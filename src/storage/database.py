"""Database connection and initialization.

Features:
- Connection pooling
- Automatic migrations
- Health checks
- Schema versioning
"""

import asyncio
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator, Awaitable, Callable, List, Tuple, Union

import aiosqlite
import structlog

logger = structlog.get_logger()


# Python 3.12+: sqlite3's default datetime adapter is deprecated.
# Register explicit adapters/converters once at import time to avoid warnings
# and keep consistent ISO-8601 persistence for datetime values.
sqlite3.register_adapter(datetime, lambda value: value.isoformat())
sqlite3.register_converter("TIMESTAMP", lambda b: datetime.fromisoformat(b.decode()))
sqlite3.register_converter("DATETIME", lambda b: datetime.fromisoformat(b.decode()))
# Keep DATE columns as raw ISO strings (matches existing model expectations).
sqlite3.register_converter("DATE", lambda b: b.decode())

# Initial schema migration
INITIAL_SCHEMA = """
-- Core Tables

-- Users table
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY,
    telegram_username TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_allowed BOOLEAN DEFAULT FALSE,
    total_cost REAL DEFAULT 0.0,
    message_count INTEGER DEFAULT 0,
    session_count INTEGER DEFAULT 0
);

-- Sessions table
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    project_path TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_cost REAL DEFAULT 0.0,
    total_turns INTEGER DEFAULT 0,
    message_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Messages table
CREATE TABLE messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    prompt TEXT NOT NULL,
    response TEXT,
    cost REAL DEFAULT 0.0,
    duration_ms INTEGER,
    error TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Tool usage table
CREATE TABLE tool_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    message_id INTEGER,
    tool_name TEXT NOT NULL,
    tool_input JSON,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (message_id) REFERENCES messages(message_id)
);

-- Audit log table
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    event_data JSON,
    success BOOLEAN DEFAULT TRUE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- User tokens table (for token auth)
CREATE TABLE user_tokens (
    token_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_used TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Cost tracking table
CREATE TABLE cost_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date DATE NOT NULL,
    daily_cost REAL DEFAULT 0.0,
    request_count INTEGER DEFAULT 0,
    UNIQUE(user_id, date),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Indexes for performance
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_project_path ON sessions(project_path);
CREATE INDEX idx_messages_session_id ON messages(session_id);
CREATE INDEX idx_messages_timestamp ON messages(timestamp);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_cost_tracking_user_date ON cost_tracking(user_id, date);
"""


class DatabaseManager:
    """Manage database connections and initialization."""

    # Pragmas applied to every connection opened by this manager.
    #
    # - ``journal_mode=WAL`` — readers no longer block writers and vice
    #   versa; essential for a concurrent async app. Historically this
    #   was set inside migration 3, but pragma statements inside a
    #   transaction are silent no-ops, so WAL was never actually
    #   enabled for most installs.
    # - ``synchronous=NORMAL`` — WAL's "safe default"; durable across
    #   app crashes, only weak against whole-OS crashes, with a
    #   meaningful fsync cost reduction.
    # - ``busy_timeout=5000`` — makes concurrent writers wait up to 5s
    #   on the internal write lock instead of immediately raising
    #   ``SQLITE_BUSY``. Without this, parallel cost-tracking updates
    #   race and one of them raises.
    # - ``foreign_keys=ON`` — SQLite default is OFF; we rely on FKs for
    #   session/user integrity.
    _CONNECTION_PRAGMAS = (
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA busy_timeout=5000",
        "PRAGMA foreign_keys=ON",
    )

    def __init__(self, database_url: str):
        """Initialize database manager."""
        self.database_path = self._parse_database_url(database_url)
        self._connection_pool = []
        self._pool_size = 5
        self._pool_lock = asyncio.Lock()

    async def _configure_connection(self, conn: aiosqlite.Connection) -> None:
        """Apply the durability/concurrency pragmas to ``conn``.

        WAL must be set **outside** a transaction, and ideally per
        connection (WAL is persistent at the database level but other
        pragmas like ``synchronous`` and ``busy_timeout`` are
        connection-local). Centralising this here means the migration
        runner, the pool initialiser, and the on-demand new-connection
        path all get identical setup.
        """
        for pragma in self._CONNECTION_PRAGMAS:
            await conn.execute(pragma)

    def _parse_database_url(self, database_url: str) -> Path:
        """Parse database URL to path."""
        if database_url.startswith("sqlite:///"):
            return Path(database_url[10:])
        elif database_url.startswith("sqlite://"):
            return Path(database_url[9:])
        else:
            return Path(database_url)

    async def initialize(self):
        """Initialize database and run migrations."""
        logger.info("Initializing database", path=str(self.database_path))

        # Ensure directory exists
        self.database_path.parent.mkdir(parents=True, exist_ok=True)

        # Run migrations
        await self._run_migrations()

        # Initialize connection pool
        await self._init_pool()

        logger.info("Database initialization complete")

    async def _run_migrations(self):
        """Run database migrations.

        Each migration entry is either:

        - a SQL string (passed to ``executescript``, which auto-commits
          per statement block); or
        - an async callable ``async def(conn) -> None`` that the runner
          invokes with the shared connection. Callable migrations are
          wrapped in ``BEGIN IMMEDIATE`` / ``COMMIT`` so multi-step
          schema rewrites either apply fully or not at all — important
          for migration 5's table-rebuild (review feedback on PR #8:
          a process kill between ``DROP TABLE audit_log`` and
          ``ALTER TABLE … RENAME`` left the DB with no ``audit_log``
          and required manual recovery).
        """
        async with aiosqlite.connect(
            self.database_path, detect_types=sqlite3.PARSE_DECLTYPES
        ) as conn:
            conn.row_factory = aiosqlite.Row

            # Apply all durability/concurrency pragmas before touching
            # any data. WAL in particular must be set before the first
            # write transaction on a fresh DB.
            await self._configure_connection(conn)

            # Get current version
            current_version = await self._get_schema_version(conn)
            logger.info("Current schema version", version=current_version)

            # Run migrations
            migrations = self._get_migrations()
            for version, migration in migrations:
                if version > current_version:
                    logger.info("Running migration", version=version)
                    if callable(migration):
                        # Atomic migration: wrap the callable + the
                        # version-stamp in one transaction so a crash
                        # during the rewrite leaves the DB exactly as
                        # it was before the migration started.
                        # ``commit()`` first to flush any pending
                        # implicit transaction aiosqlite may have
                        # opened during an earlier migration step —
                        # ``BEGIN IMMEDIATE`` errors with
                        # ``cannot start a transaction within a
                        # transaction`` otherwise.
                        await conn.commit()
                        await conn.execute("BEGIN IMMEDIATE")
                        try:
                            await migration(conn)
                            await self._set_schema_version(conn, version)
                            await conn.commit()
                        except Exception:
                            await conn.rollback()
                            raise
                    else:
                        await conn.executescript(migration)
                        await self._set_schema_version(conn, version)

            await conn.commit()

    async def _get_schema_version(self, conn: aiosqlite.Connection) -> int:
        """Get current schema version."""
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )
        """
        )

        cursor = await conn.execute("SELECT MAX(version) FROM schema_version")
        row = await cursor.fetchone()
        return row[0] if row and row[0] else 0

    async def _set_schema_version(self, conn: aiosqlite.Connection, version: int):
        """Set schema version."""
        await conn.execute(
            "INSERT INTO schema_version (version) VALUES (?)", (version,)
        )

    async def _migration_5_drop_audit_log_user_fk(
        self, conn: aiosqlite.Connection
    ) -> None:
        """Atomic variant of migration 5.

        SQLite cannot drop a FK in place, so we rebuild the table
        and rename. Every step runs via ``execute`` (not
        ``executescript``) inside the outer transaction opened by
        ``_run_migrations`` so the whole rewrite is atomic — a
        process kill mid-way leaves the pre-migration schema intact
        and the next startup retries cleanly.
        """
        await conn.execute(
            """
            CREATE TABLE audit_log_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                event_data JSON,
                success BOOLEAN DEFAULT TRUE,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT
            )
            """
        )
        await conn.execute(
            """
            INSERT INTO audit_log_new
                (id, user_id, event_type, event_data, success,
                 timestamp, ip_address)
            SELECT id, user_id, event_type, event_data, success,
                   timestamp, ip_address
            FROM audit_log
            """
        )
        await conn.execute("DROP TABLE audit_log")
        await conn.execute("ALTER TABLE audit_log_new RENAME TO audit_log")
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_user_id " "ON audit_log(user_id)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp "
            "ON audit_log(timestamp)"
        )

    def _get_migrations(
        self,
    ) -> List[
        Tuple[int, Union[str, Callable[[aiosqlite.Connection], Awaitable[None]]]]
    ]:
        """Get migration scripts."""
        return [
            (1, INITIAL_SCHEMA),
            (
                2,
                """
                -- Add analytics views
                CREATE VIEW IF NOT EXISTS daily_stats AS
                SELECT
                    date(timestamp) as date,
                    COUNT(DISTINCT user_id) as active_users,
                    COUNT(*) as total_messages,
                    SUM(cost) as total_cost,
                    AVG(duration_ms) as avg_duration
                FROM messages
                GROUP BY date(timestamp);

                CREATE VIEW IF NOT EXISTS user_stats AS
                SELECT
                    u.user_id,
                    u.telegram_username,
                    COUNT(DISTINCT s.session_id) as total_sessions,
                    COUNT(m.message_id) as total_messages,
                    SUM(m.cost) as total_cost,
                    MAX(m.timestamp) as last_activity
                FROM users u
                LEFT JOIN sessions s ON u.user_id = s.user_id
                LEFT JOIN messages m ON u.user_id = m.user_id
                GROUP BY u.user_id;
                """,
            ),
            (
                3,
                """
                -- Agentic platform tables

                -- Scheduled jobs for recurring agent tasks
                CREATE TABLE IF NOT EXISTS scheduled_jobs (
                    job_id TEXT PRIMARY KEY,
                    job_name TEXT NOT NULL,
                    cron_expression TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    target_chat_ids TEXT DEFAULT '',
                    working_directory TEXT NOT NULL,
                    skill_name TEXT,
                    created_by INTEGER DEFAULT 0,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                -- Webhook events for deduplication and audit
                CREATE TABLE IF NOT EXISTS webhook_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    delivery_id TEXT UNIQUE,
                    payload JSON,
                    processed BOOLEAN DEFAULT FALSE,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_webhook_events_delivery
                    ON webhook_events(delivery_id);
                CREATE INDEX IF NOT EXISTS idx_webhook_events_provider
                    ON webhook_events(provider, received_at);
                CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_active
                    ON scheduled_jobs(is_active);

                -- Enable WAL mode for better concurrent write performance
                PRAGMA journal_mode=WAL;
                """,
            ),
            (
                4,
                """
                -- Project thread mapping for strict forum-topic routing
                CREATE TABLE IF NOT EXISTS project_threads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_slug TEXT NOT NULL,
                    chat_id INTEGER NOT NULL,
                    message_thread_id INTEGER NOT NULL,
                    topic_name TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(chat_id, project_slug),
                    UNIQUE(chat_id, message_thread_id)
                );

                CREATE INDEX IF NOT EXISTS idx_project_threads_chat_active
                    ON project_threads(chat_id, is_active);
                CREATE INDEX IF NOT EXISTS idx_project_threads_slug
                    ON project_threads(project_slug);
                """,
            ),
            # Migration 5 is a callable so the rebuild is atomic.
            # See ``_migration_5_drop_audit_log_user_fk`` for why —
            # PR #8 review feedback on the original ``executescript``
            # version.
            (5, self._migration_5_drop_audit_log_user_fk),
        ]

    async def _init_pool(self):
        """Initialize connection pool."""
        logger.info("Initializing connection pool", size=self._pool_size)

        async with self._pool_lock:
            for _ in range(self._pool_size):
                conn = await aiosqlite.connect(
                    self.database_path, detect_types=sqlite3.PARSE_DECLTYPES
                )
                conn.row_factory = aiosqlite.Row
                await self._configure_connection(conn)
                self._connection_pool.append(conn)

    @asynccontextmanager
    async def get_connection(self) -> AsyncIterator[aiosqlite.Connection]:
        """Get database connection from pool."""
        async with self._pool_lock:
            if self._connection_pool:
                conn = self._connection_pool.pop()
            else:
                conn = await aiosqlite.connect(
                    self.database_path, detect_types=sqlite3.PARSE_DECLTYPES
                )
                conn.row_factory = aiosqlite.Row
                await self._configure_connection(conn)

        try:
            yield conn
        finally:
            async with self._pool_lock:
                if len(self._connection_pool) < self._pool_size:
                    self._connection_pool.append(conn)
                else:
                    await conn.close()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[aiosqlite.Connection]:
        """Run a block of statements as a single atomic SQLite transaction.

        Acquires one pooled connection, wraps the body in ``BEGIN
        IMMEDIATE`` / ``COMMIT`` (or ``ROLLBACK`` on exception). The
        ``IMMEDIATE`` mode takes the reserved write lock up-front, which
        makes ``SQLITE_BUSY`` deterministic (early, with ``busy_timeout``
        applied) instead of late-mid-transaction.

        Callers that already use repositories should pass the yielded
        ``conn`` to each repo method's ``conn=`` kwarg so every statement
        joins this transaction rather than borrowing a separate pooled
        connection (which would commit independently and defeat
        atomicity).
        """
        async with self.get_connection() as conn:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except Exception:
                await conn.rollback()
                raise
            else:
                await conn.commit()

    async def close(self):
        """Close all connections in pool."""
        logger.info("Closing database connections")

        async with self._pool_lock:
            for conn in self._connection_pool:
                await conn.close()
            self._connection_pool.clear()

    async def health_check(self) -> bool:
        """Check database health."""
        try:
            async with self.get_connection() as conn:
                await conn.execute("SELECT 1")
                return True
        except Exception as e:
            logger.error("Database health check failed", error=str(e))
            return False
