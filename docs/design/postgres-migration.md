# SQLite → Postgres migration

**Status:** design draft — no implementation.

## The problem

The repository layer (`src/storage/repositories.py`) is already
storage-agnostic: every repo takes a `DatabaseManager` and issues
plain SQL via `aiosqlite`. The rest of the codebase interacts with
repositories, not the DB directly — so the schema and queries are
the only SQLite-specific surface.

That said, several recent fixes push SQLite toward its limits:

- R2 introduced WAL + `busy_timeout` to handle concurrent writes.
- C3 made the audit log durable against process restarts.
- The newly-added JSONL audit sink is a workaround for SQLite's
  tamper-vulnerability — Postgres would solve it structurally via
  row-level security + pg_audit.
- Horizontal scaling (R6) is a non-starter on SQLite because every
  writer must share the same file and SQLite doesn't provide
  built-in replication.

## What changes when we move to Postgres

### Shallow (what we can port 1:1)

- Every `CREATE TABLE` + `CREATE INDEX` in
  `src/storage/database.py` is ANSI-ish SQL. Small syntax tweaks
  (`INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL` /
  `BIGSERIAL`; `BOOLEAN DEFAULT TRUE` is already standard).
- `aiosqlite.Row` → `asyncpg.Record`. Both are dict-like.
- `PRAGMA` tuning goes away. Postgres gets its own knobs
  (`synchronous_commit`, `max_connections`, …) managed by the
  operator's `postgresql.conf`.

### Medium (what changes shape)

- **Migrations.** Hand-rolled forward-only migrations in
  `_get_migrations()` are bearable on SQLite (single file, easy
  to inspect) but become a liability once multiple processes
  share a DB. This is the natural moment to adopt Alembic —
  see `alembic-migrations.md`.
- **Connection pooling.** `asyncpg` has its own pool —
  `DatabaseManager._connection_pool` goes away. The
  `get_connection()` contextmanager stays but becomes a thin
  shim over `pool.acquire()`.
- **Transaction semantics.** The R2 `transaction()` contextmanager
  uses SQLite `BEGIN IMMEDIATE`; Postgres has
  `BEGIN`/`SAVEPOINT`/`READ COMMITTED` etc. The shim already
  abstracts this — the move is updating the inside of the
  contextmanager, not every callsite.

### Deep (net-new work)

- **JSON columns.** `audit_log.event_data` is SQLite's best-effort
  `JSON`. Postgres has `jsonb` with indexes and operators — big
  win for audit-log queries, but requires touching every read.
- **Data migration.** A live system has users + sessions + audit
  history to move. Need a one-off `sqlite-to-postgres.py` script
  (pg_loader + checksum pass) OR accept "new DB, old one archived
  for reference".
- **FK behavior.** Postgres enforces FKs always — no equivalent
  of the `PRAGMA foreign_keys` SQLite default-off footgun. Any
  latent FK inconsistencies in an old SQLite file surface during
  the migration.

## Progression

1. **Pre-work (shipped):** the R2 connection-pragma + `transaction()`
   primitive + R3 `IF NOT EXISTS` idempotent migrations — all
   already merged.
2. **Introduce Alembic.** Replace the hand-rolled migration runner
   with an Alembic `env.py` that discovers versioned migrations from
   `alembic/versions/*.py`. Keep the existing
   `_get_migrations()` as a "legacy shim" that stamps Alembic's
   `alembic_version` table to the current state so existing
   installations upgrade cleanly. See `alembic-migrations.md`.
3. **Dual-driver `DatabaseManager`.** Accept a `postgresql://…` URL
   alongside `sqlite:///`. Route to `asyncpg` when Postgres; keep
   `aiosqlite` when SQLite. Hide the driver behind the existing
   `get_connection()` contextmanager.
4. **Write the migrator.** One-shot script that reads each SQLite
   table and INSERT-COPIES into Postgres. Runs inside a read lock
   on the SQLite file. Records its own checksum for verification.
5. **Flip the default + document.** New installs default to
   Postgres (`postgresql://bot@localhost/claude_bot`); existing
   SQLite installs keep working until the operator chooses to
   migrate.

## Why this has NOT shipped

- The repo's deployment story is still "one systemd unit on one
  host" (SYSTEMD_SETUP.md). SQLite is appropriate for that
  topology.
- Every critical audit finding (C1/C2/C3, H1-H5) was fixable at the
  application layer without requiring a DB swap.
- The JSONL audit sink addresses the single forensic-durability
  concern that would otherwise push us to Postgres today.
- R6 (horizontal scaling, the only other forcing function) is
  deliberately deferred — see `bot-worker-split.md`.

## Decision signals

Ship this work when any of the following lands:

- Operator wants two bot processes behind a load balancer (R6).
- Operator wants DB-level row-security / audit export via pg_audit.
- SQLite write contention actually shows up in the R5
  `bot_db_query_latency_seconds` histogram (p99 > 500 ms under
  realistic load).
- User base is large enough that the audit table grows past a few
  GB — SQLite handles this but queries slow down noticeably.

None of those are present today.
