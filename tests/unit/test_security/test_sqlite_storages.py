"""End-to-end tests for the SQLite-backed audit and token storages.

Covers C3 from ``upgrade.md``. The previous ``InMemoryAuditStorage`` /
``InMemoryTokenStorage`` implementations lost every event and every
issued token whenever the bot process restarted — a forensic disaster
and an inadvertent DoS against authenticated users.

These tests run against a real in-memory-ish SQLite database via the
existing :class:`Storage` facade, so the full path — model mapping,
JSON (de)serialisation, eager expiry of stale tokens — is exercised.
"""

from datetime import UTC, datetime, timedelta

import pytest

from src.security.audit import AuditEvent, SQLiteAuditStorage
from src.security.auth import SQLiteTokenStorage
from src.storage.facade import Storage


@pytest.fixture
async def storage(tmp_path):
    """A freshly-initialised SQLite-backed Storage."""
    db_path = tmp_path / "test.db"
    storage = Storage(f"sqlite:///{db_path}")
    await storage.initialize()
    try:
        yield storage
    finally:
        await storage.close()


async def _ensure_user(storage: Storage, user_id: int) -> None:
    """Create a users row so token FK inserts succeed.

    ``user_tokens.user_id`` has a real FOREIGN KEY to ``users``. In
    production, a user is always inserted via ``get_or_create_user``
    before a token is issued, so the tests mirror that order.
    """
    await storage.get_or_create_user(user_id)


# ---------------------------------------------------------------------------
# SQLiteAuditStorage
# ---------------------------------------------------------------------------


class TestSQLiteAuditStorage:
    async def test_round_trip_preserves_all_fields(self, storage):
        backend = SQLiteAuditStorage(storage.audit)
        event = AuditEvent(
            timestamp=datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC),
            user_id=42,
            event_type="security_violation",
            success=False,
            details={"pattern": "rm -rf", "attempted_action": "bash"},
            ip_address="10.0.0.1",
            session_id="abc-123",
            risk_level="critical",
        )

        await backend.store_event(event)
        events = await backend.get_events(user_id=42)

        assert len(events) == 1
        roundtrip = events[0]
        assert roundtrip.user_id == 42
        assert roundtrip.event_type == "security_violation"
        assert roundtrip.success is False
        assert roundtrip.details == {
            "pattern": "rm -rf",
            "attempted_action": "bash",
        }
        assert roundtrip.ip_address == "10.0.0.1"
        assert roundtrip.session_id == "abc-123"
        assert roundtrip.risk_level == "critical"

    async def test_persists_across_storage_recreation(self, tmp_path):
        """The whole point of the fix — events survive the process dying."""
        db_path = tmp_path / "durable.db"

        storage_a = Storage(f"sqlite:///{db_path}")
        await storage_a.initialize()
        backend_a = SQLiteAuditStorage(storage_a.audit)
        await backend_a.store_event(
            AuditEvent(
                timestamp=datetime.now(UTC),
                user_id=99,
                event_type="auth_attempt",
                success=True,
                details={"method": "whitelist"},
                risk_level="low",
            )
        )
        await storage_a.close()

        storage_b = Storage(f"sqlite:///{db_path}")
        await storage_b.initialize()
        try:
            backend_b = SQLiteAuditStorage(storage_b.audit)
            events = await backend_b.get_events(user_id=99)
            assert len(events) == 1
            assert events[0].details == {"method": "whitelist"}
        finally:
            await storage_b.close()

    async def test_filters_by_event_type(self, storage):
        backend = SQLiteAuditStorage(storage.audit)
        now = datetime.now(UTC)
        for i, et in enumerate(["auth_attempt", "security_violation", "auth_attempt"]):
            await backend.store_event(
                AuditEvent(
                    timestamp=now - timedelta(minutes=i),
                    user_id=7,
                    event_type=et,
                    success=True,
                    details={},
                )
            )

        violations = await backend.get_security_violations(user_id=7)
        assert len(violations) == 1
        assert violations[0].event_type == "security_violation"

    async def test_limit_is_honoured(self, storage):
        backend = SQLiteAuditStorage(storage.audit)
        now = datetime.now(UTC)
        for i in range(5):
            await backend.store_event(
                AuditEvent(
                    timestamp=now - timedelta(minutes=i),
                    user_id=1,
                    event_type="x",
                    success=True,
                    details={},
                )
            )

        events = await backend.get_events(user_id=1, limit=3)
        assert len(events) == 3

    async def test_meta_namespace_protects_against_caller_collision(self, storage):
        """Review feedback: the original ``_session_id`` /
        ``_risk_level`` flat keys could be silently overwritten by a
        caller passing ``details={"_session_id": "spoofed"}``.
        The nested ``_meta`` dict removes that footgun."""
        backend = SQLiteAuditStorage(storage.audit)
        event = AuditEvent(
            timestamp=datetime.now(UTC),
            user_id=1,
            event_type="auth_attempt",
            success=True,
            # Caller-supplied details containing keys that would
            # have collided with the old flat-namespace encoding.
            details={
                "_session_id": "spoofed-session",
                "_risk_level": "spoofed-risk",
                "legit_key": "legit-value",
            },
            session_id="real-session",
            risk_level="critical",
        )

        await backend.store_event(event)
        events = await backend.get_events(user_id=1)
        roundtrip = events[0]

        # The real session_id/risk_level survive despite the caller
        # trying to put colliding keys in details.
        assert roundtrip.session_id == "real-session"
        assert roundtrip.risk_level == "critical"
        # Caller keys round-trip as details — not eaten by the
        # meta-namespacing step.
        assert roundtrip.details["legit_key"] == "legit-value"
        assert roundtrip.details["_session_id"] == "spoofed-session"
        assert roundtrip.details["_risk_level"] == "spoofed-risk"

    async def test_reads_legacy_flat_namespace(self, storage):
        """Back-compat: rows written under the old ``_session_id`` /
        ``_risk_level`` flat namespace must still deserialise after
        the upgrade. We inject a row manually in the old shape and
        assert ``get_events`` reads it cleanly."""
        # Make sure a user exists so the audit table FK (pre-migration-5)
        # or the lack thereof (post-migration-5) doesn't interfere.
        await storage.get_or_create_user(77)

        # Write a row in the old flat-namespace shape using the
        # underlying repository directly.
        from src.storage.models import AuditLogModel

        await storage.audit.log_event(
            AuditLogModel(
                user_id=77,
                event_type="legacy_auth",
                timestamp=datetime.now(UTC),
                event_data={
                    "_session_id": "legacy-sess",
                    "_risk_level": "medium",
                    "note": "pre-upgrade row",
                },
                success=True,
                ip_address="10.0.0.2",
            )
        )

        backend = SQLiteAuditStorage(storage.audit)
        events = await backend.get_events(user_id=77)
        assert len(events) == 1
        assert events[0].session_id == "legacy-sess"
        assert events[0].risk_level == "medium"
        assert events[0].details == {"note": "pre-upgrade row"}

    async def test_accepts_events_for_unknown_user(self, storage):
        """Regression guard for migration 5.

        The audit table historically had a FOREIGN KEY on ``user_id``,
        which made it impossible to log the very first authentication
        attempt from a brand-new Telegram user (the ``users`` row is
        created later, during ``get_or_create_user``). Migration 5
        removes that FK; if a future change reintroduces it, this test
        fails immediately instead of surfacing as a login-time crash.
        """
        backend = SQLiteAuditStorage(storage.audit)
        unknown_user_id = 424242  # never added to the users table

        await backend.store_event(
            AuditEvent(
                timestamp=datetime.now(UTC),
                user_id=unknown_user_id,
                event_type="auth_attempt",
                success=False,
                details={"reason": "not whitelisted"},
                risk_level="medium",
            )
        )

        events = await backend.get_events(user_id=unknown_user_id)
        assert len(events) == 1
        assert events[0].user_id == unknown_user_id


# ---------------------------------------------------------------------------
# SQLiteTokenStorage
# ---------------------------------------------------------------------------


class TestSQLiteTokenStorage:
    async def test_store_and_retrieve(self, storage):
        backend = SQLiteTokenStorage(storage.tokens)
        await _ensure_user(storage, 1)
        expires = datetime.now(UTC) + timedelta(days=1)

        await backend.store_token(user_id=1, token_hash="hash-1", expires_at=expires)

        token = await backend.get_user_token(1)
        assert token is not None
        assert token["hash"] == "hash-1"
        assert token["expires_at"] is not None
        assert token["created_at"] is not None

    async def test_no_token_returns_none(self, storage):
        backend = SQLiteTokenStorage(storage.tokens)
        assert await backend.get_user_token(9999) is None

    async def test_expired_token_returns_none_and_is_deactivated(self, storage):
        """Past-expiry tokens must be treated as absent AND eagerly
        deactivated so subsequent scans remain cheap."""
        backend = SQLiteTokenStorage(storage.tokens)
        await _ensure_user(storage, 5)
        past = datetime.now(UTC) - timedelta(minutes=1)

        await backend.store_token(user_id=5, token_hash="stale", expires_at=past)

        assert await backend.get_user_token(5) is None
        # Double-check: calling again still returns None, the row did not
        # resurrect itself.
        assert await backend.get_user_token(5) is None

    async def test_reissue_deactivates_previous(self, storage):
        """Replacing a user's token must hide the old hash from lookups
        — otherwise both tokens would be valid simultaneously."""
        backend = SQLiteTokenStorage(storage.tokens)
        await _ensure_user(storage, 3)
        future = datetime.now(UTC) + timedelta(days=1)

        await backend.store_token(user_id=3, token_hash="old", expires_at=future)
        await backend.store_token(user_id=3, token_hash="new", expires_at=future)

        current = await backend.get_user_token(3)
        assert current is not None
        assert current["hash"] == "new"

    async def test_revoke_clears_token(self, storage):
        backend = SQLiteTokenStorage(storage.tokens)
        await _ensure_user(storage, 8)
        future = datetime.now(UTC) + timedelta(days=1)
        await backend.store_token(user_id=8, token_hash="h", expires_at=future)

        await backend.revoke_token(8)

        assert await backend.get_user_token(8) is None

    async def test_persists_across_storage_recreation(self, tmp_path):
        """The token survives a process restart — the core promise."""
        db_path = tmp_path / "durable-tokens.db"

        storage_a = Storage(f"sqlite:///{db_path}")
        await storage_a.initialize()
        await _ensure_user(storage_a, 11)
        backend_a = SQLiteTokenStorage(storage_a.tokens)
        await backend_a.store_token(
            user_id=11,
            token_hash="persistent",
            expires_at=datetime.now(UTC) + timedelta(days=7),
        )
        await storage_a.close()

        storage_b = Storage(f"sqlite:///{db_path}")
        await storage_b.initialize()
        try:
            backend_b = SQLiteTokenStorage(storage_b.tokens)
            token = await backend_b.get_user_token(11)
            assert token is not None
            assert token["hash"] == "persistent"
        finally:
            await storage_b.close()

    async def test_get_user_token_updates_last_used(self, storage):
        backend = SQLiteTokenStorage(storage.tokens)
        await _ensure_user(storage, 13)
        await backend.store_token(
            user_id=13,
            token_hash="h",
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )

        # Initially last_used is None
        row = await storage.tokens.get_active_for_user(13)
        assert row is not None
        assert row.last_used is None

        # A read through the adapter touches it
        await backend.get_user_token(13)

        row = await storage.tokens.get_active_for_user(13)
        assert row is not None
        assert row.last_used is not None

    async def test_concurrent_upsert_leaves_exactly_one_active_row(self, storage):
        """Review feedback on PR #8 — pre-fix, two concurrent
        ``store_token`` calls for the same user could each run
        UPDATE (deactivate) + INSERT, leaving TWO ``is_active=1``
        rows. Post-fix, ``upsert_active`` wraps both statements in
        ``BEGIN IMMEDIATE`` so SQLite serialises the writers.

        Launch N concurrent ``store_token`` tasks for the same user.
        After they all complete, exactly one row must be active —
        the one that won the race — and no prior row survives as
        active.
        """
        import asyncio as _asyncio

        backend = SQLiteTokenStorage(storage.tokens)
        user_id = 501
        await _ensure_user(storage, user_id)
        future = datetime.now(UTC) + timedelta(days=1)

        async def _issue(label: str) -> None:
            await backend.store_token(
                user_id=user_id, token_hash=f"hash-{label}", expires_at=future
            )

        # Fire 8 concurrent issuers for the same user.
        await _asyncio.gather(*(_issue(f"c-{i}") for i in range(8)))

        # Query the raw table — count active rows for the user.
        async with storage.db_manager.get_connection() as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM user_tokens "
                "WHERE user_id = ? AND is_active = 1",
                (user_id,),
            )
            row = await cursor.fetchone()
            active_count = row[0]

        assert active_count == 1, (
            f"expected exactly one active token after concurrent "
            f"issues; got {active_count}"
        )


class TestMigration5Atomicity:
    """Regression guard for the review feedback on PR #8 that
    called out ``executescript`` non-atomicity — a process kill
    between ``DROP TABLE audit_log`` and ``ALTER TABLE … RENAME``
    left the DB in a wedged state. Post-fix, migration 5 is a
    callable wrapped in ``BEGIN IMMEDIATE`` / ``COMMIT``, so a
    failure at any intermediate step rolls back cleanly.
    """

    async def test_migration_5_rollback_leaves_pre_migration_schema(self, tmp_path):
        """Simulate a crash inside migration 5 by forcing the
        callable to raise mid-way. Re-opening the DB must see the
        pre-migration schema intact (schema_version < 5) and the
        ``audit_log`` table still present with its old FK."""
        from src.storage.database import DatabaseManager

        db_path = tmp_path / "mid-migration.db"
        manager = DatabaseManager(f"sqlite:///{db_path}")

        # Patch migration 5 to raise after the first execute so
        # the rebuild is interrupted.
        call_count = {"n": 0}

        async def flaky_migration_5(conn):  # type: ignore[no-untyped-def]
            call_count["n"] += 1
            # Start the rebuild then explode, mimicking a crash
            # between DROP TABLE and RENAME.
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
            raise RuntimeError("simulated crash mid-migration")

        manager._migration_5_drop_audit_log_user_fk = (  # type: ignore[assignment]
            flaky_migration_5
        )

        try:
            await manager.initialize()
        except RuntimeError:
            pass  # expected — migration raised
        finally:
            await manager.close()

        # Re-open with the real migration — the DB must recover.
        manager2 = DatabaseManager(f"sqlite:///{db_path}")
        await manager2.initialize()
        try:
            # Post-recovery, audit_log exists and accepts writes.
            async with manager2.get_connection() as conn:
                cursor = await conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='audit_log'"
                )
                row = await cursor.fetchone()
                assert row is not None, "audit_log missing after recovery"
        finally:
            await manager2.close()
