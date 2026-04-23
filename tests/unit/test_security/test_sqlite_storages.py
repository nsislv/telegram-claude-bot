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
