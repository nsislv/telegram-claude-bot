"""Tests for the append-only JSONL audit sink + composite storage.

These two classes give the audit system a tamper-evident forensic
backup. An attacker who drops rows from the SQLite audit table still
leaves the JSONL file (and its logrotated copies shipped off-host by
an external forwarder).
"""

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from src.security.audit import (
    AuditEvent,
    AuditStorage,
    CompositeAuditStorage,
    InMemoryAuditStorage,
    JsonlAuditStorage,
)


def _event(
    user_id: int = 1,
    event_type: str = "auth_attempt",
    success: bool = True,
    risk_level: str = "low",
    timestamp: datetime | None = None,
) -> AuditEvent:
    return AuditEvent(
        timestamp=timestamp or datetime.now(UTC),
        user_id=user_id,
        event_type=event_type,
        success=success,
        details={"method": "whitelist"},
        ip_address="10.0.0.1",
        session_id="sess-1",
        risk_level=risk_level,
    )


# ---------------------------------------------------------------------
# JsonlAuditStorage
# ---------------------------------------------------------------------


class TestJsonlAuditStorage:
    async def test_write_creates_file_and_appends_one_line_per_event(
        self, tmp_path: Path
    ):
        sink = JsonlAuditStorage(tmp_path / "audit.log")

        await sink.store_event(_event(user_id=1))
        await sink.store_event(_event(user_id=2))

        raw = (tmp_path / "audit.log").read_text(encoding="utf-8")
        lines = [line for line in raw.splitlines() if line.strip()]
        assert len(lines) == 2
        # Every line must be valid JSON with the expected fields.
        for line in lines:
            parsed = json.loads(line)
            assert {
                "timestamp",
                "user_id",
                "event_type",
                "success",
                "details",
                "ip_address",
                "session_id",
                "risk_level",
            }.issubset(parsed.keys())

        await sink.close()

    async def test_parent_directory_is_created_on_first_write(self, tmp_path: Path):
        deep = tmp_path / "a" / "b" / "c" / "audit.log"
        sink = JsonlAuditStorage(deep)

        await sink.store_event(_event())

        assert deep.exists()
        await sink.close()

    async def test_events_survive_reopen(self, tmp_path: Path):
        """An operator reading the file after a crash must see every
        event the bot believed it had logged. That's the point."""
        path = tmp_path / "audit.log"

        sink_a = JsonlAuditStorage(path, fsync_each_write=False)
        await sink_a.store_event(_event(user_id=1))
        await sink_a.store_event(_event(user_id=2))
        await sink_a.close()

        sink_b = JsonlAuditStorage(path)
        events = await sink_b.get_events()
        assert len(events) == 2
        user_ids = {e.user_id for e in events}
        assert user_ids == {1, 2}

    async def test_get_events_filters_by_user(self, tmp_path: Path):
        sink = JsonlAuditStorage(tmp_path / "audit.log", fsync_each_write=False)
        await sink.store_event(_event(user_id=1))
        await sink.store_event(_event(user_id=2))
        await sink.store_event(_event(user_id=1))

        events = await sink.get_events(user_id=1)
        assert len(events) == 2
        assert all(e.user_id == 1 for e in events)

        await sink.close()

    async def test_get_events_filters_by_event_type(self, tmp_path: Path):
        sink = JsonlAuditStorage(tmp_path / "audit.log", fsync_each_write=False)
        await sink.store_event(_event(event_type="auth_attempt"))
        await sink.store_event(_event(event_type="security_violation"))

        violations = await sink.get_security_violations()
        assert len(violations) == 1
        assert violations[0].event_type == "security_violation"
        await sink.close()

    async def test_get_events_respects_limit(self, tmp_path: Path):
        sink = JsonlAuditStorage(tmp_path / "audit.log", fsync_each_write=False)
        now = datetime.now(UTC)
        for i in range(10):
            await sink.store_event(
                _event(user_id=1, timestamp=now - timedelta(minutes=i))
            )

        events = await sink.get_events(limit=3)
        assert len(events) == 3
        await sink.close()

    async def test_malformed_line_is_skipped_not_fatal(self, tmp_path: Path):
        """A truncated write (crash mid-line) must not prevent later
        events from being read."""
        path = tmp_path / "audit.log"
        path.parent.mkdir(exist_ok=True)
        # Write a good line + a malformed line + another good line.
        good = _event(user_id=1).to_json()
        malformed = '{"not":"json"'  # missing closing brace
        good2 = _event(user_id=2).to_json()
        path.write_text("\n".join([good, malformed, good2]) + "\n", encoding="utf-8")

        sink = JsonlAuditStorage(path)
        events = await sink.get_events()
        assert len(events) == 2  # malformed line skipped
        user_ids = {e.user_id for e in events}
        assert user_ids == {1, 2}
        await sink.close()

    async def test_empty_file_yields_no_events(self, tmp_path: Path):
        sink = JsonlAuditStorage(tmp_path / "empty.log")
        events = await sink.get_events()
        assert events == []

    async def test_permissions_tightened_on_posix(self, tmp_path: Path):
        """On POSIX we chmod to 640 so a non-root user cannot read
        the audit log. On Windows the chmod is a no-op and this
        test just proves we don't crash."""
        path = tmp_path / "audit.log"
        sink = JsonlAuditStorage(path)
        await sink.store_event(_event())

        if os.name == "posix":
            mode = path.stat().st_mode & 0o777
            assert mode == 0o640

        await sink.close()


# ---------------------------------------------------------------------
# CompositeAuditStorage
# ---------------------------------------------------------------------


class TestCompositeAuditStorage:
    async def test_store_fans_out_to_all_backends(self, tmp_path: Path):
        primary = InMemoryAuditStorage()
        secondary = JsonlAuditStorage(tmp_path / "audit.log", fsync_each_write=False)

        composite = CompositeAuditStorage(primary, secondary)
        await composite.store_event(_event(user_id=42))

        primary_events = await primary.get_events()
        secondary_events = await secondary.get_events()
        assert len(primary_events) == 1
        assert len(secondary_events) == 1
        assert primary_events[0].user_id == 42
        assert secondary_events[0].user_id == 42
        await composite.close()

    async def test_query_reads_from_primary(self, tmp_path: Path):
        primary = InMemoryAuditStorage()
        secondary = JsonlAuditStorage(tmp_path / "audit.log", fsync_each_write=False)

        # Put an event ONLY in the secondary, via direct call.
        await secondary.store_event(_event(user_id=99))
        # Via composite, another event goes to both.
        composite = CompositeAuditStorage(primary, secondary)
        await composite.store_event(_event(user_id=1))

        events = await composite.get_events()
        # Primary only has the composite-written event (user 1),
        # so that's what we read back — secondary's user_id=99 row
        # is NOT visible via query.
        assert len(events) == 1
        assert events[0].user_id == 1
        await composite.close()

    async def test_secondary_failure_does_not_break_primary_path(self):
        primary = AsyncMock(spec=AuditStorage)
        primary.store_event = AsyncMock()
        broken = AsyncMock(spec=AuditStorage)
        broken.store_event = AsyncMock(side_effect=RuntimeError("disk full"))

        composite = CompositeAuditStorage(primary, broken)

        # Must not raise — the primary succeeded, and a failing
        # secondary should not break the hot path.
        await composite.store_event(_event())

        primary.store_event.assert_awaited_once()
        broken.store_event.assert_awaited_once()

    async def test_primary_failure_propagates(self):
        primary = AsyncMock(spec=AuditStorage)
        primary.store_event = AsyncMock(side_effect=RuntimeError("primary down"))
        secondary = AsyncMock(spec=AuditStorage)
        secondary.store_event = AsyncMock()

        composite = CompositeAuditStorage(primary, secondary)

        with pytest.raises(RuntimeError, match="primary down"):
            await composite.store_event(_event())

        # Secondary is NOT called when primary fails — we do not want
        # a partial record where the JSONL file contradicts the DB.
        secondary.store_event.assert_not_awaited()

    async def test_close_iterates_all_backends(self, tmp_path: Path):
        primary = InMemoryAuditStorage()
        sink = JsonlAuditStorage(tmp_path / "audit.log", fsync_each_write=False)
        composite = CompositeAuditStorage(primary, sink)

        await composite.store_event(_event())
        await composite.close()

        # Re-opening the JSONL still reads the event — proves the
        # write was flushed to disk by close().
        reopened = JsonlAuditStorage(tmp_path / "audit.log")
        events = await reopened.get_events()
        assert len(events) == 1


class TestSettingsIntegration:
    """The ``audit_log_path`` setting is the operator knob."""

    def test_default_is_none(self):
        from src.config import create_test_config

        cfg = create_test_config()
        assert cfg.audit_log_path is None

    def test_value_is_accepted(self, tmp_path: Path):
        from src.config import create_test_config

        cfg = create_test_config(audit_log_path=str(tmp_path / "audit.log"))
        assert cfg.audit_log_path == tmp_path / "audit.log"
