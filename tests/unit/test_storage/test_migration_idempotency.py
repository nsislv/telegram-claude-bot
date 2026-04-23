"""Tests for R3 from upgrade.md.

The initial schema used bare ``CREATE TABLE`` / ``CREATE INDEX``.
If migration 1 ever re-ran against an already-initialised DB it
would raise ``OperationalError: table 'users' already exists`` and
break startup. The fix adds ``IF NOT EXISTS`` to every DDL so the
script is self-healing; the migration runner still gates replays
by ``schema_version``.

These tests execute the literal ``INITIAL_SCHEMA`` script twice
against the same aiosqlite connection and assert it is a no-op on
the second run.
"""

import tempfile
from pathlib import Path

import aiosqlite
import pytest

from src.storage.database import INITIAL_SCHEMA, DatabaseManager


class TestInitialSchemaIdempotent:
    async def test_running_initial_schema_twice_does_not_raise(self):
        """Re-executing the script on an initialised DB must be a
        safe no-op. Pre-R3 this would have raised on the second
        ``CREATE TABLE users``."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "idempotent.db"
            async with aiosqlite.connect(db_path) as conn:
                await conn.executescript(INITIAL_SCHEMA)
                await conn.commit()
                # Second run MUST NOT raise.
                await conn.executescript(INITIAL_SCHEMA)
                await conn.commit()

                cursor = await conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
                tables = {row[0] for row in await cursor.fetchall()}

        expected = {
            "users",
            "sessions",
            "messages",
            "tool_usage",
            "audit_log",
            "user_tokens",
            "cost_tracking",
        }
        # All expected tables present; no dupes / renames.
        assert expected.issubset(
            tables
        ), f"expected tables missing: {expected - tables}"

    async def test_all_ddl_statements_use_if_not_exists(self):
        """Lexical guard — every ``CREATE`` in the script must use
        ``IF NOT EXISTS`` so a future reviewer cannot accidentally
        drop the safety net by adding a bare ``CREATE TABLE``."""
        # Strip line comments so trailing ``-- ...`` doesn't confuse
        # the search.
        cleaned_lines = []
        for line in INITIAL_SCHEMA.splitlines():
            stripped = line.strip()
            if stripped.startswith("--"):
                continue
            cleaned_lines.append(line)
        cleaned = "\n".join(cleaned_lines).upper()

        # Walk every CREATE and assert the next token group is
        # ``TABLE IF NOT EXISTS`` or ``INDEX IF NOT EXISTS``.
        offenders = []
        offset = 0
        while True:
            idx = cleaned.find("CREATE ", offset)
            if idx == -1:
                break
            chunk = cleaned[idx : idx + 60]
            if "IF NOT EXISTS" not in chunk:
                offenders.append(chunk.split("\n")[0])
            offset = idx + 1

        assert not offenders, (
            "Every CREATE in INITIAL_SCHEMA must use IF NOT EXISTS; "
            f"found: {offenders}"
        )


class TestFullInitializeIsIdempotent:
    async def test_double_initialize_does_not_raise(self):
        """Run the whole ``DatabaseManager.initialize`` twice. The
        second call should be a clean no-op because ``schema_version``
        gates replays — R3 is the belt if the braces fail."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "double-init.db"
            url = f"sqlite:///{db_path}"

            manager_a = DatabaseManager(url)
            await manager_a.initialize()
            await manager_a.close()

            # Second manager on the same file must succeed.
            manager_b = DatabaseManager(url)
            await manager_b.initialize()
            assert await manager_b.health_check() is True
            await manager_b.close()


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
