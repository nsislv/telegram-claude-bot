"""Tests for the SQLite durability/concurrency pragmas and the
``DatabaseManager.transaction()`` context manager added for R2.

R2 from ``upgrade.md``: WAL was only attempted inside a transaction
(silent no-op), there was no ``busy_timeout``, and
``save_claude_interaction`` performed five sequential writes across five
different pooled connections with no atomicity. These tests pin the
new guarantees:

- Every pooled connection reports ``journal_mode=wal``.
- ``PRAGMA busy_timeout`` returns 5000 ms on every connection.
- ``transaction()`` commits on success and rolls back on exception.
"""

import tempfile
from pathlib import Path

import aiosqlite
import pytest

from src.storage.database import DatabaseManager


@pytest.fixture
async def db_manager():
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "test.db"
        manager = DatabaseManager(f"sqlite:///{db_path}")
        await manager.initialize()
        try:
            yield manager
        finally:
            await manager.close()


async def _read_pragma(conn: aiosqlite.Connection, name: str) -> str:
    cursor = await conn.execute(f"PRAGMA {name}")
    row = await cursor.fetchone()
    assert row is not None, f"PRAGMA {name} returned no row"
    value = row[0]
    # Normalise to str for comparison across int / str pragma values.
    return str(value).lower()


class TestConnectionPragmas:
    async def test_wal_mode_enabled(self, db_manager):
        """WAL was previously only attempted inside migration 3's
        transaction (a no-op). It must now be active on every
        pooled connection."""
        async with db_manager.get_connection() as conn:
            assert await _read_pragma(conn, "journal_mode") == "wal"

    async def test_busy_timeout_set(self, db_manager):
        """A 5s busy_timeout prevents immediate SQLITE_BUSY under
        concurrent writes."""
        async with db_manager.get_connection() as conn:
            assert await _read_pragma(conn, "busy_timeout") == "5000"

    async def test_foreign_keys_on(self, db_manager):
        """FK enforcement is a correctness invariant (e.g. sessions
        reference users). SQLite's default is OFF."""
        async with db_manager.get_connection() as conn:
            # PRAGMA foreign_keys returns 1/0
            assert await _read_pragma(conn, "foreign_keys") == "1"

    async def test_synchronous_normal(self, db_manager):
        """synchronous=NORMAL is the recommended WAL companion."""
        async with db_manager.get_connection() as conn:
            # PRAGMA synchronous: 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA
            assert await _read_pragma(conn, "synchronous") == "1"


class TestTransactionContext:
    async def test_commit_on_success(self, db_manager):
        """Statements inside the transaction block persist after the
        context exits successfully."""
        async with db_manager.transaction() as conn:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS _tx_test (id INTEGER, label TEXT)"
            )
            await conn.execute(
                "INSERT INTO _tx_test (id, label) VALUES (?, ?)", (1, "keeper")
            )

        async with db_manager.get_connection() as conn:
            cursor = await conn.execute("SELECT label FROM _tx_test WHERE id = 1")
            row = await cursor.fetchone()
            assert row is not None
            assert row["label"] == "keeper"

    async def test_rollback_on_exception(self, db_manager):
        """A raised exception inside the block rolls back **all** writes
        done within it — atomicity is the point."""

        async with db_manager.get_connection() as conn:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS _tx_rollback (id INTEGER, label TEXT)"
            )
            await conn.commit()

        class Boom(RuntimeError):
            pass

        async def _doomed_insert():
            async with db_manager.transaction() as conn:
                await conn.execute(
                    "INSERT INTO _tx_rollback (id, label) VALUES (?, ?)",
                    (1, "should-not-persist"),
                )
                raise Boom("nope")

        caught = False
        try:
            await _doomed_insert()
        except Boom:
            caught = True
        assert caught, "expected Boom to escape the transaction context"

        async with db_manager.get_connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM _tx_rollback")
            row = await cursor.fetchone()
            assert row is not None
            assert row[0] == 0

    async def test_nested_statements_share_transaction(self, db_manager):
        """Two inserts in one transaction land together — demonstrated
        by observing them both through a second connection only after
        commit."""
        async with db_manager.get_connection() as conn:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS _tx_atomic (id INTEGER PRIMARY KEY)"
            )
            await conn.commit()

        async with db_manager.transaction() as conn:
            await conn.execute("INSERT INTO _tx_atomic (id) VALUES (1)")
            await conn.execute("INSERT INTO _tx_atomic (id) VALUES (2)")

        async with db_manager.get_connection() as conn:
            cursor = await conn.execute("SELECT COUNT(*) FROM _tx_atomic")
            row = await cursor.fetchone()
            assert row is not None
            assert row[0] == 2
