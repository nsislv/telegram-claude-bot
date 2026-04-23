"""Tests for StopAwareUpdateProcessor.

Covers:
- Stop callbacks bypass the per-user lock (run immediately).
- Two updates from the SAME user are serialized.
- Two updates from DIFFERENT users run concurrently (R1 from upgrade.md).
- Non-stop callbacks (e.g. ``cd:``) go through the user lock.
"""

import asyncio
from unittest.mock import MagicMock

from telegram import CallbackQuery, Update, User

from src.bot.update_processor import StopAwareUpdateProcessor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_update(
    callback_data: str | None = None,
    user_id: int | None = 101,
) -> Update:
    """Build a minimal Update mock.

    By default we attach an ``effective_user`` with ``user_id=101`` so a
    test that omits it exercises the "same-user-serialization" path.
    Pass ``user_id=None`` to explicitly build an update with no user.
    """
    update = MagicMock(spec=Update)
    if callback_data is not None:
        cb = MagicMock(spec=CallbackQuery)
        cb.data = callback_data
        update.callback_query = cb
    else:
        update.callback_query = None

    if user_id is None:
        update.effective_user = None
    else:
        user = MagicMock(spec=User)
        user.id = user_id
        update.effective_user = user

    return update


# ---------------------------------------------------------------------------
# _is_priority_callback
# ---------------------------------------------------------------------------


class TestIsPriorityCallback:
    def test_stop_callback_detected(self):
        update = _make_update("stop:123")
        assert StopAwareUpdateProcessor._is_priority_callback(update) is True

    def test_cd_callback_not_priority(self):
        update = _make_update("cd:my_project")
        assert StopAwareUpdateProcessor._is_priority_callback(update) is False

    def test_no_callback_query(self):
        update = _make_update(None)
        assert StopAwareUpdateProcessor._is_priority_callback(update) is False

    def test_non_update_object(self):
        assert StopAwareUpdateProcessor._is_priority_callback("not an update") is False

    def test_callback_with_none_data(self):
        update = MagicMock(spec=Update)
        cb = MagicMock(spec=CallbackQuery)
        cb.data = None
        update.callback_query = cb
        assert StopAwareUpdateProcessor._is_priority_callback(update) is False


# ---------------------------------------------------------------------------
# _lock_key
# ---------------------------------------------------------------------------


class TestLockKey:
    def test_keyed_by_user_id(self):
        update = _make_update(user_id=777)
        assert StopAwareUpdateProcessor._lock_key(update) == 777

    def test_no_user_falls_back_to_sentinel(self):
        update = _make_update(user_id=None)
        assert (
            StopAwareUpdateProcessor._lock_key(update)
            == StopAwareUpdateProcessor._NO_USER_KEY
        )

    def test_non_update_object_falls_back(self):
        assert (
            StopAwareUpdateProcessor._lock_key("not an update")
            == StopAwareUpdateProcessor._NO_USER_KEY
        )


# ---------------------------------------------------------------------------
# do_process_update — concurrency tests
# ---------------------------------------------------------------------------


class TestStopCallbackBypassesLock:
    async def test_stop_callback_runs_while_lock_held(self):
        """A stop callback runs immediately even when the user's lock is held."""
        processor = StopAwareUpdateProcessor()

        execution_order: list[str] = []
        lock_acquired = asyncio.Event()
        stop_done = asyncio.Event()

        async def slow_coroutine():
            execution_order.append("regular_start")
            lock_acquired.set()
            await stop_done.wait()
            execution_order.append("regular_end")

        async def stop_coroutine():
            execution_order.append("stop_start")
            execution_order.append("stop_end")
            stop_done.set()

        regular_update = _make_update(None, user_id=42)
        stop_update = _make_update("stop:42", user_id=42)

        regular_task = asyncio.create_task(
            processor.do_process_update(regular_update, slow_coroutine())
        )
        await lock_acquired.wait()

        stop_task = asyncio.create_task(
            processor.do_process_update(stop_update, stop_coroutine())
        )

        await asyncio.gather(regular_task, stop_task)

        assert execution_order == [
            "regular_start",
            "stop_start",
            "stop_end",
            "regular_end",
        ]


class TestSameUserSerialized:
    async def test_two_updates_same_user_do_not_overlap(self):
        """Two updates from the SAME user are serialized."""
        processor = StopAwareUpdateProcessor()

        execution_log: list[str] = []

        async def coroutine_a():
            execution_log.append("a_start")
            await asyncio.sleep(0.05)
            execution_log.append("a_end")

        async def coroutine_b():
            execution_log.append("b_start")
            await asyncio.sleep(0.05)
            execution_log.append("b_end")

        update_a = _make_update(None, user_id=7)
        update_b = _make_update(None, user_id=7)

        task_a = asyncio.create_task(
            processor.do_process_update(update_a, coroutine_a())
        )
        # Yield so task_a acquires the lock
        await asyncio.sleep(0)

        task_b = asyncio.create_task(
            processor.do_process_update(update_b, coroutine_b())
        )

        await asyncio.gather(task_a, task_b)

        assert execution_log == ["a_start", "a_end", "b_start", "b_end"]


class TestDifferentUsersParallel:
    async def test_two_updates_different_users_run_concurrently(self):
        """R1 — the whole point of the fix.

        Two updates from different users must overlap; a long-running
        handler for user A must not block user B.
        """
        processor = StopAwareUpdateProcessor()

        a_started = asyncio.Event()
        b_started = asyncio.Event()

        async def coroutine_a():
            a_started.set()
            # Wait for B to prove it started while A is still running.
            await asyncio.wait_for(b_started.wait(), timeout=1.0)

        async def coroutine_b():
            # Wait until A is running, then signal — if A were blocking
            # us on a shared lock we would never get here.
            await asyncio.wait_for(a_started.wait(), timeout=1.0)
            b_started.set()

        update_a = _make_update(None, user_id=1)
        update_b = _make_update(None, user_id=2)

        await asyncio.gather(
            processor.do_process_update(update_a, coroutine_a()),
            processor.do_process_update(update_b, coroutine_b()),
        )

        assert a_started.is_set() and b_started.is_set()

    async def test_long_user_a_does_not_delay_user_b(self):
        """Numeric version: user B completes well before user A.

        Sanity check that concurrency is not just a lucky scheduling
        artefact.
        """
        processor = StopAwareUpdateProcessor()
        finished: list[str] = []

        async def slow_a():
            await asyncio.sleep(0.2)
            finished.append("a")

        async def fast_b():
            await asyncio.sleep(0.02)
            finished.append("b")

        update_a = _make_update(None, user_id=10)
        update_b = _make_update(None, user_id=20)

        await asyncio.gather(
            processor.do_process_update(update_a, slow_a()),
            processor.do_process_update(update_b, fast_b()),
        )

        # B finished first — would be impossible under a single global lock.
        assert finished == ["b", "a"]


class TestNonStopCallbackSequential:
    async def test_cd_callback_goes_through_user_lock(self):
        """Non-stop callbacks (cd:*) are treated as regular updates."""
        processor = StopAwareUpdateProcessor()

        execution_log: list[str] = []

        async def regular_coroutine():
            execution_log.append("regular_start")
            await asyncio.sleep(0.05)
            execution_log.append("regular_end")

        async def cd_coroutine():
            execution_log.append("cd_start")
            execution_log.append("cd_end")

        regular_update = _make_update(None, user_id=5)
        cd_update = _make_update("cd:my_project", user_id=5)

        task_regular = asyncio.create_task(
            processor.do_process_update(regular_update, regular_coroutine())
        )
        await asyncio.sleep(0)

        task_cd = asyncio.create_task(
            processor.do_process_update(cd_update, cd_coroutine())
        )

        await asyncio.gather(task_regular, task_cd)

        assert execution_log == [
            "regular_start",
            "regular_end",
            "cd_start",
            "cd_end",
        ]


class TestInitializeShutdown:
    async def test_initialize_and_shutdown_are_noop(self):
        """initialize() and shutdown() should not raise."""
        processor = StopAwareUpdateProcessor()
        await processor.initialize()
        await processor.shutdown()
