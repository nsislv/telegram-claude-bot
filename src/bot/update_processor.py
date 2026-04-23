"""Selective-concurrency update processor for PTB.

Updates from the **same** user process sequentially — one request per
user at a time, because each user owns a single Claude session and
concurrent runs against the same session would race on SDK state,
session id resume, and cost accounting.

Updates from **different** users run concurrently — a long Claude call
for user A must not block messages from users B, C, D. (Historically a
single global ``asyncio.Lock`` serialized every user; one stuck request
could freeze the bot for up to ``claude_timeout_seconds`` for everyone.)

Priority callbacks (``stop:*``) always bypass user locks so the user can
interrupt their own running handler.
"""

import asyncio
from collections import defaultdict
from typing import Any, Awaitable, Dict, Hashable, Optional

from telegram import Update
from telegram.ext._baseupdateprocessor import BaseUpdateProcessor


class StopAwareUpdateProcessor(BaseUpdateProcessor):
    """Update processor with per-user serialization and stop-bypass.

    PTB calls ``process_update(update, coroutine)`` for every incoming update.
    The base class holds a semaphore (max 256) then calls our
    ``do_process_update()``.

    - Priority callbacks (``stop:*``): ``await coroutine`` directly — runs
      immediately so the user can cancel their own in-flight request.
    - Everything else: acquire the lock for ``update.effective_user.id``
      before awaiting. Same user → serialized; different users → parallel.

    A stop callback arrives while the owning user's text handler holds the
    lock -> stop callback runs concurrently -> fires the ``asyncio.Event``
    -> watcher task inside ``execute_command()`` calls ``client.interrupt()``
    -> Claude stops -> ``run_command()`` returns -> handler finishes -> lock
    released.
    """

    _PRIORITY_PREFIXES = ("stop:",)
    # Sentinel used when an update has no associated user (e.g. system
    # updates). All such updates share one lock — they are rare, so the
    # loss of parallelism does not matter.
    _NO_USER_KEY = "__no_user__"

    def __init__(self) -> None:
        # High limit so priority callbacks are never blocked by semaphore
        super().__init__(max_concurrent_updates=256)
        self._user_locks: Dict[Hashable, asyncio.Lock] = defaultdict(asyncio.Lock)

    @classmethod
    def _is_priority_callback(cls, update: object) -> bool:
        """Return True if the update is a priority callback query."""
        if not isinstance(update, Update):
            return False
        cb = update.callback_query
        return (
            cb is not None
            and cb.data is not None
            and cb.data.startswith(cls._PRIORITY_PREFIXES)
        )

    @classmethod
    def _lock_key(cls, update: object) -> Hashable:
        """Key to select a per-user lock, falling back to a shared key.

        Telegram updates without a ``effective_user`` (e.g. poll updates,
        chat-member updates in channels the bot does not know) share a
        single lock — they are infrequent and never long-running.
        """
        if not isinstance(update, Update):
            return cls._NO_USER_KEY
        user = update.effective_user
        if user is None:
            return cls._NO_USER_KEY
        return user.id

    async def do_process_update(
        self,
        update: object,
        coroutine: Awaitable[Any],
    ) -> None:
        """Process an update, serializing by user for non-priority updates."""
        if self._is_priority_callback(update):
            # Run immediately -- no user lock
            await coroutine
            return

        key = self._lock_key(update)
        async with self._user_locks[key]:
            await coroutine

    # ------------------------------------------------------------------
    # Introspection used by tests / future metrics
    # ------------------------------------------------------------------

    def active_user_count(self) -> int:
        """How many distinct users currently hold a lock entry.

        Note: this counts lock *entries*, which grow monotonically as new
        users send messages. It is a reasonable proxy for "known users
        this process has seen" rather than live in-flight work.
        """
        return len(self._user_locks)

    def get_user_lock(self, user_id: Optional[int]) -> asyncio.Lock:
        """Return the lock associated with ``user_id`` (creating if needed).

        Primarily for tests; production code paths go through
        :meth:`do_process_update`.
        """
        key: Hashable = user_id if user_id is not None else self._NO_USER_KEY
        return self._user_locks[key]

    async def initialize(self) -> None:
        """Initialize the processor (no-op)."""

    async def shutdown(self) -> None:
        """Shutdown the processor (no-op)."""
