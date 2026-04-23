"""Tests for ``src.utils.correlation`` — R5 from upgrade.md.

Pin the observable behaviour of ``request_context``:

1. A fresh id is bound inside the block and visible via
   ``get_request_id()`` and in structlog output.
2. ``user_id`` and custom extras are bound alongside.
3. After exit, both the ContextVar and the structlog bindings are
   cleared.
4. Parallel asyncio tasks get independent ids.
5. Pre-existing structlog bindings survive.
6. Nested contexts restore the outer id on exit.
"""

import asyncio
import logging

import pytest
import structlog

from src.utils.correlation import (
    get_request_id,
    new_request_id,
    request_context,
    request_id_var,
)


@pytest.fixture(autouse=True)
def _fresh_contextvars():
    """Guarantee a clean structlog context at the start of each test —
    other tests in the suite may have left bindings on the thread-local.
    """
    structlog.contextvars.clear_contextvars()
    yield
    structlog.contextvars.clear_contextvars()


class TestNewRequestId:
    def test_returns_non_empty_hex(self):
        rid = new_request_id()
        assert isinstance(rid, str)
        assert len(rid) == 32  # uuid4.hex
        int(rid, 16)  # raises if not hex

    def test_ids_are_unique(self):
        ids = {new_request_id() for _ in range(200)}
        assert len(ids) == 200


class TestBindingLifecycle:
    async def test_request_id_visible_inside_block(self):
        assert get_request_id() is None
        async with request_context(user_id=99) as rid:
            assert get_request_id() == rid
            # structlog contextvars picked up the same id
            bound = structlog.contextvars.get_contextvars()
            assert bound["request_id"] == rid
            assert bound["user_id"] == 99

    async def test_everything_cleared_after_block(self):
        async with request_context(user_id=7):
            pass

        assert get_request_id() is None
        assert structlog.contextvars.get_contextvars() == {}

    async def test_extras_are_bound(self):
        async with request_context(user_id=1, source="webhook", correlation_id="abc"):
            bound = structlog.contextvars.get_contextvars()
            assert bound["source"] == "webhook"
            assert bound["correlation_id"] == "abc"

        # And cleared on exit
        assert structlog.contextvars.get_contextvars() == {}

    async def test_user_id_is_optional(self):
        async with request_context():
            bound = structlog.contextvars.get_contextvars()
            assert "user_id" not in bound
            assert "request_id" in bound


class TestExplicitRequestIdAdoption:
    async def test_caller_provided_id_is_used_verbatim(self):
        """External triggers (webhook, scheduler) carry their own id —
        when passed in, we must use it rather than generate a fresh one
        so the trace can be stitched back to the originating event."""
        async with request_context(user_id=None, request_id="webhook-evt-42") as rid:
            assert rid == "webhook-evt-42"
            assert get_request_id() == "webhook-evt-42"


class TestConcurrentIsolation:
    async def test_parallel_tasks_have_independent_ids(self):
        """contextvars + asyncio: two tasks must not see each other's id."""
        seen = {}

        async def task(label: str, user_id: int):
            async with request_context(user_id=user_id) as rid:
                # Yield so the other task has a chance to run between
                # bind and read — real-world scheduling.
                await asyncio.sleep(0)
                seen[label] = (rid, get_request_id())

        await asyncio.gather(task("a", 1), task("b", 2))

        rid_a, observed_a = seen["a"]
        rid_b, observed_b = seen["b"]
        assert rid_a != rid_b
        assert observed_a == rid_a
        assert observed_b == rid_b


class TestNesting:
    async def test_inner_context_restores_outer_on_exit(self):
        async with request_context(user_id=10) as outer:
            assert get_request_id() == outer
            async with request_context(user_id=20) as inner:
                assert inner != outer
                assert get_request_id() == inner
            # Back to outer after inner exits
            assert get_request_id() == outer

        assert get_request_id() is None


class TestStructlogIntegration:
    async def test_log_record_carries_request_id(self, caplog):
        """End-to-end: emit a structlog call inside the block and make
        sure the rendered record includes ``request_id``."""
        # Configure a vanilla structlog pipeline that surfaces contextvars
        # into the log dict so caplog can see them.
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.KeyValueRenderer(key_order=["event"]),
            ],
            logger_factory=structlog.stdlib.LoggerFactory(),
            cache_logger_on_first_use=False,
        )
        log = structlog.get_logger("test-corr")

        caplog.set_level(logging.INFO)
        async with request_context(user_id=5) as rid:
            log.info("hello")

        messages = [r.message for r in caplog.records]
        # KeyValueRenderer quotes string values — match with or without
        # surrounding quotes so a future renderer swap doesn't break this.
        assert any(
            f"request_id={rid}" in msg or f"request_id='{rid}'" in msg
            for msg in messages
        )
        assert any("user_id=5" in msg for msg in messages)


class TestContextVarIsAccessibleDirectly:
    """Cheap sanity check that ``request_id_var`` is importable and
    used correctly — safeguards downstream code that may read the
    ContextVar in a non-structlog path (e.g. Claude SDK metadata)."""

    async def test_get_returns_none_outside_context(self):
        assert request_id_var.get() is None

    async def test_get_returns_current_inside_context(self):
        async with request_context() as rid:
            assert request_id_var.get() == rid
