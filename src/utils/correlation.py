"""Per-request correlation IDs via ``contextvars`` + structlog.

R5 from ``upgrade.md``. structlog was already used everywhere, but with
no correlation ID threading through the async flow, reconstructing one
request's lifecycle under concurrent load meant grepping by user_id +
timestamp — brittle and error-prone. This module provides a single
primitive:

.. code-block:: python

    from src.utils.correlation import request_context

    async with request_context(user_id=update.effective_user.id):
        # every structlog call inside this block automatically
        # includes request_id=<uuid> and user_id=<id>
        await handler(update, context)

Under the hood:

- A ``ContextVar`` holds the current request id, so nested awaits in
  the same task see the same value but parallel tasks do not bleed.
- ``structlog.contextvars.bind_contextvars`` adds the same binding
  to the structlog thread-local so it shows up in every log line
  emitted during the request.

The context manager clears both bindings on exit — no leakage into
later updates handled by the same event loop task group.
"""

from __future__ import annotations

import contextvars
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import structlog

# Primary storage: a ContextVar carries the id through any ``await``
# chain in the same asyncio task.
request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "request_id", default=None
)


def new_request_id() -> str:
    """Return a fresh correlation id.

    UUID4 hex (no dashes) — short enough to be readable in logs and
    random enough that accidental collisions across a single bot
    lifetime are negligible.
    """
    return uuid.uuid4().hex


def get_request_id() -> Optional[str]:
    """Return the request id currently bound to this async context, or None."""
    return request_id_var.get()


@asynccontextmanager
async def request_context(
    user_id: Optional[int] = None,
    *,
    request_id: Optional[str] = None,
    **extra: object,
) -> AsyncIterator[str]:
    """Bind a correlation id (and optional user_id / extras) for this scope.

    Parameters
    ----------
    user_id
        Telegram user id, bound to structlog as ``user_id``. Pass
        ``None`` for system-originated flows (webhooks, scheduler)
        where no user is attached to the request.
    request_id
        Optional pre-existing id to adopt — useful for external
        triggers that carry their own trace (e.g. a GitHub webhook
        ``X-GitHub-Delivery`` header, or a scheduler's event id).
        When omitted, a fresh id is generated.
    **extra
        Additional key-value pairs bound to structlog for the duration
        of the block (e.g. ``source="webhook"``,
        ``correlation_id=event.id``).

    Yields
    ------
    The correlation id in effect for the block.
    """
    rid = request_id or new_request_id()

    # contextvars token lets us restore the previous value on exit
    # rather than setting to None (a nested ``request_context`` would
    # otherwise wipe the outer one's id).
    token = request_id_var.set(rid)

    structlog_bindings: dict = {"request_id": rid}
    if user_id is not None:
        structlog_bindings["user_id"] = user_id
    structlog_bindings.update(extra)

    structlog.contextvars.bind_contextvars(**structlog_bindings)
    try:
        yield rid
    finally:
        # Unbind only the keys we added — a caller may have bound
        # unrelated context outside of this block that must survive.
        structlog.contextvars.unbind_contextvars(*structlog_bindings.keys())
        request_id_var.reset(token)
