"""Regression tests for the M6 download-path wiring.

M6 added ``validate_file_upload(..., file_bytes=...)`` but the two
real download callsites (``orchestrator.agentic_document`` and
``handlers.message.handle_document_message``) still passed
``file_bytes=None`` — so the magic-byte check never ran in
production. These tests pin the wiring.

The tests work by:

1. Patching ``validate_file_upload`` inside the orchestrator /
   message-handler modules with a spy.
2. Building a minimally-realistic ``update`` + ``context`` pair.
3. Awaiting the code path that downloads the document.
4. Asserting the spy was called with ``file_bytes`` passed.

We deliberately do NOT assert the full M6 semantics here — those
are covered by ``test_validate_file_upload.py``. These tests only
prove the callsite wiring.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


async def _fake_download(*args, **kwargs):  # noqa: ARG001
    return bytearray(b"Hello world\n")


def _make_document_update(filename: str = "notes.txt") -> MagicMock:
    """Build an Update with the minimum shape both downloaders need."""
    update = MagicMock()
    update.effective_user = MagicMock(id=1, username="tester")
    update.message = MagicMock()
    update.message.document = MagicMock(
        file_name=filename,
        file_size=12,
        mime_type="text/plain",
        get_file=AsyncMock(
            return_value=MagicMock(
                download_as_bytearray=AsyncMock(return_value=bytearray(b"hi"))
            )
        ),
    )
    update.message.caption = None
    # ``progress_msg`` needs async edit_text / delete because the
    # handlers call them with ``await``.
    progress = MagicMock()
    progress.edit_text = AsyncMock()
    progress.delete = AsyncMock()
    update.message.reply_text = AsyncMock(return_value=progress)
    update.message.chat = MagicMock(send_action=AsyncMock())
    return update


def _make_context() -> MagicMock:
    context = MagicMock()
    context.bot_data = {
        "security_validator": MagicMock(
            validate_filename=MagicMock(return_value=(True, ""))
        ),
        "audit_logger": AsyncMock(),
        "features": MagicMock(get_file_handler=MagicMock(return_value=None)),
        "claude_integration": None,  # short-circuits the handler
    }
    context.user_data = {}
    return context


class TestOrchestratorDocumentDownloadWires:
    async def test_validate_file_upload_receives_bytes(self):
        """After download, the orchestrator must call
        ``validate_file_upload`` with ``file_bytes`` set — otherwise
        magic-byte validation never runs."""
        from src.bot.orchestrator import MessageOrchestrator

        spy = AsyncMock(return_value=(True, ""))

        update = _make_document_update("notes.txt")
        context = _make_context()

        settings = MagicMock(
            approved_directory="/tmp",
            enable_project_threads=False,
            reply_quote=False,
        )
        orch = MessageOrchestrator(settings=settings, deps={})

        # Patch ``validate_file_upload`` imported lazily inside
        # ``agentic_document``.
        with patch(
            "src.bot.middleware.security.validate_file_upload",
            spy,
        ):
            try:
                await orch.agentic_document(update, context)
            except Exception:
                # The handler errors on claude_integration=None,
                # which is expected — we only care that the
                # validator was called first.
                pass

        assert spy.await_count >= 1, "validate_file_upload was never called"
        call = spy.await_args_list[0]
        # ``file_bytes`` must be present and not None.
        file_bytes = call.kwargs.get("file_bytes")
        assert file_bytes is not None
        assert isinstance(file_bytes, (bytes, bytearray))


class TestClassicHandlerDocumentDownloadWires:
    async def test_validate_file_upload_receives_bytes(self):
        """Same invariant for the classic-mode ``handle_document`` —
        after download, the magic-byte validation must run with the
        real file bytes in hand."""
        from src.bot.handlers import message as message_module

        spy = AsyncMock(return_value=(True, ""))

        update = _make_document_update("notes.txt")
        context = _make_context()
        context.bot_data["settings"] = MagicMock(
            approved_directory="/tmp",
        )
        # rate_limiter is optional in this path.
        context.bot_data["rate_limiter"] = None

        with patch(
            "src.bot.middleware.security.validate_file_upload",
            spy,
        ):
            try:
                await message_module.handle_document(update, context)
            except Exception:
                pass

        assert spy.await_count >= 1
        call = spy.await_args_list[0]
        file_bytes = call.kwargs.get("file_bytes")
        assert file_bytes is not None
        assert isinstance(file_bytes, (bytes, bytearray))


class TestRejectionBlocksPrompt:
    """When magic-byte validation fails, we must NOT proceed to
    Claude — the handler has to short-circuit with the rejection
    message."""

    async def test_orchestrator_short_circuits_on_rejection(self):
        from src.bot.orchestrator import MessageOrchestrator

        rejecting = AsyncMock(return_value=(False, "fake executable"))

        update = _make_document_update("photo.png")
        context = _make_context()

        # If the handler proceeded past the check, it would try to
        # use claude_integration. Use a sentinel that explodes so
        # failure = short-circuit did not happen.
        context.bot_data["claude_integration"] = MagicMock()
        context.bot_data["claude_integration"].run_command = AsyncMock(
            side_effect=RuntimeError("handler must NOT reach claude")
        )

        settings = MagicMock(
            approved_directory="/tmp",
            enable_project_threads=False,
            reply_quote=False,
        )
        orch = MessageOrchestrator(settings=settings, deps={})

        with patch(
            "src.bot.middleware.security.validate_file_upload",
            rejecting,
        ):
            await orch.agentic_document(update, context)

        # The progress message got edited with the rejection text,
        # and Claude was NOT invoked.
        assert rejecting.await_count >= 1
        # ``update.message.reply_text`` returns a mock that carries
        # ``edit_text`` — check it got the rejection message.
        progress = update.message.reply_text.return_value
        edit_calls = [c for c in progress.edit_text.await_args_list if c.args]
        # At least one edit with rejection text.
        assert any(
            "fake executable" in (c.args[0] if c.args else "") for c in edit_calls
        )


# Mark all as async so pytest-asyncio picks them up.
pytestmark = pytest.mark.asyncio
