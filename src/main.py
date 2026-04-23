"""Main entry point for Claude Code Telegram Bot."""

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import structlog

from src import __version__
from src.bot.core import ClaudeCodeBot
from src.claude import (
    ClaudeIntegration,
    SessionManager,
)
from src.claude.sdk_integration import ClaudeSDKManager
from src.config.features import FeatureFlags
from src.config.settings import Settings
from src.events.bus import EventBus
from src.events.handlers import AgentHandler
from src.events.middleware import EventSecurityMiddleware
from src.exceptions import ConfigurationError
from src.notifications.service import NotificationService
from src.projects import ProjectThreadManager, load_project_registry
from src.scheduler.scheduler import JobScheduler
from src.security.audit import (
    AuditLogger,
    CompositeAuditStorage,
    JsonlAuditStorage,
    SQLiteAuditStorage,
)
from src.security.auth import (
    AuthenticationManager,
    SQLiteTokenStorage,
    TokenAuthProvider,
    WhitelistAuthProvider,
)
from src.security.rate_limiter import RateLimiter
from src.security.validators import SecurityValidator
from src.storage.facade import Storage
from src.storage.session_storage import SQLiteSessionStorage


def setup_logging(debug: bool = False) -> None:
    """Configure structured logging."""
    level = logging.DEBUG if debug else logging.INFO

    # Configure standard logging
    logging.basicConfig(
        level=level,
        format="%(message)s",
        stream=sys.stdout,
    )

    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            (
                structlog.processors.JSONRenderer()
                if not debug
                else structlog.dev.ConsoleRenderer()
            ),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Claude Code Telegram Bot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version", action="version", version=f"Claude Code Telegram Bot {__version__}"
    )

    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    parser.add_argument("--config-file", type=Path, help="Path to configuration file")

    return parser.parse_args()


def enforce_security_flag_guardrails(config: Settings, logger: Any) -> None:
    """H1 — refuse to boot unless ``DISABLE_*`` flags have explicit sign-off.

    ``DISABLE_SECURITY_PATTERNS=true`` turns off all path-traversal and
    shell-pattern validation. ``DISABLE_TOOL_VALIDATION=true`` turns off
    the entire Claude tool allowlist. Either alone lets an attacker (or
    Claude, via prompt injection) read ``~/.ssh/id_rsa`` or run arbitrary
    bash.

    Both used to default to ``false``, but a single typo in a deployment
    config silently neutered the security model with no loud signal.
    This function:

    1. Refuses to start if either flag is true and
       ``I_UNDERSTAND_SECURITY_IS_DISABLED`` is not also true.
    2. Emits a ``critical``-level log entry naming every flag that is
       enabled, so the warning is visible even when the opt-in is
       present and the bot proceeds to boot.

    Called from :func:`create_application` before any security component
    is constructed — so the refusal happens before any listener is
    bound and before any Claude wiring is initialised.
    """
    relaxed_flags = []
    if config.disable_security_patterns:
        relaxed_flags.append("DISABLE_SECURITY_PATTERNS")
    if config.disable_tool_validation:
        relaxed_flags.append("DISABLE_TOOL_VALIDATION")

    if not relaxed_flags:
        return

    if not config.i_understand_security_is_disabled:
        raise ConfigurationError(
            "Refusing to start: "
            + ", ".join(relaxed_flags)
            + " is enabled, but I_UNDERSTAND_SECURITY_IS_DISABLED is not set to "
            "true. These flags disable path-traversal validation and/or "
            "the Claude tool allowlist — with them on, authorized users "
            "(or Claude, via prompt injection) can read ~/.ssh/id_rsa or "
            "run arbitrary shell. Set I_UNDERSTAND_SECURITY_IS_DISABLED=true "
            "in the environment to explicitly acknowledge this and start "
            "the bot anyway."
        )

    logger.critical(
        "SECURITY IS INTENTIONALLY DEGRADED — "
        + ", ".join(relaxed_flags)
        + " is enabled. Authorized users (or Claude, via prompt injection) "
        "can read arbitrary files and run arbitrary shell. Do NOT run in "
        "production.",
        relaxed_flags=relaxed_flags,
        disable_security_patterns=config.disable_security_patterns,
        disable_tool_validation=config.disable_tool_validation,
    )


def build_auth_providers(
    config: Settings,
    logger: Any,
    token_storage: Optional[Any] = None,
) -> list:
    """Build the ordered list of authentication providers from configuration.

    Factored out of ``create_application`` so the auth-bootstrap rules can
    be exercised by tests in isolation — this is the most safety-critical
    piece of bot startup.

    ``token_storage`` is injected (rather than built here) so production
    wires a :class:`SQLiteTokenStorage` while tests can pass an in-memory
    double. When ``None`` and ``enable_token_auth`` is true, a
    :class:`ConfigurationError` is raised — we refuse to silently fall back
    to non-durable storage in production.

    Rules:

    1. If ``ALLOWED_USERS`` is non-empty, a ``WhitelistAuthProvider`` is
       added first.
    2. If ``ENABLE_TOKEN_AUTH`` is true, a ``TokenAuthProvider`` is added.
    3. Fall-through — when no providers have been configured yet:

       * With ``DEVELOPMENT_MODE=true`` **and** ``ALLOW_ALL_DEV_USERS=true``,
         an allow-all-dev whitelist provider is installed and a
         ``critical`` warning is logged. This path accepts commands from
         any Telegram user on earth and is intended for local development
         only.
       * With ``DEVELOPMENT_MODE=true`` but no ``ALLOW_ALL_DEV_USERS``
         opt-in, the bot refuses to start. This closes the historical
         footgun where an operator who shipped ``.env.example`` verbatim
         got an open-to-the-world RCE bot.
       * Otherwise, the bot refuses to start — a production deploy with no
         authentication configured is never desired.

    Raises:
        ConfigurationError: when the combination above is unsafe.
    """
    providers: list = []

    # Add whitelist provider if users are configured
    if config.allowed_users:
        providers.append(WhitelistAuthProvider(config.allowed_users))

    # Add token provider if enabled
    if config.enable_token_auth:
        if token_storage is None:
            raise ConfigurationError(
                "ENABLE_TOKEN_AUTH=true but no token storage was wired in "
                "(fix: pass a SQLiteTokenStorage to build_auth_providers)."
            )
        providers.append(TokenAuthProvider(config.auth_token_secret, token_storage))

    if providers:
        return providers

    # No real provider configured — decide what to do.
    #
    # This path is a CRITICAL footgun. Historically, with an empty
    # ALLOWED_USERS list and DEVELOPMENT_MODE=true, the bot silently
    # installed a whitelist provider accepting every Telegram user on
    # earth — granting RCE over Telegram via Claude's Bash tool. The
    # shipped .env.example defaulted DEVELOPMENT_MODE=true, so a careless
    # operator who forgot to set ALLOWED_USERS got an open-to-the-world
    # bot.
    #
    # We now require a SECOND explicit opt-in (ALLOW_ALL_DEV_USERS=true).
    # Without it, the bot refuses to start in that configuration.
    if config.development_mode:
        if not config.allow_all_dev_users:
            raise ConfigurationError(
                "Refusing to start: ALLOWED_USERS is empty and "
                "DEVELOPMENT_MODE=true, but ALLOW_ALL_DEV_USERS is not set "
                "to true. This configuration would accept commands from "
                "ANY Telegram user on earth (remote code execution). "
                "Either:\n"
                "  - add user IDs to ALLOWED_USERS (recommended), or\n"
                "  - explicitly opt in with ALLOW_ALL_DEV_USERS=true "
                "(dangerous, dev-only)."
            )
        logger.critical(
            "SECURITY WARNING: allow_all_dev enabled - "
            "ANY Telegram user can execute commands on this host via "
            "Claude. Do NOT run in production. Remove "
            "ALLOW_ALL_DEV_USERS=true and set ALLOWED_USERS to a concrete "
            "whitelist to close this."
        )
        providers.append(WhitelistAuthProvider([], allow_all_dev=True))
        return providers

    raise ConfigurationError("No authentication providers configured")


async def create_application(config: Settings) -> Dict[str, Any]:
    """Create and configure the application components."""
    logger = structlog.get_logger()
    logger.info("Creating application components")

    # H1 — refuse to boot if DISABLE_* flags are on without an explicit
    # operator opt-in. Runs before any security component is built so
    # we fail loudly before any listener is bound.
    enforce_security_flag_guardrails(config, logger)

    features = FeatureFlags(config)

    # Initialize storage system
    storage = Storage(config.database_url)
    await storage.initialize()

    # Create security components. Tokens and audit events are persisted
    # to SQLite so they survive a restart — critical for forensic evidence
    # after a security incident and to avoid invalidating every issued
    # token whenever the process bounces.
    token_storage = SQLiteTokenStorage(storage.tokens)
    providers = build_auth_providers(config, logger, token_storage=token_storage)

    auth_manager = AuthenticationManager(providers)
    security_validator = SecurityValidator(
        config.approved_directory,
        disable_security_patterns=config.disable_security_patterns,
    )
    rate_limiter = RateLimiter(config)

    # Create audit storage. Primary is SQLite (queryable, durable).
    # When ``AUDIT_LOG_PATH`` is set, also fan out writes to an
    # append-only JSONL file for tamper-evident forensic durability —
    # a ``logrotate`` + log-forwarder pipeline ships the file off-host
    # so an attacker with DB access cannot cover their tracks by
    # dropping SQLite rows.
    primary_audit: Any = SQLiteAuditStorage(storage.audit)
    if config.audit_log_path is not None:
        jsonl_sink = JsonlAuditStorage(config.audit_log_path)
        audit_storage = CompositeAuditStorage(primary_audit, jsonl_sink)
        logger.info(
            "Append-only audit sink enabled",
            path=str(config.audit_log_path),
        )
    else:
        audit_storage = primary_audit
    audit_logger = AuditLogger(audit_storage)

    # Create Claude integration components with persistent storage
    session_storage = SQLiteSessionStorage(storage.db_manager)
    session_manager = SessionManager(config, session_storage)

    # Create Claude SDK manager and integration facade
    logger.info("Using Claude Python SDK integration")
    sdk_manager = ClaudeSDKManager(config, security_validator=security_validator)

    claude_integration = ClaudeIntegration(
        config=config,
        sdk_manager=sdk_manager,
        session_manager=session_manager,
    )

    # --- Event bus and agentic platform components ---
    event_bus = EventBus()

    # Event security middleware
    event_security = EventSecurityMiddleware(
        event_bus=event_bus,
        security_validator=security_validator,
        auth_manager=auth_manager,
    )
    event_security.register()

    # Agent handler — translates events into Claude executions
    agent_handler = AgentHandler(
        event_bus=event_bus,
        claude_integration=claude_integration,
        default_working_directory=config.approved_directory,
        default_user_id=config.allowed_users[0] if config.allowed_users else 0,
    )
    agent_handler.register()

    # Create bot with all dependencies
    dependencies = {
        "auth_manager": auth_manager,
        "security_validator": security_validator,
        "rate_limiter": rate_limiter,
        "audit_logger": audit_logger,
        "claude_integration": claude_integration,
        "storage": storage,
        "event_bus": event_bus,
        "project_registry": None,
        "project_threads_manager": None,
    }

    bot = ClaudeCodeBot(config, dependencies)

    # Notification service and scheduler need the bot's Telegram Bot instance,
    # which is only available after bot.initialize(). We store placeholders
    # and wire them up in run_application() after initialization.

    logger.info("Application components created successfully")

    return {
        "bot": bot,
        "claude_integration": claude_integration,
        "storage": storage,
        "config": config,
        "features": features,
        "event_bus": event_bus,
        "agent_handler": agent_handler,
        "auth_manager": auth_manager,
        "security_validator": security_validator,
    }


async def run_application(app: Dict[str, Any]) -> None:
    """Run the application with graceful shutdown handling."""
    logger = structlog.get_logger()
    bot: ClaudeCodeBot = app["bot"]
    claude_integration: ClaudeIntegration = app["claude_integration"]
    storage: Storage = app["storage"]
    config: Settings = app["config"]
    features: FeatureFlags = app["features"]
    event_bus: EventBus = app["event_bus"]

    notification_service: Optional[NotificationService] = None
    scheduler: Optional[JobScheduler] = None
    project_threads_manager: Optional[ProjectThreadManager] = None

    # Set up signal handlers for graceful shutdown
    shutdown_event = asyncio.Event()

    def signal_handler(signum: int, frame: Any) -> None:
        logger.info("Shutdown signal received", signal=signum)
        shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        logger.info("Starting Claude Code Telegram Bot")

        # Initialize the bot first (creates the Telegram Application)
        await bot.initialize()

        if config.enable_project_threads:
            if not config.projects_config_path:
                raise ConfigurationError(
                    "Project thread mode enabled but required settings are missing"
                )
            registry = load_project_registry(
                config_path=config.projects_config_path,
                approved_directory=config.approved_directory,
            )
            project_threads_manager = ProjectThreadManager(
                registry=registry,
                repository=storage.project_threads,
                sync_action_interval_seconds=(
                    config.project_threads_sync_action_interval_seconds
                ),
            )

            bot.deps["project_registry"] = registry
            bot.deps["project_threads_manager"] = project_threads_manager

            if config.project_threads_mode == "group":
                if config.project_threads_chat_id is None:
                    raise ConfigurationError(
                        "Group thread mode requires PROJECT_THREADS_CHAT_ID"
                    )
                sync_result = await project_threads_manager.sync_topics(
                    bot.app.bot,
                    chat_id=config.project_threads_chat_id,
                )
                logger.info(
                    "Project thread startup sync complete",
                    mode=config.project_threads_mode,
                    chat_id=config.project_threads_chat_id,
                    created=sync_result.created,
                    reused=sync_result.reused,
                    renamed=sync_result.renamed,
                    failed=sync_result.failed,
                    deactivated=sync_result.deactivated,
                )

        # Now wire up components that need the Telegram Bot instance
        telegram_bot = bot.app.bot

        # Start event bus
        await event_bus.start()

        # Notification service
        notification_service = NotificationService(
            event_bus=event_bus,
            bot=telegram_bot,
            default_chat_ids=config.notification_chat_ids or [],
        )
        notification_service.register()
        await notification_service.start()

        # Collect concurrent tasks
        tasks = []

        # Bot task — use start() which handles its own initialization check
        bot_task = asyncio.create_task(bot.start())
        tasks.append(bot_task)

        # API server (if enabled)
        if features.api_server_enabled:
            from src.api.server import run_api_server

            api_task = asyncio.create_task(
                run_api_server(event_bus, config, storage.db_manager)
            )
            tasks.append(api_task)
            logger.info("API server enabled", port=config.api_server_port)

        # Scheduler (if enabled)
        if features.scheduler_enabled:
            scheduler = JobScheduler(
                event_bus=event_bus,
                db_manager=storage.db_manager,
                default_working_directory=config.approved_directory,
            )
            await scheduler.start()
            logger.info("Job scheduler enabled")

        # Shutdown task
        shutdown_task = asyncio.create_task(shutdown_event.wait())
        tasks.append(shutdown_task)

        # Wait for any task to complete or shutdown signal
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        # Check completed tasks for exceptions
        for task in done:
            if task.cancelled():
                continue
            exc = task.exception()
            if exc is not None:
                logger.error(
                    "Task failed",
                    task=task.get_name(),
                    error=str(exc),
                    error_type=type(exc).__name__,
                )

        # Cancel remaining tasks
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    except Exception as e:
        logger.error("Application error", error=str(e))
        raise
    finally:
        # Ordered shutdown:
        #   0. Signal every in-flight request to interrupt (R4) so
        #      orphaned Claude subprocesses get a chance to exit
        #      cleanly instead of leaving their Stop buttons pointing
        #      at a dead process.
        #   1. scheduler -> API -> notification -> bot -> claude -> storage
        logger.info("Shutting down application")

        try:
            # Step 0 — interrupt any active Claude runs. Do this
            # BEFORE we stop the bot so handlers can still post the
            # "interrupted" reply text through PTB.
            try:
                interrupted = bot.orchestrator.interrupt_all_active_requests()
                if interrupted:
                    # Small grace period so the interrupt watcher
                    # inside the SDK has time to call
                    # ``client.interrupt()`` and the handler can
                    # finish its cleanup block.
                    await asyncio.sleep(0.5)
            except Exception as interrupt_err:
                logger.warning(
                    "Failed to interrupt active requests cleanly",
                    error=str(interrupt_err),
                )

            if scheduler:
                await scheduler.stop()
            if notification_service:
                await notification_service.stop()
            await event_bus.stop()
            await bot.stop()
            await claude_integration.shutdown()
            await storage.close()
        except Exception as e:
            logger.error("Error during shutdown", error=str(e))

        logger.info("Application shutdown complete")


async def main() -> None:
    """Main application entry point."""
    args = parse_args()
    setup_logging(debug=args.debug)

    logger = structlog.get_logger()
    logger.info("Starting Claude Code Telegram Bot", version=__version__)

    try:
        # Load configuration
        from src.config import FeatureFlags, load_config

        config = load_config(config_file=args.config_file)
        features = FeatureFlags(config)

        logger.info(
            "Configuration loaded",
            environment="production" if config.is_production else "development",
            enabled_features=features.get_enabled_features(),
            debug=config.debug,
        )

        # Initialize bot and Claude integration
        app = await create_application(config)
        await run_application(app)

    except ConfigurationError as e:
        logger.error("Configuration error", error=str(e))
        sys.exit(1)
    except Exception as e:
        logger.exception("Unexpected error", error=str(e))
        sys.exit(1)


def run() -> None:
    """Synchronous entry point for setuptools."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        sys.exit(0)


if __name__ == "__main__":
    run()
