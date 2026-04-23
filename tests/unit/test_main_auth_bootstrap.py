"""Tests for the auth-provider bootstrap in ``src.main``.

Covers C2 from upgrade.md — the ``DEVELOPMENT_MODE=true`` +
``ALLOWED_USERS=[]`` path used to silently enable an allow-all auth
provider, handing RCE over Telegram to any user on earth. The fix adds
a second explicit opt-in (``ALLOW_ALL_DEV_USERS=true``) and refuses to
start without it.
"""

from unittest.mock import MagicMock

import pytest

from src.exceptions import ConfigurationError
from src.main import build_auth_providers
from src.security.auth import TokenAuthProvider, WhitelistAuthProvider


def _config(**overrides):
    """Build a minimal Settings-shaped mock for the bootstrap rules."""
    cfg = MagicMock()
    cfg.allowed_users = overrides.pop("allowed_users", [])
    cfg.enable_token_auth = overrides.pop("enable_token_auth", False)
    cfg.auth_token_secret = overrides.pop("auth_token_secret", "test-secret")
    cfg.development_mode = overrides.pop("development_mode", False)
    cfg.allow_all_dev_users = overrides.pop("allow_all_dev_users", False)
    assert not overrides, f"unexpected overrides: {overrides}"
    return cfg


def test_returns_whitelist_provider_when_users_configured():
    """Concrete ALLOWED_USERS — the normal, safe production path."""
    providers = build_auth_providers(_config(allowed_users=[111, 222]), MagicMock())

    assert len(providers) == 1
    assert isinstance(providers[0], WhitelistAuthProvider)


def test_adds_token_provider_when_enabled():
    """Token auth stacks on top of whitelist when both configured."""
    providers = build_auth_providers(
        _config(allowed_users=[111], enable_token_auth=True),
        MagicMock(),
        token_storage=MagicMock(),
    )

    assert len(providers) == 2
    assert isinstance(providers[0], WhitelistAuthProvider)
    assert isinstance(providers[1], TokenAuthProvider)


def test_token_only_config_does_not_trigger_dev_fallback():
    """Token-only setups must not trip the allow-all-dev fallback even
    with development_mode=true — there IS a real auth provider."""
    providers = build_auth_providers(
        _config(
            allowed_users=[],
            enable_token_auth=True,
            development_mode=True,
            allow_all_dev_users=False,
        ),
        MagicMock(),
        token_storage=MagicMock(),
    )

    assert len(providers) == 1
    assert isinstance(providers[0], TokenAuthProvider)


def test_token_auth_without_storage_refuses_to_start():
    """C3 — token auth without a durable storage must NOT silently fall
    back to an in-memory store. A misconfiguration here would invalidate
    every issued token on restart and lose forensic traces."""
    with pytest.raises(ConfigurationError) as exc:
        build_auth_providers(
            _config(allowed_users=[111], enable_token_auth=True),
            MagicMock(),
            # token_storage intentionally omitted
        )
    assert "token storage" in str(exc.value).lower()


class TestClosedByDefaultRefusesToStart:
    """C2 — the refuse-to-start behaviour."""

    def test_no_users_no_dev_mode_raises(self):
        """Production-like: nothing configured → explicit error."""
        with pytest.raises(ConfigurationError) as exc:
            build_auth_providers(_config(), MagicMock())
        assert "No authentication providers" in str(exc.value)

    def test_dev_mode_without_explicit_opt_in_raises(self):
        """``DEVELOPMENT_MODE=true`` alone MUST NOT open the bot up."""
        with pytest.raises(ConfigurationError) as exc:
            build_auth_providers(
                _config(development_mode=True, allow_all_dev_users=False),
                MagicMock(),
            )
        message = str(exc.value)
        assert "ALLOW_ALL_DEV_USERS" in message
        assert "ANY Telegram user" in message
        assert "remote code execution" in message.lower()

    def test_allow_all_dev_users_without_dev_mode_still_refused(self):
        """Raising the opt-in flag without DEVELOPMENT_MODE is a
        misconfiguration (the flag is only honoured in development)."""
        with pytest.raises(ConfigurationError):
            build_auth_providers(
                _config(development_mode=False, allow_all_dev_users=True),
                MagicMock(),
            )


class TestExplicitDevOptInStartsWithWarning:
    """C2 — when both DEVELOPMENT_MODE and ALLOW_ALL_DEV_USERS are true."""

    def test_installs_allow_all_dev_provider(self):
        logger = MagicMock()
        providers = build_auth_providers(
            _config(development_mode=True, allow_all_dev_users=True),
            logger,
        )

        assert len(providers) == 1
        provider = providers[0]
        assert isinstance(provider, WhitelistAuthProvider)
        assert provider.allow_all_dev is True

    def test_logs_critical_warning(self):
        logger = MagicMock()
        build_auth_providers(
            _config(development_mode=True, allow_all_dev_users=True),
            logger,
        )

        assert (
            logger.critical.called
        ), "expected a critical-level log when allow-all-dev is enabled"
        message = logger.critical.call_args.args[0]
        assert "ANY Telegram user" in message
        assert "Do NOT run in production" in message
