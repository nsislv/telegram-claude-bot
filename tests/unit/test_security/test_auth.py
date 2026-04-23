"""Tests for authentication system."""

from datetime import UTC, datetime, timedelta

import pytest

from src.exceptions import SecurityError
from src.security.auth import (
    AuthenticationManager,
    InMemoryTokenStorage,
    TokenAuthProvider,
    UserSession,
    WhitelistAuthProvider,
)


class TestUserSession:
    """Test UserSession functionality."""

    def test_session_creation(self):
        """Test session creation."""
        session = UserSession(
            user_id=123,
            auth_provider="TestProvider",
            created_at=datetime.now(UTC),
            last_activity=datetime.now(UTC),
        )

        assert session.user_id == 123
        assert session.auth_provider == "TestProvider"
        assert not session.is_expired()

    def test_session_expiry(self):
        """Test session expiry logic."""
        old_time = datetime.now(UTC) - timedelta(hours=25)
        session = UserSession(
            user_id=123,
            auth_provider="TestProvider",
            created_at=old_time,
            last_activity=old_time,
        )

        assert session.is_expired()

    def test_session_refresh(self):
        """Test session refresh."""
        old_time = datetime.now(UTC) - timedelta(hours=1)
        session = UserSession(
            user_id=123,
            auth_provider="TestProvider",
            created_at=old_time,
            last_activity=old_time,
        )

        session.refresh()
        assert not session.is_expired()
        assert session.last_activity > old_time


class TestWhitelistAuthProvider:
    """Test whitelist authentication provider."""

    async def test_allowed_user_authentication(self):
        """Test authentication of allowed user."""
        provider = WhitelistAuthProvider([123, 456])

        # Test allowed user
        result = await provider.authenticate(123, {})
        assert result is True

        # Test non-allowed user
        result = await provider.authenticate(789, {})
        assert result is False

    async def test_get_user_info(self):
        """Test user info retrieval."""
        provider = WhitelistAuthProvider([123])

        # Allowed user
        info = await provider.get_user_info(123)
        assert info is not None
        assert info["user_id"] == 123
        assert info["auth_type"] == "whitelist"

        # Non-allowed user
        info = await provider.get_user_info(456)
        assert info is None


class TestInMemoryTokenStorage:
    """Test in-memory token storage."""

    @pytest.fixture
    def storage(self):
        return InMemoryTokenStorage()

    async def test_store_and_retrieve_token(self, storage):
        """Test storing and retrieving tokens."""
        user_id = 123
        token_hash = "test_hash"
        expires_at = datetime.now(UTC) + timedelta(days=1)

        await storage.store_token(user_id, token_hash, expires_at)

        token_data = await storage.get_user_token(user_id)
        assert token_data is not None
        assert token_data["hash"] == token_hash
        assert token_data["expires_at"] == expires_at

    async def test_expired_token_cleanup(self, storage):
        """Test that expired tokens are cleaned up."""
        user_id = 123
        token_hash = "test_hash"
        expires_at = datetime.now(UTC) - timedelta(days=1)  # Expired

        await storage.store_token(user_id, token_hash, expires_at)

        token_data = await storage.get_user_token(user_id)
        assert token_data is None  # Should be cleaned up

    async def test_revoke_token(self, storage):
        """Test token revocation."""
        user_id = 123
        token_hash = "test_hash"
        expires_at = datetime.now(UTC) + timedelta(days=1)

        await storage.store_token(user_id, token_hash, expires_at)
        await storage.revoke_token(user_id)

        token_data = await storage.get_user_token(user_id)
        assert token_data is None


class TestTokenAuthProvider:
    """Test token authentication provider."""

    @pytest.fixture
    def provider(self):
        storage = InMemoryTokenStorage()
        return TokenAuthProvider("secret123", storage)

    async def test_generate_and_verify_token(self, provider):
        """Test token generation and verification."""
        user_id = 123

        # Generate token
        token = await provider.generate_token(user_id)
        assert token is not None
        assert len(token) > 20  # Should be a substantial token

        # Verify token
        result = await provider.authenticate(user_id, {"token": token})
        assert result is True

        # Test wrong token
        result = await provider.authenticate(user_id, {"token": "wrong_token"})
        assert result is False

    async def test_authentication_without_token(self, provider):
        """Test authentication fails without token."""
        result = await provider.authenticate(123, {})
        assert result is False

    async def test_get_user_info(self, provider):
        """Test user info for token auth."""
        user_id = 123

        # No token yet
        info = await provider.get_user_info(user_id)
        assert info is None

        # Generate token
        await provider.generate_token(user_id)

        # Should have info now
        info = await provider.get_user_info(user_id)
        assert info is not None
        assert info["user_id"] == user_id
        assert info["auth_type"] == "token"

    async def test_token_revocation(self, provider):
        """Test token revocation."""
        user_id = 123

        token = await provider.generate_token(user_id)

        # Should work before revocation
        result = await provider.authenticate(user_id, {"token": token})
        assert result is True

        # Revoke token
        await provider.revoke_token(user_id)

        # Should fail after revocation
        result = await provider.authenticate(user_id, {"token": token})
        assert result is False


class TestTokenHashingHMAC:
    """M2 + M3 regression tests.

    Pre-fix, ``_hash_token`` ran ``sha256(token + secret)`` — a
    length-extension-prone pattern — and ``_verify_token`` used plain
    ``==`` on the hex digests. These tests pin the new HMAC-SHA256
    hash and the ``hmac.compare_digest`` verification so a future
    refactor cannot silently regress to the old shape.
    """

    @pytest.fixture
    def provider(self):
        return TokenAuthProvider("secret-key", InMemoryTokenStorage())

    def test_hash_matches_hmac_sha256(self, provider):
        """Computed hash must match a fresh HMAC-SHA256(secret, token)."""
        import hashlib
        import hmac

        expected = hmac.new(b"secret-key", b"abc123", hashlib.sha256).hexdigest()
        assert provider._hash_token("abc123") == expected

    def test_hash_differs_from_old_concat_sha256(self, provider):
        """Sanity check: HMAC output must differ from the old
        ``sha256(token + secret)`` so we know we're on the new path."""
        import hashlib

        old_hash = hashlib.sha256(b"abc123secret-key").hexdigest()
        assert provider._hash_token("abc123") != old_hash

    def test_hash_is_deterministic(self, provider):
        assert provider._hash_token("same") == provider._hash_token("same")

    def test_hash_differs_across_secrets(self):
        p1 = TokenAuthProvider("key-1", InMemoryTokenStorage())
        p2 = TokenAuthProvider("key-2", InMemoryTokenStorage())
        assert p1._hash_token("same-token") != p2._hash_token("same-token")

    def test_verify_accepts_matching_hash(self, provider):
        hashed = provider._hash_token("token-A")
        assert provider._verify_token("token-A", hashed) is True

    def test_verify_rejects_mismatched_hash(self, provider):
        hashed = provider._hash_token("token-A")
        assert provider._verify_token("token-B", hashed) is False

    def test_verify_rejects_when_stored_hash_truncated(self, provider):
        """Length-mismatched inputs must not slip through."""
        hashed = provider._hash_token("token-A")
        assert provider._verify_token("token-A", hashed[:-1]) is False

    def test_verify_uses_compare_digest(self, monkeypatch, provider):
        """Directly verify that ``hmac.compare_digest`` is on the
        critical path. A regression back to ``==`` would make this
        test fail — the sentinel argument is intercepted only if
        we call ``compare_digest``."""
        import src.security.auth as auth_module

        calls: list = []

        def fake_compare_digest(a, b):
            calls.append((a, b))
            return a == b

        monkeypatch.setattr(auth_module.hmac, "compare_digest", fake_compare_digest)

        hashed = provider._hash_token("x")
        provider._verify_token("x", hashed)
        assert calls, "verify_token must route through hmac.compare_digest"

    def test_secretstr_secret_is_unwrapped(self):
        """Production wires a Pydantic ``SecretStr``. Its ``str()``
        returns ``"**********"`` — if we accidentally stringify,
        every user's hash would be keyed by that constant mask.
        ``_coerce_secret_bytes`` must unwrap first."""
        pytest.importorskip("pydantic")
        from pydantic import SecretStr

        provider = TokenAuthProvider(
            SecretStr("real-production-secret"), InMemoryTokenStorage()
        )
        # Independent HMAC reference built from the unwrapped secret.
        import hashlib
        import hmac

        expected = hmac.new(b"real-production-secret", b"t", hashlib.sha256).hexdigest()
        assert provider._hash_token("t") == expected

        # And the masked-string keyed HMAC (what we'd get on
        # regression) must NOT match.
        masked = hmac.new(b"**********", b"t", hashlib.sha256).hexdigest()
        assert provider._hash_token("t") != masked

    def test_none_secret_raises(self):
        """Direct callers that omit the secret are refused at hash
        time; ``build_auth_providers`` already refuses at boot."""
        provider = TokenAuthProvider(None, InMemoryTokenStorage())  # type: ignore[arg-type]
        with pytest.raises(SecurityError):
            provider._hash_token("anything")


class TestAuthenticationManager:
    """Test authentication manager."""

    @pytest.fixture
    def auth_manager(self):
        whitelist_provider = WhitelistAuthProvider([123, 456])
        token_storage = InMemoryTokenStorage()
        token_provider = TokenAuthProvider("secret123", token_storage)

        return AuthenticationManager([whitelist_provider, token_provider])

    def test_manager_requires_providers(self):
        """Test that manager requires at least one provider."""
        with pytest.raises(SecurityError):
            AuthenticationManager([])

    async def test_whitelist_authentication(self, auth_manager):
        """Test authentication through whitelist."""
        # Allowed user should authenticate
        result = await auth_manager.authenticate_user(123)
        assert result is True
        assert auth_manager.is_authenticated(123)

        # Non-allowed user should fail
        result = await auth_manager.authenticate_user(999)
        assert result is False
        assert not auth_manager.is_authenticated(999)

    async def test_token_authentication(self, auth_manager):
        """Test authentication through token."""
        user_id = 789  # Not in whitelist

        # Get token provider
        token_provider = auth_manager.providers[1]
        token = await token_provider.generate_token(user_id)

        # Should authenticate with token
        result = await auth_manager.authenticate_user(user_id, {"token": token})
        assert result is True
        assert auth_manager.is_authenticated(user_id)

    async def test_session_management(self, auth_manager):
        """Test session creation and management."""
        user_id = 123

        # Authenticate user
        await auth_manager.authenticate_user(user_id)

        # Should have session
        session = auth_manager.get_session(user_id)
        assert session is not None
        assert session.user_id == user_id

        # Refresh session
        old_activity = session.last_activity
        result = auth_manager.refresh_session(user_id)
        assert result is True
        assert session.last_activity > old_activity

        # End session
        auth_manager.end_session(user_id)
        assert not auth_manager.is_authenticated(user_id)

    async def test_expired_session_cleanup(self, auth_manager):
        """Test cleanup of expired sessions."""
        user_id = 123

        # Authenticate user
        await auth_manager.authenticate_user(user_id)

        # Manually expire session
        session = auth_manager.get_session(user_id)
        session.last_activity = datetime.now(UTC) - timedelta(hours=25)

        # Should no longer be authenticated
        assert not auth_manager.is_authenticated(user_id)
        assert auth_manager.get_session(user_id) is None

    async def test_session_info(self, auth_manager):
        """Test session information retrieval."""
        user_id = 123

        # No session initially
        info = auth_manager.get_session_info(user_id)
        assert info is None

        # Authenticate and get info
        await auth_manager.authenticate_user(user_id)
        info = auth_manager.get_session_info(user_id)

        assert info is not None
        assert info["user_id"] == user_id
        assert "created_at" in info
        assert "last_activity" in info
        assert info["is_expired"] is False

    async def test_active_sessions_count(self, auth_manager):
        """Test active sessions counting."""
        assert auth_manager.get_active_sessions_count() == 0

        # Authenticate two users
        await auth_manager.authenticate_user(123)
        await auth_manager.authenticate_user(456)

        assert auth_manager.get_active_sessions_count() == 2

        # End one session
        auth_manager.end_session(123)
        assert auth_manager.get_active_sessions_count() == 1
