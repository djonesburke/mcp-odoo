"""Tests for the static shared-bearer-token HTTP auth gate.

Covers the verifier (accept/reject/constant-time), the builder, the CLI wiring
seam, mode mutual-exclusion, and the fail-closed posture that refuses to start
an ungated HTTP transport. Complements test_auth.py (OAuth introspection).
"""

import argparse
import importlib

import hmac as real_hmac
import pytest

from odoo_mcp import auth


def _args(transport="streamable-http", health=False):
    return argparse.Namespace(transport=transport, health=health)


def _clear_auth_env(monkeypatch):
    for key in list(auth.os.environ):
        if key.startswith(auth.AUTH_ENV_PREFIX):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv(auth.STATIC_TOKEN_ENV, raising=False)
    monkeypatch.delenv(auth.STATIC_RESOURCE_ENV, raising=False)
    monkeypatch.delenv("MCP_ALLOW_UNAUTHENTICATED_HTTP", raising=False)


# ---------------------------------------------------------------------------
# Token parsing
# ---------------------------------------------------------------------------


def test_static_tokens_parses_single_and_csv_dedup_and_blanks(monkeypatch):
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv(auth.STATIC_TOKEN_ENV, "tok-1")
    assert auth.static_tokens() == ["tok-1"]

    monkeypatch.setenv(auth.STATIC_TOKEN_ENV, " a , b ,, a , c ")
    # blanks dropped, order preserved, duplicate "a" removed
    assert auth.static_tokens() == ["a", "b", "c"]
    assert auth.static_auth_configured() is True


def test_static_tokens_empty_when_unset_or_blank(monkeypatch):
    _clear_auth_env(monkeypatch)
    assert auth.static_tokens() == []
    assert auth.static_auth_configured() is False
    monkeypatch.setenv(auth.STATIC_TOKEN_ENV, "   ,  , ")
    assert auth.static_tokens() == []
    assert auth.static_auth_configured() is False


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


def test_verifier_accepts_valid_token():
    import asyncio

    verifier = auth.StaticTokenVerifier(["tok-1", "tok-2"], resource_url="https://r/mcp")
    token = asyncio.run(verifier.verify_token("tok-2"))
    assert token is not None
    assert token.client_id == auth.STATIC_CLIENT_ID
    assert token.scopes == []
    assert token.expires_at is None
    assert token.resource == "https://r/mcp"
    assert token.token == "tok-2"


def test_verifier_rejects_invalid_and_empty_allowlist():
    import asyncio

    verifier = auth.StaticTokenVerifier(["tok-1"], resource_url="https://r/mcp")
    assert asyncio.run(verifier.verify_token("nope")) is None
    assert asyncio.run(verifier.verify_token("")) is None
    assert asyncio.run(verifier.verify_token("tok-1x")) is None  # prefix must not pass

    empty = auth.StaticTokenVerifier([], resource_url="https://r/mcp")
    assert asyncio.run(empty.verify_token("tok-1")) is None
    assert asyncio.run(empty.verify_token("")) is None


def test_verifier_uses_constant_time_compare_over_all_tokens(monkeypatch):
    """compare_digest is the primitive, and every configured token is checked
    (no short-circuit) so timing does not reveal which/whether one matched."""
    import asyncio

    calls = {"n": 0}
    original_compare = real_hmac.compare_digest

    def counting_compare(a, b):
        calls["n"] += 1
        return original_compare(a, b)

    monkeypatch.setattr(auth.hmac, "compare_digest", counting_compare)

    verifier = auth.StaticTokenVerifier(
        ["a", "b", "c"], resource_url="https://r/mcp"
    )
    # Match at the FIRST position must still compare all three tokens.
    calls["n"] = 0
    assert asyncio.run(verifier.verify_token("a")) is not None
    assert calls["n"] == 3

    # A miss also compares all three.
    calls["n"] = 0
    assert asyncio.run(verifier.verify_token("z")) is None
    assert calls["n"] == 3


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def test_build_static_auth_none_when_unconfigured(monkeypatch):
    _clear_auth_env(monkeypatch)
    assert auth.build_static_auth() is None
    assert auth.static_auth_posture()["enabled"] is False


def test_build_static_auth_builds_settings_and_verifier(monkeypatch):
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv(auth.STATIC_TOKEN_ENV, "t1,t2")
    monkeypatch.setenv(auth.STATIC_RESOURCE_ENV, "https://mcp-owner.example.com/mcp")

    built = auth.build_static_auth()
    assert built is not None
    settings, verifier = built
    assert str(settings.resource_server_url) == "https://mcp-owner.example.com/mcp"
    assert settings.required_scopes is None
    assert isinstance(verifier, auth.StaticTokenVerifier)
    assert verifier.resource_url == "https://mcp-owner.example.com/mcp"

    posture = auth.static_auth_posture()
    assert posture["enabled"] is True
    assert posture["token_count"] == 2
    # posture never leaks token material
    import json

    assert "t1" not in json.dumps(posture)
    assert "t2" not in json.dumps(posture)


def test_build_static_auth_defaults_resource_when_unset(monkeypatch):
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv(auth.STATIC_TOKEN_ENV, "t1")
    built = auth.build_static_auth()
    assert built is not None
    settings, _ = built
    assert str(settings.resource_server_url) == auth.STATIC_DEFAULT_RESOURCE


# ---------------------------------------------------------------------------
# Real FastMCP seam: BearerAuthBackend -> 401 wiring
# ---------------------------------------------------------------------------


class _FakeConn:
    def __init__(self, headers):
        self.headers = headers


def test_bearer_backend_authenticates_valid_and_rejects_invalid():
    """Prove the static verifier plugs into the SDK backend that drives the
    401 path: a valid bearer authenticates; missing/invalid/non-bearer -> None
    (which RequireAuthMiddleware turns into HTTP 401)."""
    import asyncio

    from mcp.server.auth.middleware.bearer_auth import (
        AuthenticatedUser,
        BearerAuthBackend,
    )

    verifier = auth.StaticTokenVerifier(["sekret"], resource_url="https://r/mcp")
    backend = BearerAuthBackend(verifier)

    ok = asyncio.run(
        backend.authenticate(_FakeConn({"authorization": "Bearer sekret"}))
    )
    assert ok is not None
    _creds, user = ok
    assert isinstance(user, AuthenticatedUser)
    assert user.access_token.client_id == auth.STATIC_CLIENT_ID

    assert asyncio.run(backend.authenticate(_FakeConn({}))) is None
    assert (
        asyncio.run(backend.authenticate(_FakeConn({"authorization": "Bearer wrong"})))
        is None
    )
    assert (
        asyncio.run(backend.authenticate(_FakeConn({"authorization": "Basic sekret"})))
        is None
    )


# ---------------------------------------------------------------------------
# CLI wiring: configure_static_auth
# ---------------------------------------------------------------------------


def test_configure_static_auth_wires_http_only(monkeypatch, capsys):
    main_mod = importlib.import_module("odoo_mcp.__main__")
    server = importlib.import_module("odoo_mcp.server")
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv(auth.STATIC_TOKEN_ENV, "tok-a,tok-b")
    monkeypatch.setattr(server.mcp.settings, "auth", None, raising=False)
    monkeypatch.setattr(server.mcp, "_token_verifier", None, raising=False)

    # stdio -> ignored with a warning, nothing wired
    main_mod.configure_static_auth(_args(transport="stdio"))
    assert server.mcp.settings.auth is None
    assert server.mcp._token_verifier is None
    assert "ignored" in capsys.readouterr().err

    # http -> wired
    main_mod.configure_static_auth(_args(transport="streamable-http"))
    assert server.mcp.settings.auth is not None
    assert isinstance(server.mcp._token_verifier, auth.StaticTokenVerifier)
    err = capsys.readouterr().err
    assert "Static header auth enabled" in err
    # startup message must not print the token(s)
    assert "tok-a" not in err and "tok-b" not in err


# ---------------------------------------------------------------------------
# CLI wiring: configure_http_auth (mutual exclusion + fail closed)
# ---------------------------------------------------------------------------


def test_configure_http_auth_rejects_both_modes(monkeypatch):
    main_mod = importlib.import_module("odoo_mcp.__main__")
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv(auth.STATIC_TOKEN_ENV, "tok")
    monkeypatch.setenv("ODOO_MCP_AUTH_ISSUER_URL", "https://as.example.com")
    with pytest.raises(ValueError, match="only ONE HTTP auth mode"):
        main_mod.configure_http_auth(_args(transport="streamable-http"))


def test_configure_http_auth_fails_closed_without_auth(monkeypatch):
    main_mod = importlib.import_module("odoo_mcp.__main__")
    _clear_auth_env(monkeypatch)
    with pytest.raises(ValueError, match="Refusing to start an HTTP transport"):
        main_mod.configure_http_auth(_args(transport="streamable-http"))
    # sse is an HTTP transport too
    with pytest.raises(ValueError, match="Refusing to start an HTTP transport"):
        main_mod.configure_http_auth(_args(transport="sse"))


def test_configure_http_auth_stdio_needs_no_auth(monkeypatch):
    main_mod = importlib.import_module("odoo_mcp.__main__")
    _clear_auth_env(monkeypatch)
    # stdio is not remotely reachable; must not fail closed
    main_mod.configure_http_auth(_args(transport="stdio"))


def test_configure_http_auth_explicit_unauth_opt_in(monkeypatch, capsys):
    main_mod = importlib.import_module("odoo_mcp.__main__")
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv("MCP_ALLOW_UNAUTHENTICATED_HTTP", "1")
    # opt-in allows an ungated HTTP transport, but loudly
    main_mod.configure_http_auth(_args(transport="streamable-http"))
    assert "NO authentication" in capsys.readouterr().err


def test_configure_http_auth_health_probe_does_not_fail_closed(monkeypatch):
    main_mod = importlib.import_module("odoo_mcp.__main__")
    _clear_auth_env(monkeypatch)
    # a --health probe never serves traffic, so it must not be blocked
    main_mod.configure_http_auth(_args(transport="streamable-http", health=True))


def test_configure_http_auth_wires_static_on_http(monkeypatch):
    main_mod = importlib.import_module("odoo_mcp.__main__")
    server = importlib.import_module("odoo_mcp.server")
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv(auth.STATIC_TOKEN_ENV, "tok")
    monkeypatch.setattr(server.mcp.settings, "auth", None, raising=False)
    monkeypatch.setattr(server.mcp, "_token_verifier", None, raising=False)

    main_mod.configure_http_auth(_args(transport="streamable-http"))
    assert isinstance(server.mcp._token_verifier, auth.StaticTokenVerifier)


def test_static_auth_posture_surfaced_in_security_report(monkeypatch):
    server = importlib.import_module("odoo_mcp.server")
    _clear_auth_env(monkeypatch)
    monkeypatch.setenv(auth.STATIC_TOKEN_ENV, "tok-1,tok-2")
    report = server.runtime_security_report()
    assert report["static_http_auth"]["enabled"] is True
    assert report["static_http_auth"]["token_count"] == 2
    # never leaks tokens
    import json

    assert "tok-1" not in json.dumps(report["static_http_auth"])
