"""Bridge hardening: field-ACL fail-closed, token identity, redirects, throttles."""

# Fixtures are imported from test_bridge_surface and re-declared as test arguments.
# ruff: noqa: F811

from __future__ import annotations

import asyncio
import json
import logging
import os
import stat
import threading
import time
from urllib.parse import parse_qs, urlparse

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.testclient import TestClient

from odoo_mcp import server as srv
from odoo_mcp.bridge import surface
from odoo_mcp.bridge.app import build_bridge, ensure_field_policy
from odoo_mcp.bridge.config import BridgeConfigError, load_config
from odoo_mcp.bridge.oauth_routes import IpThrottleMiddleware, build_oauth_routes
from odoo_mcp.bridge.provider import BridgeOAuthProvider
from odoo_mcp.bridge.runtime import ensure_state_dir
from odoo_mcp.bridge.seal import seal, unseal
from odoo_mcp.bridge.surface import BridgeAppContext, wrap_tool
from odoo_mcp.server_core import mcp
from tests.test_bridge_core import _env
from tests.test_bridge_oauth import (
    ISSUER,
    KEY,
    REDIRECT,
    SEAL,
    Odoo,
    _authorize,
    _exchange,
    _full_flow,
    _pkce,
    _register,
    _run,
    _signin_fields,
)
from tests.test_bridge_surface import (  # noqa: F401  (fixtures)
    POLICY,
    SECRET_A,
    _as,
    _call,
    _config_with,
    _token,
    _tool,
    field_policy,
    restore_global_mcp,
    runtime,
)

# ---------------------------------------------------------------- policy


def _bridge_call(runtime, name, arguments, uid=11, login="a@example.com"):
    build = build_bridge(runtime.config, runtime=runtime, verifier=lambda lg, k: uid)
    try:
        token = build.provider._issue("c", uid, login, SECRET_A, ["odoo.read"]).access_token
        with TestClient(build.app, base_url="http://localhost") as http:
            _, body = _call(http, token, name, arguments)
        return body["result"]["structuredContent"]
    finally:
        build.undo()


def test_default_keyed_policy_masks_search_records(runtime, restore_global_mcp):
    out = _bridge_call(
        runtime, "search_records", {"model": "res.partner", "fields": ["name", "credit_limit"]}
    )
    assert out["success"] is True
    assert all("credit_limit" not in row for row in out["result"])
    assert out["redacted_fields"] == ["credit_limit"]


def test_default_keyed_policy_masks_read_record(runtime, restore_global_mcp):
    out = _bridge_call(runtime, "read_record", {"model": "res.partner", "record_id": 1})
    assert out["success"] is True
    assert out["redacted_fields"] == ["credit_limit"]
    assert "credit_limit" not in out["result"] and out["result"]["name"]


def test_read_attachment_refuses_restricted_attachment_field(runtime, restore_global_mcp):
    out = _bridge_call(runtime, "read_attachment", {"attachment_id": 5})
    assert out["success"] is False
    assert "restricts the field" in out["error"]


def test_label_and_policy_key_are_separate(runtime, restore_global_mcp):
    assert runtime.config.instance == "staging"
    assert runtime.config.policy_instance == "default"
    ctx = BridgeAppContext(runtime)
    assert ctx._default_instance_name == "default"
    undo = surface.install_seams(runtime)
    try:
        assert srv.resolve_default_instance_name() == "default"
        assert srv.resolve_instance_name(None) == "default"
        assert srv.resolve_instance_name("staging") == "default"
        assert srv.load_instances_config()[0] == "default"
        with pytest.raises(ValueError):
            srv.resolve_instance_name("production")
    finally:
        undo()


def test_custom_policy_instance_key(runtime, restore_global_mcp, tmp_path, monkeypatch):
    path = tmp_path / "custom.json"
    path.write_text(
        json.dumps({"field_acl": {"erp": {"res.partner": {"deny": ["credit_limit"]}}}})
    )
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(path))
    runtime.config = _config_with(runtime.config, policy_instance="erp")
    out = _bridge_call(
        runtime, "search_records", {"model": "res.partner", "fields": ["name", "credit_limit"]}
    )
    assert all("credit_limit" not in row for row in out["result"])


def test_policy_startup_refusals(runtime, restore_global_mcp, tmp_path, monkeypatch, capsys):
    cfg = runtime.config
    ensure_field_policy(cfg)  # a policy with rules under the key is accepted
    assert "field ACL" in capsys.readouterr().err  # and its resolution is reported

    monkeypatch.delenv("ODOO_MCP_FIELD_POLICY_FILE")
    with pytest.raises(BridgeConfigError, match="must be set"):
        ensure_field_policy(cfg)

    # the cwd fallback never counts, even with the file sitting right there
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / "odoo_mcp_policy.json").write_text(json.dumps(POLICY))
    monkeypatch.chdir(cwd)
    with pytest.raises(BridgeConfigError, match="must be set"):
        ensure_field_policy(cfg)

    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(tmp_path / "absent.json"))
    with pytest.raises(BridgeConfigError, match="does not point at a file"):
        ensure_field_policy(cfg)

    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(bad))
    with pytest.raises(Exception, match="Cannot read field policy"):
        ensure_field_policy(cfg)

    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"field_acl": {"elsewhere": {"*": {"deny": ["x"]}}}}))
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(wrong))
    with pytest.raises(BridgeConfigError, match="no rules under 'default'"):
        ensure_field_policy(cfg)

    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"field_acl": {}}))
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(empty))
    with pytest.raises(BridgeConfigError, match="no rules under"):
        ensure_field_policy(cfg)


def test_build_refuses_without_policy_and_leaves_surface_alone(
    runtime, restore_global_mcp, monkeypatch
):
    monkeypatch.delenv("ODOO_MCP_FIELD_POLICY_FILE")
    before = set(mcp._tool_manager._tools)
    with pytest.raises(BridgeConfigError):
        build_bridge(runtime.config, runtime=runtime, verifier=lambda lg, k: 1)
    assert set(mcp._tool_manager._tools) == before


def test_config_defaults_for_policy_and_redirects(tmp_path):
    config = load_config(_env(tmp_path))
    assert config.policy_instance == "default"
    assert config.allowed_redirect_hosts == ("claude.ai", "claude.com")
    assert config.allow_localhost_redirects is False
    custom = load_config(
        _env(
            tmp_path,
            ODOO_MCP_BRIDGE_POLICY_INSTANCE="erp",
            ODOO_MCP_BRIDGE_ALLOWED_REDIRECT_HOSTS="Example.COM",
        )
    )
    assert custom.policy_instance == "erp"
    assert custom.allowed_redirect_hosts == ("example.com",)


# --------------------------------------------------------- profile redaction


def test_get_odoo_profile_hides_backend_details(runtime):
    def get_odoo_profile():
        return {
            "success": True,
            "profile": {
                "url": "https://backend.internal.example",
                "hostname": "backend.internal.example",
                "database": "proddb",
                "timeout": 30,
                "verify_ssl": False,
                "json2_database_header": True,
                "username": "a@example.com",
                "transport": "json2",
                "server_version": {"error": "GET https://backend.internal.example/web/version"},
                "installed_modules": [{"name": "sale"}],
            },
        }

    tool = _tool(get_odoo_profile, name="get_odoo_profile")
    wrap_tool(tool, runtime)
    tok = _as(_token(1, "a@example.com", "k"))
    try:
        out = tool.fn()
    finally:
        auth_context_var.reset(tok)
    raw = json.dumps(out)
    assert "backend.internal" not in raw and "proddb" not in raw
    profile = out["profile"]
    for key in ("url", "hostname", "database", "timeout", "verify_ssl", "json2_database_header"):
        assert profile[key] == "<redacted>"
    assert profile["server_version"] == {"error": "unavailable"}
    assert profile["username"] == "a@example.com" and profile["installed_modules"]


# ------------------------------------------------------- file permissions


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_state_dir_audit_and_clients_are_owner_only(runtime, tmp_path):
    state = tmp_path / "newstate"
    ensure_state_dir(str(state))
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    runtime.audit.path = str(tmp_path / "fresh-audit.jsonl")
    runtime.audit.check_writable()
    assert stat.S_IMODE(os.stat(runtime.audit.path).st_mode) == 0o600
    provider = _provider(tmp_path / "st2")
    client = TestClient(_app(provider), base_url=ISSUER)
    assert _register(client).status_code == 201
    assert stat.S_IMODE(os.stat(tmp_path / "st2" / "clients.json").st_mode) == 0o600


def test_audit_file_is_created_on_start(runtime, tmp_path):
    runtime.audit.path = str(tmp_path / "created.jsonl")
    runtime.audit.check_writable()
    assert os.path.exists(runtime.audit.path)


# ------------------------------------------------------------------ helpers


def _provider(state, odoo=None, now=None, **kw):
    options = dict(
        seal_key=SEAL,
        instance="staging",
        public_url=ISSUER,
        state_dir=state,
        verifier=odoo or Odoo(),
        allowed_redirect_hosts=("claude.example.com",),
        allow_localhost_redirects=True,
    )
    if now is not None:
        options["clock"] = lambda: now[0]
    options.update(kw)
    return BridgeOAuthProvider(**options)


def _app(provider, **throttle):
    routes = build_oauth_routes(
        provider,
        AnyHttpUrl(ISSUER),
        ClientRegistrationOptions(enabled=True),
        RevocationOptions(enabled=True),
    )
    middleware = [Middleware(IpThrottleMiddleware, **throttle)] if throttle else []
    return Starlette(routes=[*routes, *provider.routes()], middleware=middleware)


def _tokens(provider, client):
    client_id, verifier, done = _full_flow(client)
    code = parse_qs(urlparse(done.headers["location"]).query)["code"][0]
    return client_id, _exchange(client, client_id, verifier, code).json()


def _refresh(client, client_id, token):
    return client.post(
        "/token",
        data={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": token},
    )


# ------------------------------------------------------ token identity (jti)


def test_every_token_carries_a_random_jti(tmp_path):
    provider = _provider(tmp_path / "s")
    client = TestClient(_app(provider), base_url=ISSUER)
    _, body = _tokens(provider, client)
    access = unseal(SEAL, body["access_token"])
    refresh = unseal(SEAL, body["refresh_token"])
    assert len(access["jti"]) >= 22 and len(refresh["jti"]) >= 22
    assert access["jti"] != refresh["jti"]
    _, other = _tokens(provider, client)
    assert unseal(SEAL, other["access_token"])["jti"] != access["jti"]


def test_unseal_is_strict_about_encoding():
    token = seal(SEAL, {"uid": 1})
    assert unseal(SEAL, token) == {"uid": 1}
    assert unseal(SEAL, token + "=") is None
    assert unseal(SEAL, token + "==") is None
    assert unseal(SEAL, token[:-1] + "\n" + token[-1]) is None


def test_revoked_access_token_stays_revoked_with_padding(tmp_path):
    provider = _provider(tmp_path / "s")
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, body = _tokens(provider, client)
    token = body["access_token"]
    revoked = client.post("/revoke", data={"client_id": client_id, "token": token})
    assert revoked.status_code == 200  # a public client may omit client_secret
    assert _run(provider.load_access_token(token)) is None
    assert _run(provider.load_access_token(token + "=")) is None
    assert _run(provider.load_access_token(token + "==")) is None


def test_rotated_refresh_token_with_padding_is_refused(tmp_path):
    provider = _provider(tmp_path / "s")
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, body = _tokens(provider, client)
    assert _refresh(client, client_id, body["refresh_token"]).status_code == 200
    assert _refresh(client, client_id, body["refresh_token"]).status_code == 400
    assert _refresh(client, client_id, body["refresh_token"] + "=").status_code == 400


def test_concurrent_refresh_exactly_one_succeeds(tmp_path):
    started = threading.Barrier(2, timeout=5)

    def slow_verifier(login, key):
        time.sleep(0.15)
        return 7

    provider = _provider(tmp_path / "s", verifier=slow_verifier)
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, body = _tokens(provider, client)
    registered = _run(provider.get_client(client_id))
    loaded = _run(provider.load_refresh_token(registered, body["refresh_token"]))
    assert loaded is not None
    del started

    async def race():
        results = await asyncio.gather(
            provider.exchange_refresh_token(registered, loaded, []),
            provider.exchange_refresh_token(registered, loaded, []),
            return_exceptions=True,
        )
        return results

    results = asyncio.run(race())
    ok = [r for r in results if not isinstance(r, BaseException)]
    failed = [r for r in results if isinstance(r, TokenError)]
    assert len(ok) == 1 and len(failed) == 1


def test_failed_reverification_does_not_burn_the_refresh_token(tmp_path):
    odoo = Odoo()
    provider = _provider(tmp_path / "s", odoo=odoo)
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, body = _tokens(provider, client)
    saved = dict(odoo.users)
    odoo.users.clear()
    assert _refresh(client, client_id, body["refresh_token"]).status_code == 400
    odoo.users.update(saved)
    assert _refresh(client, client_id, body["refresh_token"]).status_code == 200


def test_full_deny_set_refuses_refresh_instead_of_forgetting(tmp_path, monkeypatch):
    provider = _provider(tmp_path / "s")
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id, body = _tokens(provider, client)
    monkeypatch.setattr("odoo_mcp.bridge.provider.MAX_DENIED", 1)
    assert provider._claim("someone-else", int(time.time()) + 1000) is True
    refused = _refresh(client, client_id, body["refresh_token"])
    assert refused.status_code == 400
    assert "someone-else" in provider._denied  # the earlier denial survived
    assert _run(provider.load_access_token(body["access_token"])) is not None


def test_expired_denials_are_reclaimed_when_full(tmp_path, monkeypatch):
    now = [1_800_000_000.0]
    provider = _provider(tmp_path / "s", now=now)
    monkeypatch.setattr("odoo_mcp.bridge.provider.MAX_DENIED", 2)
    assert provider._claim("a", now[0] + 10) is True
    assert provider._claim("b", now[0] + 1000) is True
    assert provider._claim("c", now[0] + 1000) is False
    now[0] += 11
    assert provider._claim("c", now[0] + 1000) is True
    assert set(provider._denied) == {"b", "c"}


def test_client_cache_is_keyed_on_jti(runtime):
    first = _token(1, "a@example.com", "k", raw="same-jti")
    second = first.model_copy(update={"token": first.token + "="})
    assert runtime.client_for(first) is runtime.client_for(second)
    other = first.model_copy(update={"jti": "different"})
    assert runtime.client_for(other) is not runtime.client_for(first)


# ----------------------------------------------------------- redirect hosts


def test_defaults_accept_only_exact_claude_hosts(tmp_path):
    provider = BridgeOAuthProvider(
        seal_key=SEAL,
        instance="staging",
        public_url=ISSUER,
        state_dir=tmp_path / "s",
        verifier=Odoo(),
    )
    client = TestClient(_app(provider), base_url=ISSUER)
    good = ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/cb"]
    for uri in good:
        assert _register(client, redirect=uri).status_code == 201, uri
    bad = [
        "https://evil.example.com/cb",
        "https://claude.ai.evil.example.com/cb",
        "https://evilclaude.ai/cb",
        "https://claude.ai@evil.example.com/cb",
        "http://claude.ai/cb",
        "http://localhost:3000/cb",
        "http://127.0.0.1/cb",
    ]
    for uri in bad:
        assert _register(client, redirect=uri).status_code == 400, uri


def test_localhost_only_under_the_explicit_flag(tmp_path):
    off = _provider(tmp_path / "off", allow_localhost_redirects=False)
    assert _register(
        TestClient(_app(off), base_url=ISSUER), redirect="http://localhost:3000/cb"
    ).status_code == 400
    on = _provider(tmp_path / "on", allow_localhost_redirects=True)
    assert _register(
        TestClient(_app(on), base_url=ISSUER), redirect="http://localhost:3000/cb"
    ).status_code == 201


def test_loading_clients_drops_non_conforming_redirects(tmp_path, caplog):
    state = tmp_path / "s"
    provider = _provider(state)
    client = TestClient(_app(provider), base_url=ISSUER)
    good = _register(client).json()["client_id"]
    path = state / "clients.json"
    entries = json.loads(path.read_text())
    evil = dict(entries[0], client_id="evil-client", redirect_uris=["https://evil.example.com/cb"])
    path.write_text(json.dumps([*entries, evil]))
    with caplog.at_level(logging.WARNING):
        restarted = _provider(state)
    assert _run(restarted.get_client(good)) is not None
    assert _run(restarted.get_client("evil-client")) is None
    assert any("evil-client" in r.getMessage() for r in caplog.records)
    # tightening the list later drops previously fine clients too
    tightened = _provider(state, allowed_redirect_hosts=("claude.ai",))
    assert _run(tightened.get_client(good)) is None


def test_authorize_rechecks_the_redirect(tmp_path):
    provider = _provider(tmp_path / "s")
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id = _register(client).json()["client_id"]
    registered = _run(provider.get_client(client_id))
    params = AuthorizationParams(
        state="s",
        scopes=None,
        code_challenge="c" * 43,
        redirect_uri=AnyHttpUrl("https://evil.example.com/cb"),
        redirect_uri_provided_explicitly=True,
    )
    with pytest.raises(AuthorizeError):
        _run(provider.authorize(registered, params))


# ---------------------------------------------------- registration + metadata


def test_registration_is_public_only_and_returns_no_secret(tmp_path):
    provider = _provider(tmp_path / "s")
    client = TestClient(_app(provider), base_url=ISSUER)
    for method in ("client_secret_post", "client_secret_basic", None):
        extra = {} if method is None else {"token_endpoint_auth_method": method}
        body = {
            "redirect_uris": [REDIRECT],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            **extra,
        }
        response = client.post("/register", json=body)
        assert response.status_code == 201, response.text
        data = response.json()
        assert data["token_endpoint_auth_method"] == "none"
        assert not data.get("client_secret")
    stored = _run(provider.get_client(data["client_id"]))
    assert stored.client_secret is None and stored.token_endpoint_auth_method == "none"


def test_malformed_registration_still_gets_a_clean_400(tmp_path):
    client = TestClient(_app(_provider(tmp_path / "s")), base_url=ISSUER)
    assert client.post("/register", content=b"not json").status_code == 400


def test_metadata_advertises_only_none(tmp_path):
    client = TestClient(_app(_provider(tmp_path / "s")), base_url=ISSUER)
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["token_endpoint_auth_methods_supported"] == ["none"]
    assert meta["revocation_endpoint_auth_methods_supported"] == ["none"]
    assert meta["code_challenge_methods_supported"] == ["S256"]


# ---------------------------------------------------------------- throttles


def test_register_authorize_and_token_are_throttled_per_ip(tmp_path):
    provider = _provider(tmp_path / "s")
    app = _app(
        provider,
        limits={"/register": 2, "/authorize": 2, "/token": 2},
        client_ip_header="X-Real-IP",
    )
    client = TestClient(app, base_url=ISSUER)
    ip_a, ip_b = {"X-Real-IP": "203.0.113.1"}, {"X-Real-IP": "203.0.113.2"}
    body = {
        "redirect_uris": [REDIRECT],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    }
    assert [client.post("/register", json=body, headers=ip_a).status_code for _ in range(3)] == [
        201,
        201,
        429,
    ]
    assert client.post("/register", json=body, headers=ip_b).status_code == 201  # own budget
    client_id = "fixed-client"
    provider._clients[client_id] = OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=[AnyHttpUrl(REDIRECT)],
        token_endpoint_auth_method="none",
    )
    _, challenge = _pkce()
    codes = []
    for _ in range(3):
        codes.append(
            client.get(
                "/authorize",
                params={
                    "client_id": client_id,
                    "redirect_uri": REDIRECT,
                    "response_type": "code",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
                headers=ip_a,
                follow_redirects=False,
            ).status_code
        )
    assert 429 not in codes[:2] and codes[2] == 429
    refresh = [
        client.post(
            "/token",
            data={"grant_type": "refresh_token", "client_id": client_id, "refresh_token": "x"},
            headers=ip_a,
        ).status_code
        for _ in range(3)
    ]
    assert refresh[:2] == [400, 400] and refresh[2] == 429


def test_client_table_full_refuses_new_registrations_without_evicting(tmp_path, monkeypatch):
    monkeypatch.setattr("odoo_mcp.bridge.provider.MAX_CLIENTS", 1)
    provider = _provider(tmp_path / "s")
    client = TestClient(_app(provider), base_url=ISSUER)
    first = _register(client).json()["client_id"]
    assert _register(client).status_code == 400
    assert _run(provider.get_client(first)) is not None


def test_pending_sign_ins_are_not_evicted_when_full(tmp_path, monkeypatch):
    monkeypatch.setattr("odoo_mcp.bridge.provider.MAX_PENDING", 1)
    provider = _provider(tmp_path / "s")
    client = TestClient(_app(provider), base_url=ISSUER)
    client_id = _register(client).json()["client_id"]
    _, challenge = _pkce()
    first = _authorize(client, client_id, challenge)
    assert first.status_code == 302 and "/signin?req=" in first.headers["location"]
    second = _authorize(client, client_id, challenge)
    assert second.status_code == 302
    assert "error=temporarily_unavailable" in second.headers["location"]
    page = client.get(first.headers["location"])  # the first one still works
    assert page.status_code == 200 and _signin_fields(page.text)["req"]
    done = client.post(
        "/signin",
        data={**_signin_fields(page.text), "login": "ann@example.com", "api_key": KEY},
        follow_redirects=False,
    )
    assert done.status_code == 302 and "code=" in done.headers["location"]
