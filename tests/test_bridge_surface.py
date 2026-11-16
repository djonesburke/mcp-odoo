"""Bridge surface: read-only by build, per-request identity, audit, throttling."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from starlette.testclient import TestClient

from odoo_mcp import server as srv
from odoo_mcp.bridge import surface
from odoo_mcp.bridge.app import build_bridge
from odoo_mcp.bridge.client import UserClientCache
from odoo_mcp.bridge.config import BridgeConfig
from odoo_mcp.bridge.provider import BridgeAccessToken
from odoo_mcp.bridge.runtime import (
    AuditLog,
    BridgeAuditError,
    BridgeIdentityError,
    BridgeRuntime,
    current_user,
)
from odoo_mcp.bridge.seal import generate_seal_key
from odoo_mcp.bridge.surface import (
    READ_ALLOWLIST,
    WRITE_DENYLIST,
    BridgeAppContext,
    SurfaceError,
    restrict_tool_surface,
    wrap_tool,
)
from odoo_mcp.server_core import _resolve_odoo, mcp

SECRET_A = "key-for-user-a-SECRET"
SECRET_B = "key-for-user-b-SECRET"


@pytest.fixture
def restore_global_mcp():
    """The bridge mutates the shared ``mcp`` singleton; put it back."""
    tm, rm, pm = mcp._tool_manager, mcp._resource_manager, mcp._prompt_manager
    tools = dict(tm._tools)
    fns = {name: tool.fn for name, tool in tools.items()}
    resources, templates, prompts = dict(rm._resources), dict(rm._templates), dict(pm._prompts)
    lifespan = mcp._lowlevel_server.lifespan
    auth, provider, verifier = mcp.settings.auth, mcp._auth_server_provider, mcp._token_verifier
    routes = list(mcp._custom_starlette_routes)
    seams = {
        n: getattr(srv, n)
        for n in (
            "get_odoo_client",
            "get_odoo_client_for",
            "resolve_default_instance_name",
            "resolve_instance_name",
            "load_instances_config",
        )
    }
    yield
    tm._tools.clear()
    tm._tools.update(tools)
    for name, fn in fns.items():
        tools[name].fn = fn
    rm._resources.clear()
    rm._resources.update(resources)
    rm._templates.clear()
    rm._templates.update(templates)
    pm._prompts.clear()
    pm._prompts.update(prompts)
    mcp._lowlevel_server.lifespan = lifespan
    mcp.settings.auth, mcp._auth_server_provider, mcp._token_verifier = auth, provider, verifier
    mcp._custom_starlette_routes[:] = routes
    for name, value in seams.items():
        setattr(srv, name, value)


class FakeOdoo:
    """Records which login/key it was built for and every call it received."""

    def __init__(self, login, key):
        self.login, self.key = login, key
        self.username, self.url, self.hostname, self.db = login, "u", "h", "d"
        self.calls = []

    def get_model_fields(self, model):
        return {
            "name": {"type": "char", "string": "Name"},
            "id": {"type": "integer", "string": "ID"},
        }

    def search_read(self, **kwargs):
        self.calls.append(("search_read", kwargs))
        return [{"id": i, "name": f"{self.login}-{i}"} for i in range(1, 4)]

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((method, kwargs))
        return []


def _config(tmp_path, **kw):
    seal_path = tmp_path / "seal.key"
    if not seal_path.exists():
        generate_seal_key(seal_path)
    values = dict(
        odoo_url="https://odoo.example.com",
        odoo_db="exampledb",
        instance="staging",
        public_url="http://localhost",
        seal_key_path=str(seal_path),
        state_dir=str(tmp_path / "state"),
        audit_log=str(tmp_path / "audit.jsonl"),
        host="127.0.0.1",
        port=8765,
    )
    values.update(kw)
    return BridgeConfig(**values)


def _token(uid, login, key, exp=None, raw=None):
    return BridgeAccessToken(
        token=raw or f"raw-token-{uid}",
        client_id="c",
        scopes=["odoo.read"],
        expires_at=exp or 4_000_000_000,
        uid=uid,
        login=login,
        odoo_key=key,
    )


def _as(token):
    return auth_context_var.set(AuthenticatedUser(token) if token else None)


@pytest.fixture
def runtime(tmp_path):
    built = []

    def factory(login, key):
        client = FakeOdoo(login, key)
        built.append(client)
        return client

    rt = BridgeRuntime(
        config=_config(tmp_path),
        audit=AuditLog(str(tmp_path / "audit.jsonl"), instance="staging"),
        client_factory=factory,
    )
    rt.built = built  # type: ignore[attr-defined]
    return rt


def _audit_lines(runtime):
    try:
        with open(runtime.audit.path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle]
    except FileNotFoundError:
        return []


# ------------------------------------------------------- tool surface (build)


def _fake_server(names):
    ann = SimpleNamespace(read_only_hint=True, destructive_hint=False)
    tools = {n: SimpleNamespace(name=n, annotations=ann, fn=lambda: None) for n in names}
    return SimpleNamespace(_tool_manager=SimpleNamespace(_tools=tools)), tools


def test_restriction_removes_everything_not_allowlisted():
    server, tools = _fake_server(set(READ_ALLOWLIST) | {"execute_approved_write", "extra"})
    assert restrict_tool_surface(server) == sorted(READ_ALLOWLIST)
    assert set(tools) == set(READ_ALLOWLIST)


def test_restriction_fails_when_an_allowlisted_tool_is_missing():
    # e.g. ODOO_MCP_TOOLS_INCLUDE narrowed the registry before the bridge ran
    names = set(READ_ALLOWLIST) - {"read_record"}
    server, _ = _fake_server(names)
    with pytest.raises(SurfaceError, match="differs from the allowlist"):
        restrict_tool_surface(server)


def test_restriction_fails_on_a_non_read_only_annotation():
    server, tools = _fake_server(READ_ALLOWLIST)
    tools["search_records"].annotations = SimpleNamespace(
        read_only_hint=False, destructive_hint=True
    )
    with pytest.raises(SurfaceError, match="not annotated read-only"):
        restrict_tool_surface(server)


def test_allowlist_and_denylist_are_disjoint_and_cover_all_known_tools():
    assert not READ_ALLOWLIST & WRITE_DENYLIST
    assert {
        "execute_approved_write",
        "preview_write",
        "validate_write",
        "chatter_post",
        "execute_method",
        "generate_json2_payload",
        "submit_async_task",
        "cancel_async_task",
        "index_knowledge",
    } <= WRITE_DENYLIST
    registered = set(mcp._tool_manager._tools)
    # a new upstream tool must be classified on purpose, not exposed by default
    assert registered <= READ_ALLOWLIST | WRITE_DENYLIST | {"lookup_model_history",
        "analyze_upgrade_log", "diagnose_odoo_call", "fit_gap_report",
        "upgrade_risk_report", "business_pack_report"}


def test_real_surface_is_exactly_the_allowlist(tmp_path, runtime, restore_global_mcp):
    build = build_bridge(
        runtime.config,
        runtime=runtime,
        verifier=lambda login, key: 1,
    )
    try:
        names = set(mcp._tool_manager._tools)
        assert names == set(READ_ALLOWLIST) == set(build.tools)
        assert not names & WRITE_DENYLIST
        assert not mcp._resource_manager._resources
        assert not mcp._resource_manager._templates
        assert not mcp._prompt_manager._prompts
    finally:
        build.undo()


def test_env_cannot_widen_the_surface(tmp_path, runtime, restore_global_mcp, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_TOOLS_INCLUDE", "*")
    from odoo_mcp.bridge import cli

    env = {
        "ODOO_URL": "https://odoo.example.com",
        "ODOO_DB": "d",
        "ODOO_MCP_BRIDGE_INSTANCE": "staging",
        "ODOO_MCP_BRIDGE_PUBLIC_URL": "https://bridge.example.com",
        "ODOO_MCP_BRIDGE_SEAL_KEY_FILE": runtime.config.seal_key_path,
        "ODOO_MCP_BRIDGE_STATE_DIR": runtime.config.state_dir,
        "ODOO_MCP_BRIDGE_AUDIT_LOG": runtime.config.audit_log,
        "ODOO_MCP_TOOLS_INCLUDE": "*",
    }
    assert cli.main([], env=env) != 0


# ------------------------------------------------------ per-request identity


def test_no_user_refuses_and_never_falls_back_to_env(runtime, monkeypatch):
    monkeypatch.setenv("ODOO_URL", "https://other.example.com")
    monkeypatch.setenv("ODOO_API_KEY", "service-key")
    ctx = BridgeAppContext(runtime)
    with pytest.raises(BridgeIdentityError):
        ctx.odoo
    with pytest.raises(BridgeIdentityError):
        ctx.get_client(None)
    with pytest.raises(BridgeIdentityError):
        current_user()
    assert runtime.built == []


def test_two_users_never_share_a_client(runtime, restore_global_mcp):
    ctx = BridgeAppContext(runtime)
    fake_ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=ctx))
    undo = surface.install_seams(runtime)
    try:
        tok_a = _as(_token(1, "a@example.com", SECRET_A, raw="tok-a"))
        name_a, client_a = _resolve_odoo(fake_ctx, None)
        auth_context_var.reset(tok_a)

        tok_b = _as(_token(2, "b@example.com", SECRET_B, raw="tok-b"))
        name_b, client_b = _resolve_odoo(fake_ctx, None)
        # the module-level seam used by resources/legacy paths is per user too
        assert srv.get_odoo_client() is client_b
        auth_context_var.reset(tok_b)

        tok_a = _as(_token(1, "a@example.com", SECRET_A, raw="tok-a"))
        _, client_a_again = _resolve_odoo(fake_ctx, None)
        assert srv.get_odoo_client() is client_a
        auth_context_var.reset(tok_a)
    finally:
        undo()
    assert name_a == name_b == "staging"
    assert client_a is not client_b
    assert (client_a.login, client_a.key) == ("a@example.com", SECRET_A)
    assert (client_b.login, client_b.key) == ("b@example.com", SECRET_B)
    assert client_a_again is client_a  # cached per token
    assert ctx._odoo is None  # nothing cached on the shared context
    assert len(runtime.built) == 2


def test_one_instance_only(runtime):
    ctx = BridgeAppContext(runtime)
    tok = _as(_token(1, "a@example.com", SECRET_A))
    try:
        assert ctx.get_client("staging")[0] == "staging"
        with pytest.raises(ValueError, match="one instance only"):
            ctx.get_client("production")
    finally:
        auth_context_var.reset(tok)


def test_schema_cache_is_per_user(runtime):
    ctx = BridgeAppContext(runtime)
    tok = _as(_token(1, "a@example.com", SECRET_A))
    ctx.schema_cache["k"] = {"field_only_a_can_see": 1}
    auth_context_var.reset(tok)
    tok = _as(_token(2, "b@example.com", SECRET_B))
    try:
        assert "k" not in ctx.schema_cache
    finally:
        auth_context_var.reset(tok)


def test_client_cache_ttl_never_exceeds_token_expiry(runtime):
    now = [100.0]
    runtime.clients = UserClientCache(clock=lambda: now[0])
    token = _token(1, "a@example.com", SECRET_A, exp=150)
    first = runtime.client_for(token)
    assert runtime.client_for(token) is first
    now[0] = 151.0
    assert runtime.client_for(token) is not first


# ----------------------------------------------------- wrapper: audit + limits


def _tool(fn, name="search_records"):
    return SimpleNamespace(name=name, fn=fn)


def test_wrapper_audits_without_values_or_secrets(runtime):
    def search_records(model, fields=None, limit=10, domain=None):
        return {"success": True, "count": 3, "result": [{"name": "SENSITIVE-VALUE"}] * 3}

    tool = _tool(search_records)
    wrap_tool(tool, runtime)
    tok = _as(_token(4, "a@example.com", SECRET_A))
    try:
        out = tool.fn(
            model="res.partner",
            fields=["name", "email"],
            domain=[["name", "=", "SENSITIVE-DOMAIN-VALUE"]],
        )
    finally:
        auth_context_var.reset(tok)
    assert out["count"] == 3
    (line,) = _audit_lines(runtime)
    assert set(line) == {
        "ts", "instance", "uid", "login", "tool", "model", "fields",
        "records", "duration_ms", "outcome",
    }  # fmt: skip
    assert line["instance"] == "staging" and line["uid"] == 4
    assert line["login"] == "a@example.com" and line["tool"] == "search_records"
    assert line["model"] == "res.partner" and line["fields"] == ["name", "email"]
    assert line["records"] == 3 and line["outcome"] == "ok"
    assert isinstance(line["duration_ms"], int)
    raw = open(runtime.audit.path, encoding="utf-8").read()
    for forbidden in ("SENSITIVE", SECRET_A, "raw-token"):
        assert forbidden not in raw


def test_wrapper_refuses_without_user_and_audits_it(runtime):
    tool = _tool(lambda model: {"success": True})
    wrap_tool(tool, runtime)
    out = tool.fn(model="res.partner")
    assert out["success"] is False and "authentication required" in out["error"]
    (line,) = _audit_lines(runtime)
    assert line["uid"] is None and line["outcome"] == "unauthenticated"


def test_wrapper_error_outcome_and_exception_outcome(runtime):
    calls = {"n": 0}

    def flaky(model):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"success": False, "error": "nope"}
        raise RuntimeError("boom")

    tool = _tool(flaky)
    wrap_tool(tool, runtime)
    tok = _as(_token(1, "a@example.com", SECRET_A))
    try:
        assert tool.fn(model="m")["success"] is False
        with pytest.raises(RuntimeError):
            tool.fn(model="m")
    finally:
        auth_context_var.reset(tok)
    assert [x["outcome"] for x in _audit_lines(runtime)] == ["error", "exception:RuntimeError"]


def test_audit_failure_withholds_the_result(runtime, tmp_path):
    runtime.audit.path = str(tmp_path / "missing-dir" / "audit.jsonl")
    tool = _tool(lambda model: {"success": True, "result": ["data"]})
    wrap_tool(tool, runtime)
    tok = _as(_token(1, "a@example.com", SECRET_A))
    try:
        with pytest.raises(BridgeAuditError):
            tool.fn(model="m")
    finally:
        auth_context_var.reset(tok)


def test_per_user_rate_limit(runtime):
    runtime.limiter.max_calls = 3
    runtime.config = _config_with(runtime.config, calls_per_minute=3)
    tool = _tool(lambda model: {"success": True})
    wrap_tool(tool, runtime)
    results = {}
    for uid in (1, 2):
        tok = _as(_token(uid, f"u{uid}@example.com", "k"))
        try:
            results[uid] = [tool.fn(model="m").get("rate_limited", False) for _ in range(5)]
        finally:
            auth_context_var.reset(tok)
    assert results[1] == [False, False, False, True, True]
    assert results[2] == [False, False, False, True, True]  # separate budget
    assert any(x["outcome"] == "rate_limited" for x in _audit_lines(runtime))


def _config_with(config, **kw):
    from dataclasses import replace

    return replace(config, **kw)


def test_default_rate_limit_is_60_per_minute(runtime):
    assert runtime.limiter.max_calls == 60 and runtime.limiter.window_seconds == 60


def test_record_limit_is_capped_including_defaults(runtime):
    seen = []

    def search_records(model, limit=10):
        seen.append(limit)
        return {"success": True}

    def big_default(model, limit=5000):
        seen.append(limit)
        return {"success": True}

    for fn in (search_records, big_default):
        tool = _tool(fn)
        wrap_tool(tool, runtime)
        tok = _as(_token(1, "a@example.com", "k"))
        try:
            tool.fn(model="m", limit=100000)
            tool.fn(model="m", limit=50)
            tool.fn(model="m")
        finally:
            auth_context_var.reset(tok)
    assert seen == [200, 50, 10, 200, 50, 200]


def test_wrap_is_idempotent(runtime):
    tool = _tool(lambda model: {"success": True})
    wrap_tool(tool, runtime)
    wrap_tool(tool, runtime)
    tok = _as(_token(1, "a@example.com", "k"))
    try:
        tool.fn(model="m")
    finally:
        auth_context_var.reset(tok)
    assert len(_audit_lines(runtime)) == 1


# ------------------------------------------------------------- end to end


def _post(client, token, body):
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = client.post("/mcp", headers=headers, json=body)
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        data = [ln[6:] for ln in response.text.splitlines() if ln.startswith("data: ")]
        return response.status_code, json.loads(data[-1])
    try:
        return response.status_code, response.json()
    except ValueError:
        return response.status_code, response.text


def _call(client, token, name, arguments, rid=1):
    return _post(
        client,
        token,
        {
            "jsonrpc": "2.0",
            "id": rid,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )


def test_end_to_end_http_two_users(runtime, restore_global_mcp):
    runtime.config = _config_with(runtime.config, max_limit=20)
    build = build_bridge(runtime.config, runtime=runtime, verifier=lambda login, key: 1)
    try:
        tokens = {}
        for uid, login, key in ((11, "a@example.com", SECRET_A), (12, "b@example.com", SECRET_B)):
            issued = build.provider._issue("c", uid, login, key, ["odoo.read"])
            tokens[login] = issued.access_token
        with TestClient(build.app, base_url="http://localhost") as http:
            status, _ = _post(http, None, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
            assert status == 401  # no token, no access

            status, listing = _post(
                http, tokens["a@example.com"], {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )
            assert status == 200
            assert {t["name"] for t in listing["result"]["tools"]} == set(READ_ALLOWLIST)

            # a write tool is simply not there
            _, refused = _call(http, tokens["a@example.com"], "execute_method", {})
            assert "error" in refused or refused["result"].get("isError")

            for login in ("a@example.com", "b@example.com"):
                _, body = _call(
                    http,
                    tokens[login],
                    "search_records",
                    {"model": "res.partner", "fields": ["name"], "limit": 100000},
                )
                rows = body["result"]["structuredContent"]["result"]
                assert [r["name"] for r in rows][0] == f"{login}-1"

            _, health = _call(http, tokens["b@example.com"], "health_check", {})
            payload = json.loads(health["result"]["content"][0]["text"])
            assert payload["instance"] == "staging"
            assert payload["signed_in"] == {"uid": 12, "login": "b@example.com"}
            assert "SECRET" not in json.dumps(payload)
    finally:
        build.undo()

    by_login = {c.login: c for c in runtime.built}
    assert by_login["a@example.com"].key == SECRET_A
    assert by_login["b@example.com"].key == SECRET_B
    for client in runtime.built:
        searches = [kw for m, kw in client.calls if m == "search_read"]
        assert searches and all(kw["limit"] == 20 for kw in searches)  # capped
    lines = _audit_lines(runtime)
    assert {(x["uid"], x["tool"]) for x in lines} >= {
        (11, "search_records"),
        (12, "search_records"),
        (12, "health_check"),
    }
    raw = open(runtime.audit.path, encoding="utf-8").read()
    assert SECRET_A not in raw and SECRET_B not in raw


def test_expired_and_foreign_tokens_get_401(runtime, restore_global_mcp):
    build = build_bridge(runtime.config, runtime=runtime, verifier=lambda login, key: 1)
    try:
        from odoo_mcp.bridge.seal import seal

        foreign = seal(bytes(32), {"v": 1, "typ": "access"})
        with TestClient(build.app, base_url="http://localhost") as http:
            status, _ = _post(
                http, foreign, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            )
        assert status == 401
    finally:
        build.undo()
