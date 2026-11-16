"""Bridge: sealing, startup refusals, the read-only client guard, client cache."""

from __future__ import annotations

import os
import stat
import time

import pytest

from odoo_mcp.bridge import cli
from odoo_mcp.bridge.client import (
    BRIDGE_RPC_METHODS,
    BridgeAuthError,
    BridgeMethodRefused,
    BridgeOdooClient,
    BridgeUnavailableError,
    UserClientCache,
    verify_odoo_login,
)
from odoo_mcp.bridge.config import (
    TESTED_MCP_VERSION,
    BridgeConfigError,
    check_sdk_version,
    load_config,
)
from odoo_mcp.bridge.seal import (
    SEAL_KEY_BYTES,
    SealKeyError,
    generate_seal_key,
    load_seal_key,
    seal,
    unseal,
)
from odoo_mcp.diagnostics import READ_ONLY_METHODS
from odoo_mcp.odoo_client import OdooJson2Error

KEY = bytes(range(32))


def _env(tmp_path, **extra):
    key_path = tmp_path / "seal.key"
    if not key_path.exists():
        generate_seal_key(key_path)
    env = {
        "ODOO_URL": "https://odoo.example.com",
        "ODOO_DB": "exampledb",
        "ODOO_MCP_BRIDGE_INSTANCE": "staging",
        "ODOO_MCP_BRIDGE_PUBLIC_URL": "https://bridge.example.com",
        "ODOO_MCP_BRIDGE_SEAL_KEY_FILE": str(key_path),
        "ODOO_MCP_BRIDGE_STATE_DIR": str(tmp_path / "state"),
        "ODOO_MCP_BRIDGE_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
    }
    env.update(extra)
    return env


# ------------------------------------------------------------------ sealing


def test_seal_round_trip():
    payload = {"v": 1, "typ": "access", "uid": 5, "login": "a@example.com"}
    assert unseal(KEY, seal(KEY, payload)) == payload


def test_seal_is_randomised_and_hides_content():
    a, b = seal(KEY, {"key": "SECRET-API-KEY"}), seal(KEY, {"key": "SECRET-API-KEY"})
    assert a != b
    assert "SECRET" not in a


def test_unseal_rejects_tampering():
    token = seal(KEY, {"uid": 1})
    flipped = token[:-3] + ("AAA" if not token.endswith("AAA") else "BBB")
    assert unseal(KEY, flipped) is None
    assert unseal(KEY, token[:-1]) is None
    assert unseal(KEY, "garbage") is None
    assert unseal(KEY, "obt1.") is None


def test_unseal_rejects_wrong_key():
    token = seal(KEY, {"uid": 1})
    assert unseal(bytes(32), token) is None


def test_generate_and_load_seal_key(tmp_path):
    path = tmp_path / "k"
    generate_seal_key(path)
    assert len(load_seal_key(path)) == SEAL_KEY_BYTES
    with pytest.raises(FileExistsError):
        generate_seal_key(path)  # never overwrite
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_seal_key_missing_or_wrong_length(tmp_path):
    with pytest.raises(SealKeyError):
        load_seal_key(tmp_path / "nope")
    short = tmp_path / "short"
    short.write_bytes(b"x" * 16)
    if os.name == "posix":
        os.chmod(short, 0o600)  # isolate the length check from the mode check
    with pytest.raises(SealKeyError, match="32 bytes"):
        load_seal_key(short)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_seal_key_group_readable_refused(tmp_path):
    path = tmp_path / "k"
    generate_seal_key(path)
    path.chmod(0o640)
    with pytest.raises(SealKeyError, match="chmod 600"):
        load_seal_key(path)


# ----------------------------------------------------------------- startup


def test_valid_environment_loads(tmp_path):
    config = load_config(_env(tmp_path))
    assert config.instance == "staging"
    assert config.calls_per_minute == 60 and config.max_limit == 200


@pytest.mark.parametrize(
    "extra",
    [
        {"ODOO_PASSWORD": "x"},
        {"ODOO_API_KEY": "x"},
        {"ODOO_USERNAME": "svc@example.com"},
        {"ODOO_MCP_TOOLS_INCLUDE": "*"},
        {"ODOO_MCP_TOOLS_EXCLUDE": "search_*"},
        {"ODOO_MCP_PLUGINS": "evil"},
        {"ODOO_MCP_ENABLE_WRITES": "1"},
        {"ODOO_CONFIG_FILE": "/etc/odoo.json"},
        {"ODOO_URL": "https://a.example.com,https://b.example.com"},
        {"ODOO_MCP_BRIDGE_INSTANCE": "dev"},
        {"ODOO_MCP_BRIDGE_PUBLIC_URL": "http://bridge.example.com"},
    ],
)
def test_startup_refuses(tmp_path, capsys, extra):
    env = _env(tmp_path, **extra)
    with pytest.raises(BridgeConfigError):
        load_config(env)
    assert cli.main([], env=env) != 0
    err = capsys.readouterr().err
    assert "refusing to start" in err


def test_startup_refusal_never_prints_the_credential(tmp_path, capsys):
    env = _env(tmp_path, ODOO_API_KEY="TOPSECRETVALUE")
    assert cli.main([], env=env) == 2
    assert "TOPSECRETVALUE" not in capsys.readouterr().err


def test_startup_refuses_missing_required(tmp_path):
    env = _env(tmp_path)
    del env["ODOO_MCP_BRIDGE_AUDIT_LOG"]
    with pytest.raises(BridgeConfigError, match="AUDIT_LOG"):
        load_config(env)


def test_startup_refuses_missing_or_loose_seal_key(tmp_path, capsys, monkeypatch):
    _pretend_tested_sdk(monkeypatch)
    env = _env(tmp_path)
    env["ODOO_MCP_BRIDGE_SEAL_KEY_FILE"] = str(tmp_path / "absent")
    assert cli.main([], env=env) != 0
    assert "seal key" in capsys.readouterr().err
    bad = tmp_path / "short"
    bad.write_bytes(b"x")
    env["ODOO_MCP_BRIDGE_SEAL_KEY_FILE"] = str(bad)
    assert cli.main([], env=env) != 0


def test_cli_generates_seal_key(tmp_path):
    target = tmp_path / "gen.key"
    assert cli.main(["--generate-seal-key", str(target)]) == 0
    assert len(target.read_bytes()) == SEAL_KEY_BYTES
    assert cli.main(["--generate-seal-key", str(target)]) != 0  # exists


# ------------------------------------------------------------ client guard


@pytest.fixture
def guarded(monkeypatch):
    calls = []

    def fake_json2(self, model, method, payload):
        calls.append((model, method))
        return {"uid": 3} if method == "context_get" else []

    monkeypatch.setattr(
        "odoo_mcp.odoo_client.OdooClient._json2_call", fake_json2, raising=True
    )
    client = BridgeOdooClient(
        url="https://odoo.example.com",
        db="d",
        username="u@example.com",
        password="",
        transport="json2",
        api_key="k",
    )
    return client, calls


def test_guard_allows_read_methods(guarded):
    client, calls = guarded
    for method in sorted(BRIDGE_RPC_METHODS):
        client.execute_method("res.partner", method)
    assert {m for _, m in calls} >= READ_ONLY_METHODS


@pytest.mark.parametrize(
    "method", ["write", "create", "unlink", "copy", "action_confirm", "message_post", "init"]
)
def test_guard_refuses_write_methods_before_any_network_call(guarded, method):
    client, calls = guarded
    before = len(calls)
    with pytest.raises(BridgeMethodRefused):
        client.execute_method("res.partner", method, [1], {"name": "x"})
    with pytest.raises(BridgeMethodRefused):
        client._execute_once("res.partner", method, (), {})
    with pytest.raises(BridgeMethodRefused):
        client._json2_call("res.partner", method, {})
    assert len(calls) == before


def test_bridge_set_is_read_only_plus_aggregation_only():
    assert BRIDGE_RPC_METHODS - READ_ONLY_METHODS == {"read_group", "formatted_read_group"}


# ------------------------------------------------------------ login verify


def _patch_login(monkeypatch, *, uid=9, owner="Ann@Example.com", fail=False):
    def fake(self, model, method, payload):
        if fail:
            raise ConnectionError("blocked")
        if method == "context_get":
            return {"lang": "en_US", "uid": uid}
        if method == "read":
            return [{"id": uid, "login": owner}]
        raise AssertionError(method)

    monkeypatch.setattr("odoo_mcp.odoo_client.OdooClient._json2_call", fake)


def test_verify_login_accepts_matching_owner_case_insensitive(monkeypatch):
    _patch_login(monkeypatch)
    uid = verify_odoo_login(
        url="https://odoo.example.com", db="d", login="ann@example.com", key="k"
    )
    assert uid == 9


def test_verify_login_rejects_mismatched_login(monkeypatch):
    _patch_login(monkeypatch)
    with pytest.raises(BridgeAuthError):
        verify_odoo_login(
            url="https://odoo.example.com", db="d", login="bob@example.com", key="k"
        )


def test_verify_login_failure_is_generic(monkeypatch):
    _patch_login(monkeypatch, fail=True)
    with pytest.raises(BridgeUnavailableError) as info:
        verify_odoo_login(
            url="https://odoo.example.com", db="d", login="ann@example.com", key="SECRETKEY"
        )
    assert "SECRETKEY" not in str(info.value) and "blocked" not in str(info.value)


@pytest.mark.parametrize(
    "error, expected",
    [
        (ConnectionError("down"), BridgeUnavailableError),
        (TimeoutError("slow"), BridgeUnavailableError),
        (OSError("reset"), BridgeUnavailableError),
        (OdooJson2Error("boom", status_code=502), BridgeUnavailableError),
        (OdooJson2Error("boom", status_code=503), BridgeUnavailableError),
        (OdooJson2Error("slow down", status_code=429), BridgeUnavailableError),
        (OdooJson2Error("bad key", status_code=401), BridgeAuthError),
        (OdooJson2Error("denied", status_code=403), BridgeAuthError),
        (ValueError("anything else"), BridgeAuthError),
    ],
)
def test_verify_login_separates_unreachable_from_bad_credentials(monkeypatch, error, expected):
    def fake(self, model, method, payload):
        raise error

    monkeypatch.setattr("odoo_mcp.odoo_client.OdooClient._json2_call", fake)
    with pytest.raises(expected) as info:
        verify_odoo_login(url="https://odoo.example.com", db="d", login="a@example.com", key="k")
    assert type(info.value) is expected


def _pretend_tested_sdk(monkeypatch):
    """Report the tested mcp version so a check after the SDK guard is reachable
    whatever SDK the test environment happens to install (CI resolves mcp>=2,<3)."""
    import importlib.metadata as md

    real = md.version
    monkeypatch.setattr(
        "importlib.metadata.version",
        lambda name: TESTED_MCP_VERSION if name == "mcp" else real(name),
    )


def test_sdk_version_check_names_both_versions():
    check_sdk_version(TESTED_MCP_VERSION)
    with pytest.raises(BridgeConfigError) as info:
        check_sdk_version("2.1.0")
    assert "2.1.0" in str(info.value) and TESTED_MCP_VERSION in str(info.value)
    with pytest.raises(BridgeConfigError):
        check_sdk_version("not installed")


def test_cli_refuses_an_untested_sdk(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("importlib.metadata.version", lambda name: "9.9.9")
    assert cli.main([], env=_env(tmp_path)) == 2
    err = capsys.readouterr().err
    assert "9.9.9" in err and TESTED_MCP_VERSION in err


def test_trusted_proxies_config(tmp_path):
    assert load_config(_env(tmp_path)).trusted_proxies == ("127.0.0.0/8", "::1/128")
    config = load_config(_env(tmp_path, ODOO_MCP_BRIDGE_TRUSTED_PROXIES="10.0.0.0/8, 192.0.2.7"))
    assert config.trusted_proxies == ("10.0.0.0/8", "192.0.2.7")
    with pytest.raises(BridgeConfigError, match="TRUSTED_PROXIES"):
        load_config(_env(tmp_path, ODOO_MCP_BRIDGE_TRUSTED_PROXIES="not-an-ip"))


def test_verify_login_uses_json2_only(monkeypatch):
    # Sign-in must never open the XML-RPC transport (blocked at the CDN).
    def boom(*a, **k):
        raise AssertionError("xmlrpc must not be used")

    monkeypatch.setattr("odoo_mcp.odoo_client.OdooClient._connect_xmlrpc", boom)
    _patch_login(monkeypatch)
    assert verify_odoo_login(
        url="https://odoo.example.com", db="d", login="ann@example.com", key="k"
    )


# ---------------------------------------------------------------- the cache


def test_client_cache_is_per_token_and_expires():
    now = [1000.0]
    cache = UserClientCache(max_entries=2, clock=lambda: now[0])
    built = []

    def factory_for(name):
        def factory():
            built.append(name)
            return object()

        return factory

    a1 = cache.get_or_build("tokA", 1100, factory_for("a"))
    assert cache.get_or_build("tokA", 1100, factory_for("a")) is a1
    b1 = cache.get_or_build("tokB", 1100, factory_for("b"))
    assert b1 is not a1
    now[0] = 1200.0  # past both expiries
    assert cache.get_or_build("tokA", 1300, factory_for("a2")) is not a1
    assert built == ["a", "b", "a2"]


def test_client_cache_is_bounded():
    cache = UserClientCache(max_entries=2, clock=time.time)
    for i in range(5):
        cache.get_or_build(f"t{i}", time.time() + 100, object)
    assert len(cache) == 2


def test_allowed_logins_parsed_casefolded(tmp_path):
    from odoo_mcp.bridge.config import load_config

    env = _env(tmp_path)
    env["ODOO_MCP_BRIDGE_ALLOWED_LOGINS"] = " Ann@Example.com , bob@example.com ,"
    cfg = load_config(env)
    assert cfg.allowed_logins == frozenset({"ann@example.com", "bob@example.com"})


def test_allowed_logins_unset_is_none(tmp_path):
    from odoo_mcp.bridge.config import load_config

    assert load_config(_env(tmp_path)).allowed_logins is None


def test_allowed_logins_only_commas_refused(tmp_path):
    from odoo_mcp.bridge.config import BridgeConfigError, load_config

    env = _env(tmp_path)
    env["ODOO_MCP_BRIDGE_ALLOWED_LOGINS"] = " , ,"
    with pytest.raises(BridgeConfigError, match="names no login"):
        load_config(env)
