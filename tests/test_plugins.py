"""Plugin loading, isolation, and tool filtering."""

import asyncio
from types import SimpleNamespace

import pytest

from odoo_mcp import plugin_api, server, server_core


def _tools():
    return {t.name for t in asyncio.run(server.mcp.list_tools())}


def _fake_entry_points(monkeypatch, mapping):
    """mapping: name -> register callable (or loader raising)."""

    entries = []
    for name, register in mapping.items():
        entries.append(SimpleNamespace(name=name, load=lambda r=register: r))

    def fake_entry_points(*, group):
        assert group == "odoo_mcp.tools"
        return entries

    import importlib.metadata as md

    monkeypatch.setattr(md, "entry_points", fake_entry_points)


def test_no_env_means_no_plugin_load(monkeypatch):
    monkeypatch.delenv("ODOO_MCP_PLUGINS", raising=False)
    server_core.load_plugins(plugin_api)
    posture = server_core.plugin_posture()
    assert posture["enabled"] == []
    assert posture["loaded"] == []
    assert posture["failed"] == {}


def test_plugin_registers_tool_and_survives_failures(monkeypatch):
    def good(api):
        from typing import Any, Dict

        @api.tool(description="demo plugin tool", structured_output=True)
        def plugin_demo_tool() -> Dict[str, Any]:
            return {"success": True, "tool": "plugin_demo_tool"}

    def bad(api):
        raise RuntimeError("kaboom")

    _fake_entry_points(monkeypatch, {"good": good, "bad": bad})
    monkeypatch.setenv("ODOO_MCP_PLUGINS", "good, bad, ghost")
    try:
        server_core.load_plugins(plugin_api)
        posture = server_core.plugin_posture()
        assert posture["loaded"] == ["good"]
        assert "RuntimeError: kaboom" in posture["failed"]["bad"]
        assert "ghost" in posture["failed"]
        assert "plugin_demo_tool" in _tools()
    finally:
        server.mcp._tool_manager._tools.pop("plugin_demo_tool", None)
        monkeypatch.delenv("ODOO_MCP_PLUGINS", raising=False)
        server_core.load_plugins(plugin_api)


def test_tool_filter_include_exclude(monkeypatch):
    registry = server.mcp._tool_manager._tools
    before = dict(registry)
    try:
        monkeypatch.setenv(
            "ODOO_MCP_TOOLS_INCLUDE", "search_records,read_record,health_check"
        )
        monkeypatch.setenv("ODOO_MCP_TOOLS_EXCLUDE", "read_*")
        server_core.apply_tool_filter()
        names = _tools()
        assert names == {"search_records", "health_check"}
        filtered = server_core.plugin_posture()["tools_filtered"]
        assert "aggregate_records" in filtered and "read_record" in filtered
    finally:
        registry.clear()
        registry.update(before)
        monkeypatch.delenv("ODOO_MCP_TOOLS_INCLUDE", raising=False)
        monkeypatch.delenv("ODOO_MCP_TOOLS_EXCLUDE", raising=False)
        server_core.apply_tool_filter()


def test_filter_noop_without_env(monkeypatch):
    monkeypatch.delenv("ODOO_MCP_TOOLS_INCLUDE", raising=False)
    monkeypatch.delenv("ODOO_MCP_TOOLS_EXCLUDE", raising=False)
    count_before = len(_tools())
    server_core.apply_tool_filter()
    assert len(_tools()) == count_before
    assert server_core.plugin_posture()["tools_filtered"] == []


# ----- fail-closed on an unexpected SDK registry shape ---------------------


@pytest.mark.parametrize(
    "shape", [None, [], "not-a-dict"], ids=["missing", "list", "str"]
)
def test_filter_raises_when_registry_shape_is_unexpected(monkeypatch, shape):
    """A requested filter that cannot be applied must not pass silently.

    apply_tool_filter reaches into the private mcp._tool_manager._tools. If the
    SDK renames it, the old code returned quietly and the operator kept every
    tool they asked to remove — failing open, with no signal. It now raises.
    """
    monkeypatch.setenv("ODOO_MCP_TOOLS_INCLUDE", "health_check")
    monkeypatch.setattr(
        server_core.mcp, "_tool_manager", SimpleNamespace(_tools=shape), raising=False
    )

    with pytest.raises(RuntimeError, match="not the expected mapping"):
        server_core.apply_tool_filter()


def test_filter_raises_for_exclude_only_requests(monkeypatch):
    """EXCLUDE alone is a filter request too — it must fail closed as well."""
    monkeypatch.delenv("ODOO_MCP_TOOLS_INCLUDE", raising=False)
    monkeypatch.setenv("ODOO_MCP_TOOLS_EXCLUDE", "unlink_*")
    monkeypatch.setattr(
        server_core.mcp, "_tool_manager", SimpleNamespace(_tools=None), raising=False
    )

    with pytest.raises(RuntimeError):
        server_core.apply_tool_filter()


def test_unexpected_shape_is_tolerated_when_no_filter_requested(monkeypatch):
    """The raise is reachable only when filtering was explicitly asked for.

    With neither env var set the function short-circuits before touching the
    registry, so a future SDK rename cannot break a default deployment.
    """
    monkeypatch.delenv("ODOO_MCP_TOOLS_INCLUDE", raising=False)
    monkeypatch.delenv("ODOO_MCP_TOOLS_EXCLUDE", raising=False)
    monkeypatch.setattr(
        server_core.mcp, "_tool_manager", SimpleNamespace(_tools=None), raising=False
    )

    server_core.apply_tool_filter()  # must not raise

    assert server_core.plugin_posture()["tools_filtered"] == []


def test_health_check_still_reports_tools_filtered(monkeypatch):
    """The audit readout survives the patch — it is what makes the control checkable."""
    from odoo_mcp.tools_read import health_check

    registry = server.mcp._tool_manager._tools
    before = dict(registry)
    try:
        monkeypatch.setenv("ODOO_MCP_TOOLS_INCLUDE", "search_records,health_check")
        server_core.apply_tool_filter()

        filtered = health_check()["plugins"]["tools_filtered"]
        assert "read_record" in filtered
        assert "search_records" not in filtered
    finally:
        registry.clear()
        registry.update(before)
        monkeypatch.delenv("ODOO_MCP_TOOLS_INCLUDE", raising=False)
        server_core.apply_tool_filter()


def test_health_check_reports_plugin_posture():
    from odoo_mcp.tools_read import health_check

    report = health_check()
    assert report["plugins"] == server_core.plugin_posture()


def test_plugin_api_surface_is_stable():
    from odoo_mcp import plugin_api

    assert plugin_api.PLUGIN_API_VERSION == 1
    for member in (
        "tool",
        "resolve_odoo",
        "redact_records",
        "error_envelope",
        "validate_model_name",
        "clamp_limit",
        "READ_ONLY_TOOL",
        "PREVIEW_TOOL",
    ):
        assert hasattr(plugin_api, member), member
