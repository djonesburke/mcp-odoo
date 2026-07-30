"""Tests for the ODOO_MCP_ENABLE_WRITES gate on chatter_post.

chatter_post reaches ``message_post``, which writes a mail.message and — for
the default ``comment`` subtype — emails followers. It is registered
unconditionally, so before this gate a server with writes disabled still had a
live outbound path. These tests pin the refusal on all three routes to
``message_post`` (preview, approved-execute, and MCP_CHATTER_DIRECT), pin that
the refusal happens before any Odoo call, and pin that the happy path still
works once writes are enabled.

Complements test_server.py (chatter_post behaviour with writes enabled).
"""

import importlib

import pytest

from tests.test_server import FakeCtx, _ChatterClient


@pytest.fixture
def server():
    return importlib.import_module("odoo_mcp.server")


def _writes_off(monkeypatch):
    monkeypatch.delenv("ODOO_MCP_ENABLE_WRITES", raising=False)
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)


def _writes_on(monkeypatch):
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)


# ---------------------------------------------------------------------------
# Refusal — every route to message_post
# ---------------------------------------------------------------------------


def test_refuses_and_makes_no_odoo_call_when_writes_disabled(server, monkeypatch):
    _writes_off(monkeypatch)
    client = _ChatterClient()

    result = server.chatter_post(
        FakeCtx(client), model="res.partner", record_id=7, body="Hello there"
    )

    assert result["success"] is False
    assert result["tool"] == "chatter_post"
    assert "ODOO_MCP_ENABLE_WRITES=1" in result["error"]
    # The refusal is the whole point: nothing reached Odoo.
    assert client.calls == []


def test_refuses_in_direct_mode(server, monkeypatch):
    _writes_off(monkeypatch)
    # MCP_CHATTER_DIRECT bypasses the approval token, not the write gate.
    monkeypatch.setenv("MCP_CHATTER_DIRECT", "1")
    client = _ChatterClient()

    result = server.chatter_post(
        FakeCtx(client), model="res.partner", record_id=7, body="Hello there"
    )

    assert result["success"] is False
    assert result["tool"] == "chatter_post"
    assert client.calls == []


def test_refuses_on_the_approved_execute_path(server, monkeypatch):
    """A token minted while writes were on must not execute after they go off.

    Approval tokens are a pure function of the payload, so one captured from a
    writes-enabled process stays syntactically valid. The gate is re-checked on
    the execute call rather than trusted from preview time.
    """
    _writes_on(monkeypatch)
    ctx = FakeCtx(_ChatterClient())
    preview = server.chatter_post(ctx, model="res.partner", record_id=7, body="Hi")
    approval = preview["approval"]

    _writes_off(monkeypatch)
    client = _ChatterClient()
    result = server.chatter_post(
        FakeCtx(client),
        model="res.partner",
        record_id=7,
        body="Hi",
        approval=approval,
        confirm=True,
    )

    assert result["success"] is False
    assert result["tool"] == "chatter_post"
    assert client.calls == []


def test_preview_hands_out_no_approval_token_when_writes_disabled(server, monkeypatch):
    """An upfront refusal beats a token the server would later refuse to honour."""
    _writes_off(monkeypatch)

    result = server.chatter_post(
        FakeCtx(_ChatterClient()), model="res.partner", record_id=7, body="Hi"
    )

    assert result["success"] is False
    assert "approval" not in result
    assert result.get("mode") != "preview"


def test_gate_precedes_argument_validation(server, monkeypatch):
    """Checked at function entry, so a disabled server does no work at all.

    An empty body would otherwise raise a validation error; with writes off the
    write-disabled refusal is what comes back, and _resolve_odoo is never
    reached — a refused call never opens a connection.
    """
    _writes_off(monkeypatch)

    result = server.chatter_post(
        FakeCtx(_ChatterClient()), model="res.partner", record_id=0, body=""
    )

    assert result["success"] is False
    assert "ODOO_MCP_ENABLE_WRITES=1" in result["error"]


def test_refusal_wording_matches_execute_approved_write(server, monkeypatch):
    """Both destructive tools refuse in the same words, so callers see one rule.

    The literal is spelled out here rather than compared against a live
    execute_approved_write refusal, because that tool checks the approval token
    before its write gate and so cannot be driven to the gate without a full
    valid approval. Pinning the string keeps the two refusals from drifting.
    """
    _writes_off(monkeypatch)

    chatter = server.chatter_post(
        FakeCtx(_ChatterClient()), model="res.partner", record_id=7, body="Hi"
    )

    assert (
        chatter["error"]
        == "write execution disabled; set ODOO_MCP_ENABLE_WRITES=1 to enable"
    )


# ---------------------------------------------------------------------------
# Acceptance — the gate does not break the enabled path
# ---------------------------------------------------------------------------


def test_preview_and_execute_still_work_when_writes_enabled(server, monkeypatch):
    _writes_on(monkeypatch)
    ctx = FakeCtx(_ChatterClient())

    preview = server.chatter_post(ctx, model="res.partner", record_id=7, body="Hi")
    assert preview["success"] is True
    assert preview["mode"] == "preview"

    client = _ChatterClient()
    executed = server.chatter_post(
        FakeCtx(client),
        model="res.partner",
        record_id=7,
        body="Hi",
        approval=preview["approval"],
        confirm=True,
    )

    assert executed["success"] is True
    assert executed["mode"] == "execute"
    assert client.calls[0][1] == "message_post"


def test_direct_mode_still_posts_when_writes_enabled(server, monkeypatch):
    _writes_on(monkeypatch)
    monkeypatch.setenv("MCP_CHATTER_DIRECT", "1")
    client = _ChatterClient()

    result = server.chatter_post(
        FakeCtx(client), model="res.partner", record_id=7, body="Hi"
    )

    assert result["success"] is True
    assert result["mode"] == "direct"
    assert client.calls[0][1] == "message_post"


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_gate_accepts_the_standard_truthy_spellings(server, monkeypatch, value):
    _writes_off(monkeypatch)
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", value)

    result = server.chatter_post(
        FakeCtx(_ChatterClient()), model="res.partner", record_id=7, body="Hi"
    )

    assert result["success"] is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off"])
def test_gate_rejects_falsey_and_blank_spellings(server, monkeypatch, value):
    _writes_off(monkeypatch)
    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", value)

    result = server.chatter_post(
        FakeCtx(_ChatterClient()), model="res.partner", record_id=7, body="Hi"
    )

    assert result["success"] is False
