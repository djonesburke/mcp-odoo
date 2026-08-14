"""Burke behaviors 3 and 4 — the human confirmation gate on Odoo writes.

**Behavior 3.** ``ODOO_MCP_ELICIT_WRITES=1`` is the only gate on the write path
that a human actually stands in. Every other gate — approval token, session
validation record, payload match, ``confirm=true`` — is one the calling agent
satisfies by itself. Upstream auto-approved when a client could not be asked,
so on such a client "confirm every write" silently became "write freely", with
the operator still believing a gate was in place. These tests hold it closed.

**Behavior 4.** A prompt that echoes only the proposed values reads like a diff
but is half of one: it cannot show that a field is already at the target value,
and on ``unlink`` it identifies records by bare integer id. These tests hold the
before-state in the prompt, and hold it out of the approval token.
"""

from __future__ import annotations

import importlib
import json

import pytest

from odoo_mcp import tools_write
from odoo_mcp.field_policy import reset_field_policy
from tests.test_batch_write import FakeCtx


# --------------------------------------------------------------------------
# Doubles
# --------------------------------------------------------------------------


class _Elicitation:
    def __init__(self, form=None, url=None):
        self.form = form
        self.url = url


class _Capabilities:
    def __init__(self, elicitation):
        self.elicitation = elicitation


class _CapCtx(FakeCtx):
    """A ctx that declares client capabilities, as a real MCP client does."""

    def __init__(self, odoo=None, capabilities=None):
        super().__init__(odoo)
        self.client_capabilities = capabilities


class _Review:
    """Shape of the resolved MRTR review argument."""

    def __init__(self, action, approve=None):
        self.action = action
        self.data = None
        if approve is not None:
            self.data = type("Data", (), {"approve": approve})()


class _ReadClient:
    def __init__(self, records=None, fail=None, fields_metadata=None):
        self.records = records or []
        self.fail = fail
        self.reads = []
        self._fields_metadata = fields_metadata or {
            "state": {"type": "char", "readonly": False},
            "name": {"type": "char", "readonly": False},
            "partner_id": {"type": "many2one", "readonly": False},
            "margin": {"type": "float", "readonly": False},
        }

    def get_model_fields(self, model):
        return self._fields_metadata

    def read_records(self, model, ids, fields=None):
        self.reads.append({"model": model, "ids": list(ids), "fields": list(fields or [])})
        if self.fail is not None:
            raise self.fail
        wanted = set(ids)
        return [
            {key: value for key, value in record.items() if fields is None or key in fields}
            for record in self.records
            if record["id"] in wanted
        ]


def _run(coro):
    import asyncio

    return asyncio.run(coro)


FORM_CAPABLE = _Capabilities(_Elicitation(form=object()))
NO_ELICITATION = _Capabilities(None)
URL_ONLY = _Capabilities(_Elicitation(form=None, url="https://example.invalid/confirm"))


# --------------------------------------------------------------------------
# Behavior 3 — the gate fails closed
# --------------------------------------------------------------------------


def test_gap_is_none_when_capabilities_cannot_be_introspected():
    """No capability object means the elicit call itself is the authority.

    Reporting a gap here would refuse every write on any client whose ctx does
    not expose capabilities — including the direct-call path, where a human
    genuinely can be asked.
    """
    assert tools_write._client_elicitation_gap(FakeCtx(None)) is None


def test_gap_flags_a_client_with_no_elicitation_capability():
    gap = tools_write._client_elicitation_gap(_CapCtx(capabilities=NO_ELICITATION))
    assert gap is not None and "no elicitation capability" in gap


def test_gap_flags_url_only_elicitation():
    """URL-mode elicitation cannot carry a confirmation form, so it is a gap."""
    gap = tools_write._client_elicitation_gap(_CapCtx(capabilities=URL_ONLY))
    assert gap is not None and "URL-mode" in gap


def test_form_capable_client_reports_no_gap():
    assert tools_write._client_elicitation_gap(_CapCtx(capabilities=FORM_CAPABLE)) is None


def test_resolver_refuses_when_gate_is_on_and_no_human_can_be_asked(monkeypatch):
    """The heart of behavior 3: refuse, where upstream returned approve=True."""
    monkeypatch.setenv(tools_write.ELICIT_WRITES_ENV, "1")
    decision = tools_write._resolve_write_confirmation(
        {"model": "res.partner", "operation": "write"},
        _CapCtx(capabilities=NO_ELICITATION),
    )
    assert decision.approve is False


def test_resolver_still_approves_when_the_gate_is_off(monkeypatch):
    """Behavior 3 must not turn the default (gate off) deployment into a wall."""
    monkeypatch.delenv(tools_write.ELICIT_WRITES_ENV, raising=False)
    decision = tools_write._resolve_write_confirmation(
        {"model": "res.partner", "operation": "write"},
        _CapCtx(capabilities=NO_ELICITATION),
    )
    assert decision.approve is True


def test_write_is_blocked_and_audited_when_no_human_can_be_asked(monkeypatch, tmp_path):
    from odoo_mcp import audit

    server = importlib.import_module("odoo_mcp.server")
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv(server.ELICIT_WRITES_ENV, "1")
    monkeypatch.setenv(audit.AUDIT_LOG_ENV, str(log_path))

    result = _run(
        server.execute_approved_write_tool(
            _CapCtx(capabilities=NO_ELICITATION),
            {"model": "res.partner", "operation": "write", "token": "bogus"},
            confirm=True,
            review=_Review("decline"),
        )
    )

    assert result["success"] is False
    assert "no human could be asked" in result["error"]
    # Refused before the token gate, so the reason the operator reads is the
    # real one rather than a downstream symptom.
    assert "token" not in result["error"]
    entry = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert entry["event"] == "elicit"
    assert entry["outcome"] == "blocked"


def test_human_decline_is_not_reported_as_a_client_gap(monkeypatch, tmp_path):
    """"Someone said no" and "nobody was asked" must stay distinguishable.

    They are the same refusal to the caller and completely different facts to
    whoever reads the audit log afterwards.
    """
    from odoo_mcp import audit

    server = importlib.import_module("odoo_mcp.server")
    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setenv(server.ELICIT_WRITES_ENV, "1")
    monkeypatch.setenv(audit.AUDIT_LOG_ENV, str(log_path))

    result = _run(
        server.execute_approved_write_tool(
            _CapCtx(capabilities=FORM_CAPABLE),
            {"model": "res.partner", "operation": "write", "token": "bogus"},
            confirm=True,
            review=_Review("decline"),
        )
    )

    assert result["success"] is False
    assert "declined by the human reviewer" in result["error"]
    entry = json.loads(log_path.read_text().strip().splitlines()[-1])
    assert entry["outcome"] == "declined"


# --------------------------------------------------------------------------
# Behavior 4 — the prompt shows what the write replaces
# --------------------------------------------------------------------------


def test_create_captures_no_state_and_makes_no_odoo_call():
    """There is no before-state for a create, so it must not cost a round trip."""
    client = _ReadClient()
    state = tools_write._collect_current_state(
        FakeCtx(client),
        model="res.partner",
        operation="create",
        record_ids=None,
        values={"name": "Ada"},
        instance=None,
    )
    assert state["available"] is True
    assert state["records"] == []
    assert client.reads == []


def test_write_reads_the_written_fields_and_a_label():
    client = _ReadClient(records=[{"id": 30530, "display_name": "S00423", "state": "draft"}])
    state = tools_write._collect_current_state(
        FakeCtx(client),
        model="sale.order",
        operation="write",
        record_ids=[30530],
        values={"state": "sale"},
        instance=None,
    )
    assert state["available"] is True
    assert client.reads[0]["ids"] == [30530]
    assert set(client.reads[0]["fields"]) == {"id", "display_name", "state"}
    assert state["records"][0]["state"] == "draft"


def test_unlink_reads_labels_so_records_are_identifiable():
    client = _ReadClient(records=[{"id": 30530, "display_name": "S00423"}])
    state = tools_write._collect_current_state(
        FakeCtx(client),
        model="sale.order",
        operation="unlink",
        record_ids=[30530],
        values=None,
        instance=None,
    )
    assert client.reads[0]["fields"] == ["id", "display_name"]
    assert state["records"][0]["display_name"] == "S00423"


def test_read_failure_degrades_to_a_stated_reason_not_an_exception():
    """A failed snapshot must not take the write path down with it."""
    client = _ReadClient(fail=RuntimeError("odoo unreachable"))
    state = tools_write._collect_current_state(
        FakeCtx(client),
        model="sale.order",
        operation="write",
        record_ids=[1],
        values={"state": "sale"},
        instance=None,
    )
    assert state["available"] is False
    assert "could not read" in state["reason"]


def test_missing_records_are_reported_rather_than_silently_dropped():
    client = _ReadClient(records=[{"id": 1, "display_name": "Kept"}])
    state = tools_write._collect_current_state(
        FakeCtx(client),
        model="sale.order",
        operation="unlink",
        record_ids=[1, 999],
        values=None,
        instance=None,
    )
    assert state["missing_ids"] == [999]


def test_field_acl_hides_denied_values_from_the_confirmation(monkeypatch, tmp_path):
    """A confirmation dialog must not become a way to read masked fields."""
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"field_acl": {"default": {"sale.order": {"deny": ["margin"]}}}}))
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(policy))
    reset_field_policy()
    try:
        client = _ReadClient(
            records=[{"id": 7, "display_name": "S00423", "margin": 1234.5, "state": "draft"}]
        )
        state = tools_write._collect_current_state(
            FakeCtx(client),
            model="sale.order",
            operation="write",
            record_ids=[7],
            values={"margin": 99.0, "state": "sale"},
            instance=None,
        )
        assert "margin" not in state["records"][0]
        assert state["redacted_fields"] == ["margin"]
        message = tools_write._write_elicitation_message(
            {"model": "sale.order", "operation": "write", "record_ids": [7],
             "values": {"margin": 99.0, "state": "sale"}},
            state,
        )
        assert "1234.5" not in message
        assert tools_write._REDACTED_MARKER in message
    finally:
        reset_field_policy()


def test_message_shows_before_and_after_for_each_field():
    state = {
        "available": True,
        "records": [{"id": 30530, "display_name": "S00423", "state": "draft"}],
        "redacted_fields": [],
        "missing_ids": [],
        "not_listed": 0,
    }
    message = tools_write._write_elicitation_message(
        {
            "model": "sale.order",
            "operation": "write",
            "record_ids": [30530],
            "values": {"state": "sale"},
        },
        state,
    )
    assert '"draft" -> "sale"' in message
    assert "30530  S00423" in message


def test_message_flags_a_field_already_at_the_target_value():
    """A no-op write should be visible as one, not read as a real change."""
    state = {
        "available": True,
        "records": [{"id": 1, "display_name": "S1", "state": "sale"}],
        "redacted_fields": [],
        "missing_ids": [],
        "not_listed": 0,
    }
    message = tools_write._write_elicitation_message(
        {"model": "sale.order", "operation": "write", "record_ids": [1],
         "values": {"state": "sale"}},
        state,
    )
    assert "unchanged" in message


def test_many2one_pair_is_compared_against_the_bare_id():
    """Odoo reads relations as [id, label] but writes take the id.

    Without this, every relational field reads as changed and buries the
    fields that really are.
    """
    assert tools_write._same_value([3, "Acme"], 3) is True
    assert tools_write._same_value([3, "Acme"], 4) is False


def test_unlink_message_names_the_records_and_says_it_deletes():
    state = {
        "available": True,
        "records": [{"id": 30530, "display_name": "S00423 - Village of Jackson"}],
        "redacted_fields": [],
        "missing_ids": [],
        "not_listed": 0,
    }
    message = tools_write._write_elicitation_message(
        {"model": "sale.order", "operation": "unlink", "record_ids": [30530]}, state
    )
    assert "DELETES" in message
    assert "Village of Jackson" in message


def test_message_says_so_when_the_before_state_is_missing():
    """Silent degradation here would show a half-diff that looks like a whole one."""
    message = tools_write._write_elicitation_message(
        {"model": "sale.order", "operation": "write", "record_ids": [1],
         "values": {"state": "sale"}},
        None,
    )
    assert "WARNING" in message
    assert "only what the write will set" in message


def test_long_values_are_truncated_in_the_prompt():
    message = tools_write._write_elicitation_message(
        {"model": "res.partner", "operation": "write", "record_ids": [1],
         "values": {"comment": "x" * 500}},
        None,
    )
    assert "x" * 500 not in message
    assert "..." in message


@pytest.mark.parametrize("operation", ["write", "unlink"])
def test_snapshot_reaches_the_approval_record_but_not_the_token(operation):
    """The before-state must never enter the canonical payload.

    If it did, the approval token would change whenever Odoo data changed, and
    a validated approval would stop matching itself mid-flight.
    """
    server = importlib.import_module("odoo_mcp.server")
    client = _ReadClient(records=[{"id": 7, "display_name": "S00423", "state": "draft"}])
    ctx = FakeCtx(client)

    report = server.validate_write(
        ctx,
        "sale.order",
        operation,
        values={"state": "sale"} if operation == "write" else None,
        record_ids=[7],
    )

    assert report["success"] is True
    assert report["current_state"]["available"] is True
    assert "current_state" not in report["approval"]
    # The stored record carries it; the canonical payload does not.
    stored = ctx.request_context.lifespan_context.write_approvals[report["approval"]["token"]]
    assert stored["current_state"]["available"] is True
    assert "current_state" not in stored["payload"]
    assert server.verify_write_approval(report["approval"])[0] is True
