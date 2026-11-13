"""Field-ACL bypass paths from the 2026-11-10 security scan (SW-178).

One block per finding: F1 (execute_method reads), F13 (attachment-backed
binaries), F12 (denied fields reached through a relation), F6 (decorated
aggregate names), F17 (odoo://search default order) and F10 (get_* methods
are not read-only by name).
"""

import importlib
import json

import pytest

from tests.test_batch_write import FakeCtx

from odoo_mcp.diagnostics import classify_method_safety
from odoo_mcp.field_policy import comodel_resolver, get_field_policy, reset_field_policy

server = importlib.import_module("odoo_mcp.server")

POLICY = {
    "field_acl": {
        "default": {
            "*": {"deny": ["acc_number"]},
            "res.partner": {"deny": ["credit_limit"]},
            "hr.employee": {"allow": ["name", "work_email"]},
            "hr.version": {"deny": ["wage"]},
            "hr.leave": {"allow": []},
        }
    }
}

FIELDS = {
    "res.users": {
        "name": {"type": "char"},
        "employee_id": {"type": "many2one", "relation": "hr.employee"},
        "partner_id": {"type": "many2one", "relation": "res.partner"},
    },
    "hr.employee": {
        "name": {"type": "char"},
        "wage": {"type": "monetary"},
        "version_id": {"type": "many2one", "relation": "hr.version"},
    },
    "hr.version": {"wage": {"type": "monetary"}, "name": {"type": "char"}},
    "res.partner": {
        "name": {"type": "char"},
        "credit_limit": {"type": "monetary"},
        "user_ids": {"type": "one2many", "relation": "res.users"},
    },
}


class Client:
    """Records every call; answers reads from canned rows."""

    def __init__(self, rows=None, result=None):
        self.rows = rows if rows is not None else []
        self.result = result
        self.calls = []

    def get_model_fields(self, model):
        self.calls.append(("get_model_fields", model))
        return FIELDS.get(model, {"name": {"type": "char"}})

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method, args, kwargs))
        return self.rows if self.result is None else self.result

    def search_read(self, model_name, domain, **kwargs):
        self.calls.append((model_name, "search_read", (domain,), kwargs))
        return self.rows

    def read_records(self, model, ids, fields=None):
        self.calls.append((model, "read", (ids,), {"fields": fields}))
        return self.rows

    def get_server_version(self):
        return {"server_version_info": [19, 0]}

    def odoo_calls(self):
        return [c for c in self.calls if c[0] != "get_model_fields"]


@pytest.fixture
def policy(monkeypatch, tmp_path):
    pf = tmp_path / "fp.json"
    pf.write_text(json.dumps(POLICY))
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(pf))
    monkeypatch.delenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", raising=False)
    monkeypatch.delenv("ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", raising=False)
    monkeypatch.setattr(server, "resolve_instance_name", lambda name: name or "default")
    monkeypatch.setattr(server, "resolve_default_instance_name", lambda: "default")
    reset_field_policy()
    yield
    reset_field_policy()


# --- F1: execute_method read paths -----------------------------------------


def test_f1_execute_method_search_read_redacts_denied_field(policy):
    client = Client(rows=[{"id": 1, "name": "A", "credit_limit": 5000}])
    out = server.execute_method(
        FakeCtx(client), "res.partner", "search_read", [[]], {"fields": ["credit_limit"]}
    )
    assert out["success"] is True
    assert out["result"] == [{"id": 1, "name": "A"}]
    assert out["redacted_fields"] == ["credit_limit"]


def test_f1_execute_method_read_redacts_allow_list_model(policy):
    client = Client(rows=[{"id": 7, "name": "Ann", "wage": 99, "birthday": "x"}])
    out = server.execute_method(FakeCtx(client), "hr.employee", "read", [[7]])
    assert out["success"] is True
    assert out["result"] == [{"id": 7, "name": "Ann"}]
    assert out["redacted_fields"] == ["birthday", "wage"]


@pytest.mark.parametrize(
    "method,args,kwargs",
    [
        ("search_count", [[["credit_limit", ">", 100]]], None),
        ("search", [[["credit_limit", ">", 100]]], None),
        ("search_read", [], {"domain": [["credit_limit", ">", 100]]}),
        ("search", [], {"args": [["credit_limit", ">", 100]]}),
        ("search", [[]], {"order": "credit_limit desc"}),
        ("search", [[], 0, 5, "credit_limit desc"], None),
        ("search_read", [[], ["name"], 0, 5, "credit_limit"], None),
        ("search_read", [[["user_ids.employee_id.wage", ">", 1]]], None),
    ],
)
def test_f1_execute_method_refuses_filter_or_order_on_denied_field(
    policy, method, args, kwargs
):
    client = Client(rows=[{"id": 1}])
    out = server.execute_method(FakeCtx(client), "res.partner", method, args, kwargs)
    assert out["success"] is False
    assert "Field policy" in out["error"]
    assert client.odoo_calls() == []


def test_f1_execute_method_pins_default_order_on_governed_model(policy):
    client = Client(result=[3, 1])
    out = server.execute_method(FakeCtx(client), "hr.leave", "search", [[]])
    assert out["success"] is True
    assert client.odoo_calls()[0][3]["order"] == "id"


@pytest.mark.parametrize("method", ["name_search", "name_get"])
def test_f1_execute_method_refuses_label_reads_on_governed_model(policy, method):
    client = Client(result=[[1, "Ann on Sick Leave"]])
    out = server.execute_method(FakeCtx(client), "hr.leave", method, [])
    assert out["success"] is False
    assert "Field policy" in out["error"]
    assert client.odoo_calls() == []


def test_f1_execute_method_unchanged_without_policy(monkeypatch, tmp_path):
    monkeypatch.delenv("ODOO_MCP_FIELD_POLICY_FILE", raising=False)
    monkeypatch.delenv("ODOO_MCP_POLICY_FILE", raising=False)
    monkeypatch.chdir(tmp_path)
    reset_field_policy()
    try:
        client = Client(rows=[{"id": 1, "credit_limit": 5}])
        out = server.execute_method(
            FakeCtx(client),
            "res.partner",
            "search_read",
            [[["credit_limit", ">", 1]]],
        )
        assert out == {"success": True, "result": [{"id": 1, "credit_limit": 5}]}
        assert client.calls[0][3] == {}
    finally:
        reset_field_policy()


# --- F10: get_* is not read-only by name -----------------------------------


def test_f10_get_prefix_is_not_classified_read_only():
    assert classify_method_safety("get_portal_url")["safety"] != "read_only"
    assert classify_method_safety("_get_report_values")["safety"] != "read_only"
    assert classify_method_safety("search_read")["safety"] == "read_only"


def test_f10_execute_method_blocks_unreviewed_get_method(policy):
    client = Client(result="https://x/my/invoices/42?access_token=t")
    out = server.execute_method(
        FakeCtx(client), "account.move", "get_portal_url", [[42]]
    )
    assert out["success"] is False
    assert "Unreviewed side-effect methods" in out["error"]
    assert client.odoo_calls() == []


def test_f10_reviewed_get_method_still_runs(policy, monkeypatch):
    monkeypatch.setenv(
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "account.move.get_portal_url"
    )
    client = Client(result="url")
    out = server.execute_method(
        FakeCtx(client), "account.move", "get_portal_url", [[42]]
    )
    assert out == {"success": True, "result": "url"}


# --- F13: attachment-backed binary fields ----------------------------------

ID_CARD = {
    "id": 9,
    "name": "id_card",
    "type": "binary",
    "file_size": 10,
    "res_model": "hr.employee",
    "res_field": "id_card",
    "res_id": 7,
    "datas": "c2VjcmV0",
}


def test_f13_read_attachment_refuses_masked_owner_field(policy):
    client = Client(rows=[dict(ID_CARD)])
    out = server.read_attachment(FakeCtx(client), attachment_id=9)
    assert out["success"] is False
    assert "Field policy" in out["error"]
    assert "c2VjcmV0" not in json.dumps(out)
    # The content read never happens.
    assert all("datas" not in (c[3].get("fields") or []) for c in client.calls)


def test_f13_read_attachment_still_returns_unmasked_attachment(policy):
    row = dict(ID_CARD, res_model="res.partner", res_field="image_1920")
    client = Client(rows=[row])
    out = server.read_attachment(FakeCtx(client), attachment_id=9)
    assert out["success"] is True
    assert out["data_base64"] == "c2VjcmV0"


def test_f13_search_records_drops_content_of_masked_owner_field(policy):
    client = Client(rows=[dict(ID_CARD, raw="secret", index_content="secret")])
    out = server.search_records(
        FakeCtx(client),
        model="ir.attachment",
        domain=[["res_field", "=", "id_card"]],
        fields=["datas", "raw", "index_content", "res_model", "res_field"],
    )
    assert out["success"] is True
    assert "secret" not in json.dumps(out["result"]) and "c2Vj" not in json.dumps(
        out["result"]
    )
    assert {"datas", "raw", "index_content"} <= set(out["redacted_fields"])


def test_f13_content_without_owner_columns_fails_closed(policy):
    client = Client(rows=[{"id": 9, "datas": "c2VjcmV0"}])
    out = server.read_record(
        FakeCtx(client), model="ir.attachment", record_id=9, fields=["datas"]
    )
    assert out["success"] is True
    assert out["result"] == {"id": 9}
    assert out["redacted_fields"] == ["datas"]


def test_f13_plain_attachment_content_is_untouched(policy):
    row = {"id": 4, "datas": "b2s=", "res_model": "sale.order", "res_field": False}
    client = Client(rows=[row])
    out = server.read_record(
        FakeCtx(client),
        model="ir.attachment",
        record_id=4,
        fields=["datas", "res_model", "res_field"],
    )
    assert out["result"] == row
    assert "redacted_fields" not in out


def test_f13_execute_method_read_on_attachment_is_masked(policy):
    client = Client(rows=[dict(ID_CARD)])
    out = server.execute_method(FakeCtx(client), "ir.attachment", "read", [[9]])
    assert out["success"] is True
    assert "datas" not in out["result"][0]


# --- F12: denied field reached through a relation --------------------------


@pytest.mark.parametrize(
    "domain",
    [
        [["employee_id.wage", ">", 1000]],
        [["employee_id", "any", [["wage", ">", 1000]]]],
        [["employee_id.version_id.wage", ">", 1000]],
        [["partner_id.user_ids.employee_id", "not any", [["wage", ">", 1]]]],
        ["|", ["name", "=", "x"], ["partner_id.credit_limit", ">", 5]],
    ],
)
def test_f12_search_records_refuses_denied_field_through_relation(policy, domain):
    client = Client(rows=[{"id": 1, "name": "u"}])
    out = server.search_records(
        FakeCtx(client), model="res.users", domain=domain, fields=["name"]
    )
    assert out["success"] is False
    assert "Field policy" in out["error"]
    assert client.odoo_calls() == []


def test_f12_open_relation_path_still_passes(policy):
    client = Client(rows=[{"id": 1, "name": "u"}])
    out = server.search_records(
        FakeCtx(client),
        model="res.users",
        domain=[["partner_id.name", "ilike", "x"]],
        fields=["name"],
    )
    assert out["success"] is True


def test_f12_ungoverned_outer_model_is_still_checked(monkeypatch, tmp_path):
    pf = tmp_path / "fp.json"
    pf.write_text(
        json.dumps({"field_acl": {"default": {"hr.version": {"deny": ["wage"]}}}})
    )
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(pf))
    reset_field_policy()
    try:
        policy = get_field_policy()
        resolve = comodel_resolver(Client())
        assert not policy.governs("default", "hr.employee")
        block = policy.check_domain(
            "default", "hr.employee", [["version_id.wage", ">", 1]], resolve
        )
        assert block is not None and "hr.version.wage" in block
        assert (
            policy.check_domain(
                "default", "hr.employee", [["version_id.name", "=", "a"]], resolve
            )
            is None
        )
        # An instance with no rules at all never resolves anything.
        assert (
            policy.check_domain(
                "other", "hr.employee", [["version_id.wage", ">", 1]], resolve
            )
            is None
        )
    finally:
        reset_field_policy()


def test_f12_unresolvable_relation_fails_closed(policy):
    class Broken(Client):
        def get_model_fields(self, model):
            return {"error": "boom"}

    block = get_field_policy().check_domain(
        "default",
        "res.users",
        [["employee_id.name", "=", "x"]],
        comodel_resolver(Broken()),
    )
    assert block is not None and "cannot" in block


def test_f12_aggregate_refuses_denied_field_through_relation(policy):
    client = Client(rows=[])
    out = server.aggregate_records(
        FakeCtx(client),
        model="res.users",
        group_by=["employee_id.wage"],
    )
    assert out["success"] is False
    assert "Field policy" in out["error"]
    assert client.odoo_calls() == []


# --- F6: decorated aggregate names -----------------------------------------


@pytest.mark.parametrize("measure", ["wage!", "wage)", "wage!:sum", "wage :sum"])
def test_f6_decorated_measure_is_refused(policy, measure):
    block = get_field_policy().check_aggregate(
        "default", "hr.version", [measure.split(":", 1)[0]]
    )
    assert block is not None

    client = Client(rows=[{"employee_id": [1, "Ann"], "wage": 5000, "__count": 1}])
    out = server.aggregate_records(
        FakeCtx(client),
        model="hr.version",
        group_by=["employee_id"],
        measures=[measure],
    )
    assert out["success"] is False
    assert client.odoo_calls() == []


def test_f6_aggregate_across_instances_refuses_decorated_measure(policy, monkeypatch):
    import odoo_mcp.tools_cross_instance as tci

    client = Client(rows=[{"employee_id": [1, "Ann"], "wage": 5000, "__count": 1}])

    class App:
        def get_client(self, instance=None):
            return "default", client

    class Selection:
        selected = ["default"]
        skipped_opt_out: list = []
        unknown: list = []

    monkeypatch.setattr(tci, "_resolve_selection", lambda app, instances: Selection())
    try:
        payload = tci.run_aggregate_across(
            App(),
            {"model": "hr.version", "group_by": ["employee_id"], "measures": ["wage!"]},
        )
    except Exception as exc:  # a refusal may also surface as a raise
        payload = {"errors": {"default": str(exc)}}
    assert client.odoo_calls() == []
    assert "5000" not in json.dumps(payload, default=str)


def test_f6_aggregate_rows_drop_denied_columns(policy):
    """Legacy read_group can return a column nobody named (fields=[])."""
    client = Client(
        rows=[{"employee_id": [1, "Ann"], "wage": 5000, "hours": 8, "__count": 1}]
    )
    out = server.aggregate_records(
        FakeCtx(client), model="hr.version", group_by=["employee_id"]
    )
    assert out["success"] is True
    assert out["rows"] == [{"employee_id": [1, "Ann"], "hours": 8, "__count": 1}]


# --- F17: odoo://search default order --------------------------------------


def test_f17_search_resource_pins_order_on_governed_model(policy, monkeypatch):
    client = Client(rows=[{"id": 2}, {"id": 1}])
    monkeypatch.setattr(server, "get_odoo_client", lambda: client)
    json.loads(server.search_records_resource("hr.leave", "[]"))
    call = client.odoo_calls()[0]
    assert call[3].get("order") == "id"
