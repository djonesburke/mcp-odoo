"""End-to-end field ACL redaction across the read tools and resources."""

import importlib
import json
from pathlib import Path

import pytest

from tests.test_batch_write import FakeCtx

from odoo_mcp.field_policy import reset_field_policy

server = importlib.import_module("odoo_mcp.server")


class PolicyClient:
    """Minimal Odoo client returning records with a sensitive field."""

    def search_read(self, *args, **kwargs):
        return [
            {"id": 1, "name": "Azure", "credit_limit": 5000, "email": "a@x.io"},
            {"id": 2, "name": "Deco", "credit_limit": 9000, "email": "d@x.io"},
        ]

    def read_records(self, model, ids, fields=None):
        return [{"id": ids[0], "name": "Azure", "credit_limit": 5000}]

    def get_model_fields(self, model):
        return {
            "name": {"type": "char", "string": "Name"},
            "credit_limit": {"type": "monetary", "string": "Credit Limit"},
            "email": {"type": "char", "string": "Email"},
        }

    def get_models(self):
        return {"model_names": ["res.partner"]}


@pytest.fixture
def deny_credit_limit(monkeypatch, tmp_path):
    pf = tmp_path / "fp.json"
    pf.write_text(
        json.dumps(
            {"field_acl": {"default": {"res.partner": {"deny": ["credit_limit"]}}}}
        )
    )
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(pf))
    monkeypatch.setattr(server, "resolve_instance_name", lambda name: name or "default")
    monkeypatch.setattr(server, "resolve_default_instance_name", lambda: "default")
    reset_field_policy()
    yield
    reset_field_policy()


def test_search_records_redacts_denied_field(deny_credit_limit):
    out = server.search_records(FakeCtx(PolicyClient()), model="res.partner")
    assert out["success"] is True
    assert all("credit_limit" not in row for row in out["result"])
    assert out["redacted_fields"] == ["credit_limit"]
    assert all("name" in row for row in out["result"])


def test_read_record_redacts_denied_field(deny_credit_limit):
    out = server.read_record(FakeCtx(PolicyClient()), model="res.partner", record_id=1)
    assert out["success"] is True
    assert "credit_limit" not in out["result"]
    assert out["redacted_fields"] == ["credit_limit"]


def test_aggregate_rejects_denied_field(deny_credit_limit):
    out = server.aggregate_records(
        FakeCtx(PolicyClient()),
        model="res.partner",
        group_by=["country_id"],
        measures=["credit_limit:sum"],
    )
    assert out["success"] is False
    assert "credit_limit" in out["error"]


def test_aggregate_rejects_denied_groupby(deny_credit_limit):
    out = server.aggregate_records(
        FakeCtx(PolicyClient()),
        model="res.partner",
        group_by=["credit_limit"],
        measures=["__count:count"] if False else None,
    )
    assert out["success"] is False
    assert "credit_limit" in out["error"]


def test_get_model_fields_marks_restricted(deny_credit_limit):
    out = server.get_model_fields(FakeCtx(PolicyClient()), model="res.partner")
    assert out["success"] is True
    assert out["result"]["credit_limit"]["access"] == "restricted"
    assert "access" not in out["result"]["name"]
    assert out["restricted_fields"] == ["credit_limit"]


def test_resource_get_record_redacts(deny_credit_limit, monkeypatch):
    monkeypatch.setattr(server, "get_odoo_client", lambda: PolicyClient())
    payload = json.loads(server.get_record("res.partner", "1"))
    assert "credit_limit" not in payload
    assert payload["_redacted_fields"] == ["credit_limit"]


def test_no_policy_is_byte_identical(monkeypatch, tmp_path):
    """With no policy configured anywhere, reads pass through untouched.

    Clearing the two env vars is not enough to reach the no-policy state:
    policy_file_path() then falls back to the bare relative filename
    "odoo_mcp_policy.json", which resolves against the current working
    directory — the repo root under pytest, where this project ships one. So
    the cwd is moved to an empty tmp_path as well; without that, this test
    asserts against whatever policy the repo happens to carry rather than
    against no policy at all.

    Uses monkeypatch rather than os.environ.pop so the cleared variables are
    restored afterwards, and resets the process-wide policy cache on the way
    out so a "no policy" verdict does not leak into later tests.
    """
    monkeypatch.delenv("ODOO_MCP_FIELD_POLICY_FILE", raising=False)
    monkeypatch.delenv("ODOO_MCP_POLICY_FILE", raising=False)
    monkeypatch.chdir(tmp_path)
    reset_field_policy()
    try:
        out = server.search_records(FakeCtx(PolicyClient()), model="res.partner")
        assert "redacted_fields" not in out
        assert all("credit_limit" in row for row in out["result"])
    finally:
        reset_field_policy()


class _EchoLife:
    """Lifespan double whose get_client echoes the requested instance name."""

    def __init__(self, odoo):
        self.odoo = odoo
        self.schema_cache = {}
        self.write_approvals = {}

    def get_client(self, instance=None):
        return (instance or "default"), self.odoo


class _EchoCtx:
    def __init__(self, odoo):
        self.request_context = type(
            "R", (), {"lifespan_context": _EchoLife(odoo)}
        )()


def test_instance_isolation(monkeypatch, tmp_path):
    pf = tmp_path / "fp.json"
    # Policy only for instance 'alpha'; 'default' is unaffected.
    pf.write_text(
        json.dumps(
            {"field_acl": {"alpha": {"res.partner": {"deny": ["credit_limit"]}}}}
        )
    )
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(pf))
    monkeypatch.setattr(server, "resolve_instance_name", lambda name: name or "default")
    monkeypatch.setattr(server, "resolve_default_instance_name", lambda: "default")
    reset_field_policy()
    try:
        default_out = server.search_records(
            _EchoCtx(PolicyClient()), model="res.partner"
        )
        assert "redacted_fields" not in default_out
        alpha_out = server.search_records(
            _EchoCtx(PolicyClient()), model="res.partner", instance="alpha"
        )
        assert alpha_out["redacted_fields"] == ["credit_limit"]
    finally:
        reset_field_policy()


def test_health_check_reports_field_acl(deny_credit_limit):
    health = server.health_check()
    assert health["runtime"]["field_acl"]["active"] is True
    assert health["runtime"]["field_acl"]["instances_with_rules"] == 1


# --- curated tools: the path a field mask does not reach --------------------


class HolidayClient:
    """Client whose search_read answers the search_holidays projection."""

    def __init__(self):
        self.calls = 0

    def search_read(self, model_name, domain, **kwargs):
        self.calls += 1
        return [
            {
                "display_name": "Holiday",
                "start_datetime": "2024-01-01 00:00:00",
                "stop_datetime": "2024-01-02 00:00:00",
                "employee_id": [7, "Ada"],
                "name": "Vacation",
                "state": "validate",
            }
        ]


@pytest.fixture
def close_absence_model(monkeypatch, tmp_path):
    """The shipped shape: hr.leave.report.calendar as an empty whitelist."""
    pf = tmp_path / "fp.json"
    pf.write_text(
        json.dumps(
            {"field_acl": {"default": {"hr.leave.report.calendar": {"allow": []}}}}
        )
    )
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(pf))
    monkeypatch.setattr(server, "resolve_instance_name", lambda name: name or "default")
    monkeypatch.setattr(server, "resolve_default_instance_name", lambda: "default")
    reset_field_policy()
    yield
    reset_field_policy()


def test_search_holidays_refuses_when_the_policy_closes_the_model(close_absence_model):
    """A curated tool must not answer around the mask it never consults.

    search_holidays reads hr.leave.report.calendar through the raw client and
    returns a fixed projection -- the employee link, the dates, the name and
    the state of a named person's time off. Redaction never applied to it
    (docs/field-acl.md, "Limits"), so masking hr.leave and its report models
    in the policy file would have left this tool answering in full.

    It refuses rather than redacts because the projection has required fields:
    a partially-filled Holiday is not a thing this response model can carry,
    and silently returning fewer rows would be worse than an error that says
    why.
    """
    client = HolidayClient()
    result = server.search_holidays(
        FakeCtx(client), start_date="2024-01-01", end_date="2024-01-31"
    )
    assert result.success is False
    assert "hr.leave.report.calendar" in result.error
    assert "employee_id" in result.error
    assert client.calls == 0, "the refusal must happen before Odoo is read"


def test_search_holidays_is_unchanged_without_a_policy(monkeypatch, tmp_path):
    """The upstream guarantee: no policy file, no behaviour change."""
    monkeypatch.delenv("ODOO_MCP_FIELD_POLICY_FILE", raising=False)
    monkeypatch.delenv("ODOO_MCP_POLICY_FILE", raising=False)
    monkeypatch.chdir(tmp_path)
    reset_field_policy()
    try:
        result = server.search_holidays(
            FakeCtx(HolidayClient()), start_date="2024-01-01", end_date="2024-01-31"
        )
        assert result.success is True
        assert result.result[0].name == "Vacation"
    finally:
        reset_field_policy()


def test_search_holidays_still_answers_when_the_policy_spares_it(
    deny_credit_limit,
):
    """A policy about other models does not disable a curated tool."""
    result = server.search_holidays(
        FakeCtx(HolidayClient()), start_date="2024-01-01", end_date="2024-01-31"
    )
    assert result.success is True
    assert result.result[0].state == "validate"


# --- domain filtering: the question, not just the answer -------------------
#
# Every read below asks only for fields nobody denied, so output redaction
# passes them through untouched. The domain is what turns each one into an
# answer about the denied field -- a filtered aggregate is the per-person
# series, a bare count bisected over dates is a named person's absence. The
# 2026-09-08 adversarial review (B3) found this open on all six enforcement
# paths at once; these pin the four that run in-process here, and
# tests/test_cross_instance.py pins the other two.


class CountingPolicyClient(PolicyClient):
    """PolicyClient that records whether Odoo was reached at all."""

    def __init__(self):
        self.calls = 0

    def search_read(self, *args, **kwargs):
        self.calls += 1
        return super().search_read(*args, **kwargs)


def test_search_records_refuses_a_domain_over_a_denied_field(deny_credit_limit):
    client = CountingPolicyClient()
    out = server.search_records(
        FakeCtx(client),
        model="res.partner",
        domain=[["credit_limit", ">", 1000]],
        fields=["name"],
    )
    assert out["success"] is False
    assert "credit_limit" in out["error"]
    assert client.calls == 0, "the refusal must happen before Odoo is read"


def test_search_records_refusal_does_not_echo_the_domain_value(deny_credit_limit):
    """A domain value can be the content the rule withholds."""
    out = server.search_records(
        FakeCtx(CountingPolicyClient()),
        model="res.partner",
        domain=[["credit_limit", "=", 424242]],
    )
    assert out["success"] is False
    assert "424242" not in out["error"]
    assert "credit_limit" in out["error"] and "res.partner" in out["error"]


def test_search_records_still_answers_an_allowed_domain(deny_credit_limit):
    out = server.search_records(
        FakeCtx(PolicyClient()),
        model="res.partner",
        domain=[["name", "ilike", "a"]],
    )
    assert out["success"] is True
    assert out["count"] == 2
    assert out["redacted_fields"] == ["credit_limit"]


def test_aggregate_refuses_a_domain_only_narrowing(deny_credit_limit):
    """group_by and measures are all open; the domain is the whole attack."""
    out = server.aggregate_records(
        FakeCtx(PolicyClient()),
        model="res.partner",
        group_by=["country_id"],
        measures=["id:count"],
        domain=[["credit_limit", ">", 0]],
    )
    assert out["success"] is False
    assert "credit_limit" in out["error"]


def test_index_knowledge_refuses_a_domain_over_a_denied_field(deny_credit_limit):
    client = CountingPolicyClient()
    out = server.index_knowledge(
        FakeCtx(client),
        model="res.partner",
        domain=[["credit_limit", ">", 1000]],
    )
    assert out["success"] is False
    assert "credit_limit" in out["error"]
    assert client.calls == 0


def test_search_resource_refuses_a_domain_over_a_denied_field(
    deny_credit_limit, monkeypatch
):
    client = CountingPolicyClient()
    monkeypatch.setattr(server, "get_odoo_client", lambda: client)
    payload = json.loads(
        server.search_records_resource(
            "res.partner", json.dumps([["credit_limit", ">", 1000]])
        )
    )
    assert "credit_limit" in payload["error"]
    assert client.calls == 0


def test_search_records_refuses_a_dotted_path_to_a_denied_field(deny_credit_limit):
    """The relation is not a way around the rule."""
    out = server.search_records(
        FakeCtx(CountingPolicyClient()),
        model="res.partner",
        domain=[["credit_limit.whatever", "=", 1]],
    )
    assert out["success"] is False
    assert "credit_limit" in out["error"]


# ---------------------------------------------------------------------------
# The policy this repo actually ships, driven through the real tools.
#
# tests/test_shipped_policy.py pins the file's shape and tests/test_field_policy.py
# pins filter_fields against it. Neither proves a tool call is what applies it, and
# the 2026-09-08 rulings all landed on models a curated tool or a free-text shortcut
# can reach. These go through server.search_records / aggregate_records with the real
# file loaded, so the assertion is "the key did not reach the caller", not "the rule
# is present".
# ---------------------------------------------------------------------------

SHIPPED_POLICY_PATH = Path(__file__).resolve().parent.parent / "odoo_mcp_policy.json"


class ShippedClient:
    """Rows shaped like the ones the 2026-09-08 rulings withhold.

    Every value is a placeholder -- 1.0, "somebody" -- because the tests
    assert on field *names* never reaching the caller. No Burke figure and no
    real name belongs in a fixture.
    """

    _ROWS = {
        "account.analytic.line": [
            {
                "id": 31,
                "date": "2026-09-01",
                "amount": -1.0,
                "unit_amount": 1.0,
                "name": "[EMPL] WO/0001 - somebody",
                "display_name": "[EMPL] WO/0001 - somebody",
            }
        ],
        "mrp.workcenter.productivity": [
            {
                "id": 41,
                "duration": 60.0,
                "employee_id": [7, "somebody"],
                "employee_cost": 1.0,
                "total_cost": 1.0,
            }
        ],
        "account.account": [
            {
                "id": 11,
                "code": "1010",
                "account_type": "asset_cash",
                "current_balance": 1.0,
            }
        ],
        "account.bank.statement.line": [
            {"id": 21, "date": "2026-09-01", "amount": 1.0, "running_balance": 2.0}
        ],
    }

    # Enough metadata for the free-text query shortcut to pick a text field.
    _FIELDS = {
        "name": {"type": "char", "string": "Description", "searchable": True},
    }

    def __init__(self):
        self.calls = 0

    def search_read(self, model_name=None, fields=None, **kwargs):
        self.calls += 1
        rows = self._ROWS[model_name]
        if fields is None:
            return [dict(row) for row in rows]
        wanted = set(fields) | {"id"}
        return [{k: v for k, v in row.items() if k in wanted} for row in rows]

    def get_model_fields(self, model):
        return dict(self._FIELDS)


@pytest.fixture
def shipped_policy(monkeypatch):
    """Load the vendored odoo_mcp_policy.json, not a fixture policy."""
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(SHIPPED_POLICY_PATH))
    monkeypatch.setattr(server, "resolve_instance_name", lambda name: name or "default")
    monkeypatch.setattr(server, "resolve_default_instance_name", lambda: "default")
    reset_field_policy()
    yield
    reset_field_policy()


@pytest.mark.parametrize(
    "model,fields,denied",
    [
        (
            "account.analytic.line",
            ["date", "amount", "unit_amount", "name", "display_name"],
            ["display_name", "name"],
        ),
        (
            "mrp.workcenter.productivity",
            ["duration", "employee_cost", "total_cost"],
            ["employee_cost", "total_cost"],
        ),
        (
            "account.account",
            ["code", "account_type", "current_balance"],
            ["current_balance"],
        ),
        (
            "account.bank.statement.line",
            ["date", "amount", "running_balance"],
            ["running_balance"],
        ),
    ],
)
def test_shipped_policy_strips_the_ruled_fields_through_search_records(
    shipped_policy, model, fields, denied
):
    client = ShippedClient()
    out = server.search_records(FakeCtx(client), model=model, fields=fields)
    assert out["success"] is True
    assert client.calls == 1
    for row in out["result"]:
        for field in denied:
            assert field not in row, f"{field} reached the caller on {model}"
    assert out["redacted_fields"] == denied


@pytest.mark.parametrize(
    "model,field",
    [
        ("account.analytic.line", "name"),
        ("mrp.workcenter.productivity", "employee_cost"),
        ("account.account", "current_balance"),
        ("account.bank.statement.line", "running_balance"),
    ],
)
def test_shipped_policy_refuses_a_domain_over_a_ruled_field(
    shipped_policy, model, field
):
    """Redacting the column leaves the filter; the filter is the same question."""
    client = ShippedClient()
    out = server.search_records(
        FakeCtx(client), model=model, domain=[[field, "!=", False]], fields=["id"]
    )
    assert out["success"] is False
    assert field in out["error"] and model in out["error"]
    assert client.calls == 0, "the refusal must happen before Odoo is read"


def test_shipped_policy_refuses_a_cash_balance_aggregate(shipped_policy):
    """The measure is the denied field, so check_aggregate answers first."""
    out = server.aggregate_records(
        FakeCtx(ShippedClient()),
        model="account.account",
        group_by=["account_type"],
        measures=["current_balance:sum"],
    )
    assert out["success"] is False
    assert "current_balance" in out["error"]


def test_free_text_query_on_analytic_lines_refuses_instead_of_half_answering(
    shipped_policy,
):
    """The one shipped read path the ``name`` deny changes, and how it degrades.

    ``query`` is a server-side shortcut: it builds an OR ilike domain from the
    model's searchable text fields, and on account.analytic.line that is
    ``name`` -- now denied. The tool refuses, naming the model and the field,
    rather than quietly searching a narrower set of columns and returning a
    partial answer that looks complete. Nothing else in src/ reads any field
    these rulings denied (grepped 2026-09-08), so this is the whole blast
    radius inside the server.
    """
    client = ShippedClient()
    out = server.search_records(
        FakeCtx(client), model="account.analytic.line", query="EMPL", fields=["id"]
    )
    assert out["success"] is False
    assert "account.analytic.line" in out["error"] and "name" in out["error"]
    assert client.calls == 0
