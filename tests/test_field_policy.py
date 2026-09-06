"""Unit tests for the pure field-level ACL policy module."""

import json
from pathlib import Path

import pytest

from odoo_mcp import field_policy
from odoo_mcp.field_policy import (
    ALWAYS_KEPT,
    FieldPolicy,
    FieldPolicyError,
    _parse_field_policy,
    load_field_policy,
    reset_field_policy,
)

SHIPPED_POLICY_PATH = Path(__file__).resolve().parent.parent / "odoo_mcp_policy.json"


def make(acl):
    return _parse_field_policy({"field_acl": acl})


def test_empty_policy_is_passthrough():
    policy = FieldPolicy({})
    assert policy.active() is False
    kept, redacted = policy.filter_fields("default", "res.partner", ["a", "b"])
    assert kept == ["a", "b"] and redacted == []


def test_deny_removes_listed_fields():
    policy = make({"default": {"res.partner": {"deny": ["credit_limit", "comment"]}}})
    kept, redacted = policy.filter_fields(
        "default", "res.partner", ["name", "credit_limit", "comment", "email"]
    )
    assert kept == ["name", "email"]
    assert sorted(redacted) == ["comment", "credit_limit"]


def test_allow_is_exclusive_whitelist():
    policy = make({"default": {"hr.employee": {"allow": ["name", "work_email"]}}})
    kept, redacted = policy.filter_fields(
        "default", "hr.employee", ["name", "work_email", "ssn", "salary"]
    )
    assert kept == ["name", "work_email"]
    assert sorted(redacted) == ["salary", "ssn"]


def test_id_is_never_redacted():
    policy = make({"default": {"res.partner": {"allow": ["name"]}}})
    kept, redacted = policy.filter_fields("default", "res.partner", ["id", "x"])
    assert "id" in kept
    assert redacted == ["x"]


def test_wildcard_merges_with_specific_deny():
    policy = make(
        {
            "default": {
                "res.partner": {"deny": ["credit_limit"]},
                "*": {"deny": ["message_ids"]},
            }
        }
    )
    kept, redacted = policy.filter_fields(
        "default", "res.partner", ["name", "credit_limit", "message_ids"]
    )
    assert kept == ["name"]
    assert sorted(redacted) == ["credit_limit", "message_ids"]
    # Wildcard also applies to a model with no specific rule.
    kept2, redacted2 = policy.filter_fields(
        "default", "sale.order", ["name", "message_ids"]
    )
    assert kept2 == ["name"] and redacted2 == ["message_ids"]


def test_wildcard_deny_merges_into_a_model_whose_rule_is_an_allow():
    """The shape the shipped policy relies on: whitelist model + '*' deny.

    A model with an ``allow`` rule already redacts anything outside the
    whitelist, so the wildcard adds nothing there -- but the merge must not
    drop the whitelist either. Both controls have to survive.
    """
    policy = make(
        {
            "default": {
                "hr.employee": {"allow": ["name", "work_email"]},
                "*": {"deny": ["partner_bank_id"]},
            }
        }
    )
    kept, redacted = policy.filter_fields(
        "default", "hr.employee", ["name", "work_email", "work_phone", "partner_bank_id"]
    )
    assert kept == ["name", "work_email"]
    assert sorted(redacted) == ["partner_bank_id", "work_phone"]


def test_wildcard_allow_intersects_with_specific_allow():
    """Two whitelists merge by intersection -- the stricter one wins."""
    policy = make(
        {
            "default": {
                "res.partner": {"allow": ["name", "email", "phone"]},
                "*": {"allow": ["name", "email", "ref"]},
            }
        }
    )
    kept, redacted = policy.filter_fields(
        "default", "res.partner", ["name", "email", "phone", "ref"]
    )
    assert kept == ["name", "email"]
    assert sorted(redacted) == ["phone", "ref"]
    # A model with no specific rule falls back to the wildcard whitelist alone.
    kept2, redacted2 = policy.filter_fields(
        "default", "sale.order", ["name", "ref", "phone"]
    )
    assert kept2 == ["name", "ref"] and redacted2 == ["phone"]


def test_wildcard_deny_applies_to_a_model_with_no_rule_of_its_own():
    """The whole point of the data-class rule: models nobody enumerated."""
    policy = make({"default": {"*": {"deny": ["partner_bank_id"]}}})
    kept, redacted = policy.filter_fields(
        "default",
        "account.bank.statement.line",
        ["id", "amount", "partner_bank_id"],
    )
    assert kept == ["id", "amount"]
    assert redacted == ["partner_bank_id"]


def test_id_is_kept_even_when_no_merged_rule_admits_it():
    """ALWAYS_KEPT wins over both halves of the merge."""
    assert ALWAYS_KEPT == frozenset({"id"})
    policy = make(
        {
            "default": {
                "hr.employee": {"allow": ["name"]},
                "*": {"deny": ["id", "partner_bank_id"]},
            }
        }
    )
    kept, redacted = policy.filter_fields(
        "default", "hr.employee", ["id", "name", "partner_bank_id"]
    )
    assert kept == ["id", "name"]
    assert redacted == ["partner_bank_id"]
    # ...and on a model that only the wildcard covers.
    kept2, _ = policy.filter_fields("default", "sale.order", ["id"])
    assert kept2 == ["id"]


def test_instances_are_isolated():
    policy = make({"a": {"res.partner": {"deny": ["x"]}}})
    # Instance 'b' has no rules -> pass-through.
    kept, redacted = policy.filter_fields("b", "res.partner", ["x", "y"])
    assert kept == ["x", "y"] and redacted == []
    kept_a, redacted_a = policy.filter_fields("a", "res.partner", ["x", "y"])
    assert kept_a == ["y"] and redacted_a == ["x"]


def test_redact_record_drops_keys():
    policy = make({"default": {"res.partner": {"deny": ["credit_limit"]}}})
    record = {"id": 1, "name": "Acme", "credit_limit": 5000}
    filtered, redacted = policy.redact_record("default", "res.partner", record)
    assert filtered == {"id": 1, "name": "Acme"}
    assert redacted == ["credit_limit"]


def test_redact_records_aggregates_names():
    policy = make({"default": {"res.partner": {"deny": ["credit_limit"]}}})
    records = [
        {"id": 1, "credit_limit": 1},
        {"id": 2, "credit_limit": 2, "name": "x"},
    ]
    out, redacted = policy.redact_records("default", "res.partner", records)
    assert all("credit_limit" not in r for r in out)
    assert redacted == ["credit_limit"]


def test_check_aggregate_blocks_denied_field():
    policy = make({"default": {"account.move.line": {"deny": ["balance"]}}})
    err = policy.check_aggregate("default", "account.move.line", ["partner_id", "balance"])
    assert err is not None and "balance" in err
    assert policy.check_aggregate("default", "account.move.line", ["partner_id"]) is None


def test_restricted_fields_for_metadata_marking():
    policy = make({"default": {"res.partner": {"deny": ["credit_limit"]}}})
    restricted = policy.restricted_fields(
        "default", "res.partner", ["name", "credit_limit"]
    )
    assert restricted == ["credit_limit"]


@pytest.mark.parametrize(
    "acl",
    [
        {"default": {"res.partner": {"deny": ["a"], "allow": ["b"]}}},  # both
        {"default": {"res.partner": {}}},  # neither
        {"default": {"res.partner": {"deny": "notalist"}}},
        {"default": {"res.partner": {"deny": [1, 2]}}},
        {"default": {"res.partner": "notdict"}},
        {"default": "notdict"},
        # A malformed wildcard fails closed like any other model key: it is the
        # broadest rule in the file, so it is the worst one to load silently.
        {"default": {"*": {"deny": ["a"], "allow": ["b"]}}},
        {"default": {"*": {}}},
        {"default": {"*": {"deny": "notalist"}}},
        {"default": {"*": {"deny": [None]}}},
    ],
)
def test_malformed_policies_fail_closed(acl):
    with pytest.raises(FieldPolicyError):
        make(acl)


def test_field_acl_not_object_fails():
    with pytest.raises(FieldPolicyError):
        _parse_field_policy({"field_acl": ["nope"]})


def test_load_no_file_is_inactive(monkeypatch, tmp_path):
    monkeypatch.delenv("ODOO_MCP_FIELD_POLICY_FILE", raising=False)
    monkeypatch.delenv("ODOO_MCP_POLICY_FILE", raising=False)
    monkeypatch.chdir(tmp_path)
    reset_field_policy()
    policy = load_field_policy()
    assert policy.active() is False


def test_load_from_dedicated_file(monkeypatch, tmp_path):
    pf = tmp_path / "field_policy.json"
    pf.write_text(json.dumps({"field_acl": {"default": {"res.partner": {"deny": ["x"]}}}}))
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(pf))
    reset_field_policy()
    try:
        policy = load_field_policy()
        assert policy.active() is True
        _, redacted = policy.filter_fields("default", "res.partner", ["x", "y"])
        assert redacted == ["x"]
    finally:
        reset_field_policy()


def test_load_malformed_file_raises(monkeypatch, tmp_path):
    pf = tmp_path / "bad.json"
    pf.write_text("{ not valid json")
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(pf))
    reset_field_policy()
    try:
        with pytest.raises(FieldPolicyError):
            load_field_policy()
    finally:
        reset_field_policy()


def test_posture_reports_active(monkeypatch, tmp_path):
    pf = tmp_path / "fp.json"
    pf.write_text(json.dumps({"field_acl": {"default": {"*": {"deny": ["x"]}}}}))
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(pf))
    reset_field_policy()
    try:
        posture = field_policy.field_policy_posture()
        assert posture["active"] is True
        assert posture["instances_with_rules"] == 1
    finally:
        reset_field_policy()


# --- the shipped policy, driven through the real filter --------------------
#
# tests/test_shipped_policy.py pins the SHAPE of odoo_mcp_policy.json. These
# pin its BEHAVIOUR: the same file loaded through _parse_field_policy and run
# through filter_fields, which is what the connector actually does. A rule can
# be present and still mask nothing (2026-08-25: acc_number denied while
# display_name carried the number), so structure alone is not evidence.


@pytest.fixture(scope="module")
def shipped():
    data = json.loads(SHIPPED_POLICY_PATH.read_text(encoding="utf-8"))
    return _parse_field_policy(data)


def test_shipped_policy_parses(shipped):
    """A malformed shipped file fails closed and disables the connector."""
    assert shipped.active() is True
    assert shipped.instances() == ["default"]


@pytest.mark.parametrize(
    "model",
    [
        "account.bank.statement.line",
        "account.payment.register",
        "res.partner",
        "sale.order",
    ],
)
def test_bank_fields_are_denied_on_every_model(shipped, model):
    """The data-class rule: a bank field is masked wherever it appears.

    Per-model entries only protect the models someone enumerated;
    partner_bank_id was found readable on account.bank.statement.line while it
    was denied on account.payment (2026-09-06).
    """
    _, redacted = shipped.filter_fields(
        "default",
        model,
        [
            "acc_number",
            "bank_acc_number",
            "account_number",
            "partner_bank_id",
            "bank_account_id",
            "employee_bank_account_id",
        ],
    )
    assert sorted(redacted) == [
        "acc_number",
        "account_number",
        "bank_acc_number",
        "bank_account_id",
        "employee_bank_account_id",
        "partner_bank_id",
    ]


def test_public_employee_mirror_is_masked_like_hr_employee(shipped):
    """hr.employee.public exposes the same people through a second model.

    work_phone and job_title were whitelisted away on hr.employee and readable
    on hr.employee.public, which is why this model carries the same 'allow'
    list rather than a deny list of what was noticed.
    """
    kept, redacted = shipped.filter_fields(
        "default",
        "hr.employee.public",
        ["id", "name", "work_email", "department_id", "job_id", "parent_id",
         "work_phone", "job_title", "mobile_phone"],
    )
    assert kept == ["id", "name", "work_email", "department_id", "job_id", "parent_id"]
    assert sorted(redacted) == ["job_title", "mobile_phone", "work_phone"]


def test_public_employee_matches_hr_employee_exactly(shipped):
    """Whatever hr.employee admits, its public mirror admits -- and no more."""
    fields = [
        "name", "work_email", "department_id", "job_id", "parent_id",
        "wage", "private_email", "ssnid", "work_phone", "job_title",
    ]
    assert shipped.filter_fields("default", "hr.employee", fields) == (
        shipped.filter_fields("default", "hr.employee.public", fields)
    )


def test_time_off_description_is_denied(shipped):
    """hr.leave name/private_name are free text where staff write the reason."""
    kept, redacted = shipped.filter_fields(
        "default",
        "hr.leave",
        ["id", "employee_id", "date_from", "state", "name", "private_name"],
    )
    assert kept == ["id", "employee_id", "date_from", "state"]
    assert sorted(redacted) == ["name", "private_name"]


@pytest.mark.parametrize(
    "model,fields",
    [
        ("account.move.line", ["debit", "credit", "balance", "amount_currency"]),
        ("product.product", ["standard_price", "list_price"]),
        ("product.template", ["standard_price", "list_price"]),
        ("sale.order.line", ["margin", "purchase_price", "price_unit"]),
        ("res.partner", ["credit", "debit", "credit_limit"]),
    ],
)
def test_wildcard_did_not_close_the_deliberately_open_fields(shipped, model, fields):
    """2026-08-25: Purchasing and Accounting need these; a wildcard is exactly
    the kind of edit that could take them out company-wide by accident.

    account.analytic.line is deliberately NOT in this list. Its employee_id,
    amount and unit_amount yield a per-employee rate by division and are an
    open question for the owner (fix brief 2026-09-06, section 4), not a field
    set the 2026-08-25 decision ever covered. Pinning it here as settled would
    make the next session argue with a test to implement his ruling."""
    kept, redacted = shipped.filter_fields("default", model, fields)
    assert kept == fields and redacted == []


def test_id_survives_the_shipped_wildcard(shipped):
    for model in ("hr.employee", "hr.employee.public", "hr.leave", "sale.order"):
        kept, _ = shipped.filter_fields("default", model, ["id"])
        assert kept == ["id"], model
