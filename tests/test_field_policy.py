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


def test_empty_allow_closes_a_model_completely():
    """An empty whitelist is the shape used for absence models.

    It is legal (a list of strings, and exactly one of deny/allow), it is
    strictly stricter than any deny list, and it stays correct when Odoo adds
    a field -- which is why the 2026-09-08 absence ruling is expressed this
    way rather than as an enumeration. Pinned because "allow: []" reads like
    a mistake to anyone who has not met this test.
    """
    policy = make({"default": {"hr.leave": {"allow": []}}})
    kept, redacted = policy.filter_fields(
        "default", "hr.leave", ["id", "employee_id", "state", "whatever_odoo_adds"]
    )
    assert kept == ["id"]
    assert sorted(redacted) == ["employee_id", "state", "whatever_odoo_adds"]


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


# --- check_domain: the filter is an inference channel of its own -----------
#
# Output redaction answers "may this seat see the column". It does not answer
# "may this seat ask a question about the column", and a domain is exactly
# that question: filter to one denied value and every column still returned --
# or the bare row count -- becomes the answer. Found by the 2026-09-08
# adversarial review (B3) on six enforcement paths at once.


def test_check_domain_blocks_a_denied_leaf():
    policy = make({"default": {"hr.leave": {"deny": ["employee_id"]}}})
    err = policy.check_domain(
        "default", "hr.leave", [["employee_id", "=", 7], ["state", "=", "validate"]]
    )
    assert err is not None and "employee_id" in err
    assert (
        policy.check_domain("default", "hr.leave", [["state", "=", "validate"]]) is None
    )


def test_check_domain_takes_every_segment_of_a_dotted_path():
    """Every segment is checked, not only the head.

    ``employee_id.name`` reaches the denied field through the relation, and a
    longer path can hop *back* to the model being read, so a denied name
    anywhere along the path refuses the domain. Odoo 17+ rewrites
    ``a.b.c op v`` into ``a any (b any (c op v))``, which this module already
    refused; the two spellings are one query and must check alike.
    """
    policy = make({"default": {"hr.leave": {"deny": ["employee_id"]}}})
    err = policy.check_domain(
        "default", "hr.leave", [["employee_id.name", "ilike", "somebody"]]
    )
    assert err is not None and "employee_id" in err
    # The denied segment is in the middle of the path, not at its head.
    err = policy.check_domain(
        "default", "hr.leave", [["holiday_status_id.employee_id.name", "=", 7]]
    )
    assert err is not None and "employee_id" in err


def test_check_domain_walks_any_subdomains():
    """A sub-domain leaf hides a field name one level down."""
    policy = make({"default": {"account.analytic.line": {"deny": ["employee_id"]}}})
    for operator in ("any", "not any", "ANY", "not any!"):
        err = policy.check_domain(
            "default",
            "account.analytic.line",
            [["account_id", operator, [["employee_id", "=", 7]]]],
        )
        assert err is not None, operator
        assert "employee_id" in err


def test_check_domain_ignores_logic_operators_and_empty_domains():
    policy = make({"default": {"hr.leave": {"deny": ["employee_id"]}}})
    assert policy.check_domain("default", "hr.leave", []) is None
    assert policy.check_domain("default", "hr.leave", None) is None
    assert (
        policy.check_domain(
            "default",
            "hr.leave",
            ["&", ["state", "=", "validate"], "|", ["id", "=", 1], ["id", "=", 2]],
        )
        is None
    )


def test_check_domain_on_an_empty_allow_refuses_everything_but_id():
    """``allow: []`` closes the model, so any domain over it is a question
    about a field the seat may not read. ``id`` is never redactable."""
    policy = make({"default": {"hr.leave": {"allow": []}}})
    assert policy.check_domain("default", "hr.leave", [["id", "in", [1, 2]]]) is None
    err = policy.check_domain(
        "default", "hr.leave", [["date_from", ">=", "2026-01-01"]]
    )
    assert err is not None and "date_from" in err


def test_check_domain_error_text_carries_no_domain_values():
    """The refusal names the model and the field names and nothing else.

    A domain value can be the very content the rule withholds -- a person's
    name in an ilike, an account number in an equals -- so echoing the domain
    back would leak through the error the mask exists to prevent.
    """
    policy = make({"default": {"hr.leave": {"deny": ["employee_id"]}}})
    err = policy.check_domain(
        "default", "hr.leave", [["employee_id.name", "ilike", "Nobody Real"]]
    )
    assert err is not None
    assert "Nobody Real" in str([["employee_id.name", "ilike", "Nobody Real"]])
    assert "Nobody Real" not in err
    assert "ilike" not in err
    assert "hr.leave" in err and "employee_id" in err


def test_check_domain_is_inert_without_a_policy():
    """No policy file, no behaviour change -- the upstream guarantee."""
    policy = FieldPolicy({})
    assert policy.check_domain("default", "hr.leave", [["employee_id", "=", 7]]) is None


def test_check_domain_survives_a_malformed_domain():
    """Domains arrive from a caller; a junk shape must not raise here."""
    policy = make({"default": {"hr.leave": {"deny": ["employee_id"]}}})
    for junk in ("garbage", 7, {"conditions": []}, [None, 3, ["x"]], [[]]):
        assert policy.check_domain("default", "hr.leave", junk) is None


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


@pytest.mark.parametrize(
    "model",
    [
        "hr.leave",
        "hr.leave.report",
        "hr.leave.report.calendar",
        "hr.leave.employee.type.report",
    ],
)
def test_absence_facts_are_withheld_not_just_the_reason(shipped, model):
    """2026-09-08 ruling: the fact of the absence goes, not only the reason.

    This test asserted the opposite until that ruling. It pinned employee_id,
    date_from and state as kept on hr.leave and only the two free-text
    description fields as redacted -- which was the conservative half the
    2026-09-06 brief proposed and the owner declined. The old assertion is
    what an absence leak looks like when it is passing its tests, so the
    reversal is recorded here rather than quietly rewritten.
    """
    kept, redacted = shipped.filter_fields(
        "default",
        model,
        [
            "id",
            "employee_id",
            "date_from",
            "date_to",
            "state",
            "holiday_status_id",
            "number_of_days",
            "name",
            "private_name",
            "display_name",
        ],
    )
    assert kept == ["id"], f"{model} still returns {kept}"
    assert "employee_id" in redacted and "state" in redacted


def test_closure_calendar_keeps_the_closure_and_drops_the_person(shipped):
    """The narrowed absence model: a shop shutdown still reads."""
    kept, redacted = shipped.filter_fields(
        "default",
        "resource.calendar.leaves",
        [
            "id",
            "date_from",
            "date_to",
            "time_type",
            "resource_id",
            "name",
            "holiday_id",
        ],
    )
    assert kept == ["id", "date_from", "date_to", "time_type"]
    assert sorted(redacted) == ["holiday_id", "name", "resource_id"]


@pytest.mark.parametrize(
    "model",
    ["account.analytic.line", "hr.leave.report", "resource.calendar.leaves"],
)
def test_leave_relations_are_redacted_wherever_they_appear(shipped, model):
    """An hr.leave label names the person, the leave type and the duration.

    The policy filters the model being read, not the far end of a relation --
    the same reason a res.partner.bank label had to be denied by field name on
    every model that references it.
    """
    _, redacted = shipped.filter_fields(
        "default", model, ["holiday_id", "leave_id"]
    )
    assert sorted(redacted) == ["holiday_id", "leave_id"]


def test_person_key_fields_are_denied_on_analytic_lines(shipped):
    """employee + hours + cost on one row is a rate one division away.

    The 2026-09-08 review (B1) showed the rate still reachable on this very
    model through ``name`` -- ``mrp_workorder_hr_account`` writes the employee
    name into it as ``[EMPL] <work order> - <employee>`` -- and Dalton ruled
    ``name`` and ``display_name`` denied the same day, knowing it costs every
    analytic-line description on the org bundle. amount and unit_amount stay:
    they are cost analytics, and denying them company-wide would break
    accounting. So a labour line still returns its hours and its money; what
    it no longer returns is any column that says whose they are.
    """
    kept, redacted = shipped.filter_fields(
        "default",
        "account.analytic.line",
        [
            "id",
            "date",
            "amount",
            "unit_amount",
            "account_id",
            "employee_id",
            "user_id",
            "job_title",
            "manager_id",
            "name",
            "display_name",
        ],
    )
    assert kept == ["id", "date", "amount", "unit_amount", "account_id"]
    assert sorted(redacted) == [
        "display_name",
        "employee_id",
        "job_title",
        "manager_id",
        "name",
        "user_id",
    ]


def test_workcenter_rate_is_denied_but_the_work_is_not(shipped):
    """The one model that stores the hourly cost rather than implying it.

    mrp_workorder computes employee_cost from the employee's own hourly_cost
    when one is set, and stores it on the productivity row along with
    total_cost -- so ruling 2 was defeated here without any division at all
    (2026-09-08 review, B2). Dalton denied both figures and kept employee_id
    and duration, because who worked which work order for how long is ops
    data and it was the money that was ruled out.
    """
    kept, redacted = shipped.filter_fields(
        "default",
        "mrp.workcenter.productivity",
        [
            "id",
            "employee_id",
            "workorder_id",
            "duration",
            "employee_cost",
            "total_cost",
        ],
    )
    assert kept == ["id", "employee_id", "workorder_id", "duration"]
    assert sorted(redacted) == ["employee_cost", "total_cost"]


def test_cash_position_presentations_are_denied_on_four_models(shipped):
    """Four models carry it, and one of them is a JSON blob.

    account.journal.kanban_dashboard is computed text carrying the account
    balance, the last statement balance and the outstanding-payment balance
    as formatted currency. Verified read-only against production 2026-09-08:
    returned in full, redacted_fields null. A rule that only covered
    account.bank.statement would have looked complete and left the cash
    position one call away.

    The 2026-09-08 review (B5) found two further one-call paths --
    account.account.current_balance on asset_cash accounts, read on
    production daily by the ops lane, and
    account.bank.statement.line.running_balance -- and Dalton ruled both
    denied. Still "presentations", not "the cash position": a balance:sum
    aggregate over account.move.line filtered to asset_cash accounts reaches
    the same figure through a domain over account_id, which nothing denies,
    and that is pinned open below.
    """
    kept, redacted = shipped.filter_fields(
        "default",
        "account.bank.statement",
        [
            "id",
            "date",
            "journal_id",
            "balance_start",
            "balance_end",
            "balance_end_real",
        ],
    )
    assert kept == ["id", "date", "journal_id"]
    assert sorted(redacted) == ["balance_end", "balance_end_real", "balance_start"]

    kept, redacted = shipped.filter_fields(
        "default",
        "account.journal",
        ["id", "name", "type", "current_statement_balance", "kanban_dashboard"],
    )
    assert kept == ["id", "name", "type"]
    assert sorted(redacted) == ["current_statement_balance", "kanban_dashboard"]

    kept, redacted = shipped.filter_fields(
        "default",
        "account.account",
        ["id", "code", "name", "account_type", "current_balance"],
    )
    assert kept == ["id", "code", "name", "account_type"]
    assert redacted == ["current_balance"]

    kept, redacted = shipped.filter_fields(
        "default",
        "account.bank.statement.line",
        ["id", "date", "amount", "payment_ref", "running_balance"],
    )
    assert kept == ["id", "date", "amount", "payment_ref"]
    assert redacted == ["running_balance"]


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

    account.analytic.line is still deliberately NOT in this list, and now for
    a settled reason rather than an open one: the owner ruled on 2026-09-08
    that employee_id is denied there, and later the same day that name and
    display_name are too. Its amount and unit_amount are pinned as open by
    test_person_key_fields_are_denied_on_analytic_lines instead, which is
    where that trade-off lives."""
    kept, redacted = shipped.filter_fields("default", model, fields)
    assert kept == fields and redacted == []


def test_id_survives_the_shipped_wildcard(shipped):
    for model in ("hr.employee", "hr.employee.public", "hr.leave", "sale.order"):
        kept, _ = shipped.filter_fields("default", model, ["id"])
        assert kept == ["id"], model


def test_shipped_policy_refuses_a_domain_over_a_denied_field(shipped):
    """The two models the 2026-09-08 rulings closed, attacked by domain.

    Both reads below return only fields nobody denied -- dates, hours, cost,
    an id -- so output redaction lets them through untouched. The domain is
    what makes them an answer about a named person, and check_domain is what
    refuses them.
    """
    # Ruling 2's model: group_by and measures are all open fields; the domain
    # is the whole attack (review finding B3, first failing read).
    err = shipped.check_domain(
        "default", "account.analytic.line", [["employee_id", "=", 7]]
    )
    assert err is not None
    assert "account.analytic.line" in err and "employee_id" in err

    # Ruling 1's model: allow: [] closes it, so bisecting a count over dates
    # is refused along with everything else that is not id.
    err = shipped.check_domain(
        "default",
        "hr.leave",
        [
            ["employee_id.name", "ilike", "somebody"],
            ["date_from", ">=", "2026-01-01"],
            ["date_from", "<", "2026-02-01"],
        ],
    )
    assert err is not None and "hr.leave" in err


def test_shipped_policy_still_allows_an_open_domain(shipped):
    """Refusing every domain would be a mask nobody could work with."""
    assert (
        shipped.check_domain(
            "default",
            "account.analytic.line",
            [["date", ">=", "2026-01-01"], ["amount", "<", 0]],
        )
        is None
    )
    assert (
        shipped.check_domain(
            "default",
            "sale.order",
            [["partner_id", "=", 1], ["state", "=", "sale"]],
        )
        is None
    )
    assert shipped.check_domain("default", "hr.leave", [["id", "=", 1]]) is None


def test_shipped_wildcard_denies_holiday_id_as_a_filter(shipped):
    """The wildcard fields are filters as well as columns."""
    err = shipped.check_domain(
        "default", "account.analytic.line", [["holiday_id", "!=", False]]
    )
    assert err is not None and "holiday_id" in err


@pytest.mark.parametrize(
    "model,field",
    [
        ("account.analytic.line", "name"),
        ("account.analytic.line", "display_name"),
        ("mrp.workcenter.productivity", "employee_cost"),
        ("mrp.workcenter.productivity", "total_cost"),
        ("account.account", "current_balance"),
        ("account.bank.statement.line", "running_balance"),
    ],
)
def test_shipped_policy_refuses_a_domain_over_the_2026_09_08_denials(
    shipped, model, field
):
    """A denied column is a denied question, on the fields ruled that day.

    Every read below returns nothing but open columns -- an id, a date, an
    amount -- so output redaction lets it through untouched. The domain is
    what turns it into an answer about the denied field: ``name ilike
    '[EMPL]'`` on analytic lines isolates the labour rows whose description
    names a person, and ``current_balance > 0`` bisects a balance without
    ever selecting it. check_domain is what refuses them (review finding B3).
    """
    err = shipped.check_domain("default", model, [[field, "!=", False]])
    assert err is not None, f"a domain over {field} on {model} was allowed"
    assert model in err and field in err


def test_shipped_policy_refuses_a_dotted_domain_into_a_denied_analytic_field(
    shipped,
):
    """The dotted path is not a way round it either."""
    err = shipped.check_domain(
        "default", "account.analytic.line", [["name", "ilike", "[EMPL] WO"]]
    )
    assert err is not None and "name" in err


def test_the_cash_aggregate_the_rulings_leave_open_is_still_open(shipped):
    """Pinned as open so nobody reads the four denies as more than they are.

    balance:sum over account.move.line, filtered by account_id to the cash
    accounts, reaches the same figure. account_id is not denied on that
    model, so check_domain does not refuse it and check_aggregate does not
    either. If that is ever closed it will be a new ruling; until then this
    test is the honest statement of what ruling 3 achieved.
    """
    assert (
        shipped.check_domain(
            "default",
            "account.move.line",
            [["account_id.account_type", "=", "asset_cash"]],
        )
        is None
    )
    assert (
        shipped.check_aggregate(
            "default", "account.move.line", ["account_id", "balance"]
        )
        is None
    )


# --- B-1: the dotted spelling of a sub-domain, and the depth cap -----------
#
# Second adversarial review, 2026-09-08 (finding B-1). check_domain refused
# the `any`-chain spelling of a loop-back query but passed the dotted one,
# and returned an empty segment list past MAX_DOMAIN_DEPTH -- so on the two
# models the rulings closed, a denied field was still usable as a filter in
# one call. Every segment of a dotted path is now attributed to the outer
# model, and an over-deep domain is refused rather than checked to the cap.


def test_shipped_policy_refuses_a_dotted_loop_back_to_denied_productivity_cost(
    shipped,
):
    """The productivity model, reached back through its own work order.

    ``workorder_id.time_ids`` returns to mrp.workcenter.productivity, so
    ``workorder_id.time_ids.employee_cost > X`` filtered to one person is a
    threshold question about a denied stored column, answered by the row
    count alone. Written as ``workorder_id any (time_ids any (employee_cost
    ...))`` it was already refused; the dotted form was not.
    """
    err = shipped.check_domain(
        "default",
        "mrp.workcenter.productivity",
        [
            ["employee_id", "=", 7],
            ["workorder_id.time_ids.employee_cost", ">", 30],
        ],
    )
    assert err is not None
    assert "mrp.workcenter.productivity" in err and "employee_cost" in err


def test_shipped_policy_refuses_a_dotted_loop_back_to_denied_analytic_fields(
    shipped,
):
    """The analytic model, reached back through its own account.

    ``account_id.line_ids`` returns to account.analytic.line, so both of
    these ask about a field denied on the model being read: the labour-row
    description and the person link.
    """
    err = shipped.check_domain(
        "default",
        "account.analytic.line",
        [["account_id.line_ids.name", "ilike", "somebody"], ["date", "=", "2026-01-02"]],
    )
    assert err is not None
    assert "account.analytic.line" in err and "name" in err

    err = shipped.check_domain(
        "default",
        "account.analytic.line",
        [["account_id.line_ids.employee_id", "=", 7]],
    )
    assert err is not None and "employee_id" in err


def test_check_domain_refuses_a_domain_nested_past_the_depth_cap(shipped):
    """Padding a chain past MAX_DOMAIN_DEPTH must not buy a pass.

    Nine alternating ``any`` levels put ``employee_id`` below the cap, where
    the walk used to stop and return what it had -- nothing denied. Odoo
    collapses the chain to the one-level loop-back and answers it, so the
    only safe reading of a domain the policy cannot walk to the bottom is a
    refusal.
    """
    domain = [["employee_id", "=", 7]]
    for step in range(9):
        field = "account_id" if step % 2 == 0 else "line_ids"
        domain = [[field, "any", domain]]
    err = shipped.check_domain("default", "account.analytic.line", domain)
    assert err is not None
    assert "account.analytic.line" in err
    assert str(field_policy.MAX_DOMAIN_DEPTH) in err
    # No domain value is echoed back, on this path either.
    assert "7" not in err.replace(str(field_policy.MAX_DOMAIN_DEPTH), "")
    # An unpoliced model stays pass-through, depth included: no policy file,
    # no behaviour change.
    assert FieldPolicy({}).check_domain("default", "account.analytic.line", domain) is None


def test_every_segment_attribution_over_refuses_a_far_model_field(shipped):
    """The accepted cost of attributing every segment to the outer model.

    ``partner_id.name`` on account.analytic.line asks for the *partner's*
    name, which no ruling denied -- but ``name`` is denied on the model being
    read, and resolving the comodel would need an Odoo read on the refusal
    path. So it is refused. Over-refusing is the fail-closed direction and
    this test is the honest statement of what it costs.
    """
    err = shipped.check_domain(
        "default", "account.analytic.line", [["partner_id.name", "ilike", "acme"]]
    )
    assert err is not None and "name" in err
