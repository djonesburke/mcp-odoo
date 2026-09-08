"""The policy file Burke actually ships must keep masking what it claims to.

``odoo_mcp_policy.json`` is not a fixture -- it is the file vendored into the
team's `.mcpb` bundle, and it is the only thing standing between a Claude
connection and Odoo payroll. Not because Odoo is permissive by accident: every
current holder of that connection carries Odoo's Employees/Administrator and
Payroll/Officer groups, so Odoo itself would answer a wage query. Until
SERVICE-USERS.md is applied and Odoo groups become the real boundary, this file
is the boundary.

On 2026-08-25 the commercial masks (margin, cost, partner credit) were removed
deliberately, because Purchasing and Accounting need those numbers to work.
That edit is exactly the shape of edit that could take the HR masks with it --
same file, same session, one model too many in the delete. These tests pin the
part that was never up for discussion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

POLICY_PATH = Path(__file__).resolve().parent.parent / "odoo_mcp_policy.json"


@pytest.fixture(scope="module")
def acl() -> dict:
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    default = policy["field_acl"]["default"]
    assert default, "field_acl.default is empty: every mask is off"
    return default


# --- what must stay masked -------------------------------------------------


def test_employee_model_is_an_exclusive_whitelist(acl):
    """A deny list would leak any PII field a future Odoo adds."""
    rule = acl.get("hr.employee")
    assert rule is not None, "hr.employee is unmasked"
    assert "allow" in rule, "hr.employee must be a whitelist, not a deny list"
    assert "wage" not in rule["allow"]
    assert "private_email" not in rule["allow"]


@pytest.mark.parametrize(
    "field",
    ["wage", "contract_wage", "ssnid", "passport_id", "birthday", "private_street"],
)
def test_pay_and_pii_denied_on_contract_model(acl, field):
    rule = acl.get("hr.version")
    assert rule is not None, "hr.version is unmasked: wages are readable"
    assert field in rule.get("deny", []), f"hr.version.{field} is no longer masked"


@pytest.mark.parametrize("field", ["acc_number", "sanitized_acc_number"])
def test_bank_account_numbers_denied(acl, field):
    rule = acl.get("res.partner.bank")
    assert rule is not None, "res.partner.bank is unmasked"
    assert field in rule.get("deny", [])


def test_masked_set_is_exactly_this(acl):
    """The masked set is closed. Both directions are load-bearing.

    An addition restricts a connection whose point is reading the business, so
    it should be a decision. A removal is how a leak reopens. res.users.apikeys
    came out on 2026-08-25 after checking production: seven fields, no key
    material, because Odoo stores the key hashed.

    2026-09-06 added three keys, each a decision: '*' (see
    test_wildcard_is_exactly_this_set), hr.employee.public -- which mirrors
    hr.employee and was handing over work_phone and job_title that
    hr.employee withholds -- and hr.leave, whose private_name is a free-text
    reason field.

    2026-09-08 added seven keys on three rulings by the owner, then three
    more the same day: an adversarial review found two of those rulings
    defeated on models nobody had listed, and the owner ruled on each.
    Absence: the three report models that mirror hr.leave, each carrying the
    employee link, the dates, the type and the state on its own rows, plus
    resource.calendar.leaves, which is the same data wearing the
    company-closure calendar's clothes. Derived pay: account.analytic.line,
    and mrp.workcenter.productivity, which stores the person's hourly cost
    outright rather than leaving it to be derived. Cash position:
    account.bank.statement and account.journal, plus the two presentations
    the review found still one call away -- account.account.current_balance
    and account.bank.statement.line.running_balance.
    """
    assert set(acl) == {
        "*",
        "hr.employee",
        "hr.employee.public",
        "hr.leave",
        "hr.leave.report",
        "hr.leave.report.calendar",
        "hr.leave.employee.type.report",
        "resource.calendar.leaves",
        "hr.version",
        "res.partner.bank",
        "hr.applicant",
        "hr.bank.account.allocation.wizard.line",
        "account.payment",
        "account.move",
        "account.batch.payment",
        "account.analytic.line",
        "mrp.workcenter.productivity",
        "account.bank.statement",
        "account.bank.statement.line",
        "account.account",
        "account.journal",
        "res.partner",
    }


def test_bank_display_name_is_denied(acl):
    """The account number lives in the label, not only in acc_number.

    Verified against production 2026-08-25: res.partner.bank display names read
    "1017033567 - CO Bank". Denying acc_number while leaving display_name open
    masks nothing, and it looked masked for a week.
    """
    assert "display_name" in acl["res.partner.bank"]["deny"]


@pytest.mark.parametrize(
    "model", ["account.payment", "account.move", "account.batch.payment"]
)
def test_bank_reference_fields_are_denied(acl, model):
    """A many2one carries its target's display name with it.

    ``account.payment.partner_bank_id`` returned
    ``[63, "731201737 - JPMorgan Chase Bank, N.A."]`` -- the full number, on a
    model that had no bank rule at all. Field-level masking does not follow
    relations, so every referencing field has to be named here. This list is
    the ones found; it is not a proof of completeness, which is why
    SERVICE-USERS.md exists.
    """
    assert "partner_bank_id" in acl[model]["deny"]


def test_recruitment_compensation_is_denied(acl):
    """hr.applicant carries pay data outside the contract model."""
    denied = acl["hr.applicant"]["deny"]
    for field in ("salary_expected", "salary_proposed"):
        assert field in denied


# --- the three 2026-09-08 rulings ------------------------------------------


@pytest.mark.parametrize(
    "model",
    [
        "hr.leave",
        "hr.leave.report",
        "hr.leave.report.calendar",
        "hr.leave.employee.type.report",
    ],
)
def test_absence_models_are_closed_whitelists(acl, model):
    """Ruling: withhold absence facts, not only the free-text reason.

    An empty 'allow' is the only shape that holds. A deny list would have to
    enumerate employee_id, the two date pairs, state, the type, the duration
    and the display name -- and would still hand over whatever absence field
    the next Odoo adds, on a model whose entire purpose is recording that a
    named person was away. The previous rule denied two fields and left the
    other six readable, which is how this ruling came to be needed.

    The three report models are here because they are hr.leave read a second
    way. Nobody had looked at them; they were found by listing every model
    whose name starts with the masked one's.
    """
    rule = acl.get(model)
    assert rule is not None, f"{model} is unmasked: absence facts are readable"
    assert "allow" in rule, f"{model} must be a whitelist, not a deny list"
    assert rule["allow"] == [], (
        f"{model} admits {rule['allow']}. Nothing on an absence model is "
        "readable through the org connector; 'id' is returned regardless."
    )


def test_leave_relations_are_denied_everywhere(acl):
    """The absence fact travels in a many2one's label, like a bank number."""
    for field in ("holiday_id", "leave_id"):
        assert field in acl["*"]["deny"], (
            f"{field} points at hr.leave, whose label names the person, the "
            "kind of leave and the duration"
        )


def test_closure_calendar_hides_the_person_not_the_closure(acl):
    """resource.calendar.leaves is two things in one model.

    With no resource_id it is a company closure -- a shop shutdown week, which
    is not personnel material and which Purchasing has reason to read. With a
    resource_id it is one named person's approved time off, written there by
    hr_holidays. So this is the one absence model that is narrowed rather than
    closed: the person goes, the closure stays.
    """
    denied = acl["resource.calendar.leaves"]["deny"]
    assert set(denied) == {"resource_id", "name", "display_name"}
    for readable in ("date_from", "date_to", "time_type", "calendar_id"):
        assert readable not in denied, (
            f"{readable} is how a company closure is read; denying it would "
            "close the calendar as well as the person"
        )


def test_person_key_fields_are_denied_on_analytic_lines(acl):
    """Ruling: deny employee_id on analytic lines, plus the 2026-09-08 follow-up.

    employee_id plus unit_amount plus amount on one row is a rate per person
    per hour, one division away, and hr.version.wage being masked does not
    help. amount and unit_amount stay -- they are cost analytics and denying
    them company-wide would break accounting -- so the attribution is what
    goes.

    user_id, job_title and manager_id go with employee_id because the ruling
    is about the rate not being computable, and employee_id alone does not
    achieve that: user_id names the same person through res.users, and
    job_title is a related field reaching the hr.employee field the
    hr.employee whitelist already withholds.

    name and display_name were added on 2026-09-08 after the adversarial
    review (B1) showed the ruling defeated on this very model:
    mrp_workorder_hr_account writes "[EMPL] <work order> - <employee>" into
    ``name``, so the description carries the person even with every id field
    denied, and an analytic line's display_name is its name. Dalton took the
    trade-off knowingly -- every analytic-line description now disappears for
    every holder of the org bundle, not only the labour ones. That cost is
    the reason this is a ruling and not a fix, and the reason it is pinned
    here: re-opening it is a decision, not a cleanup.
    """
    denied = set(acl["account.analytic.line"]["deny"])
    assert denied == {
        "employee_id",
        "user_id",
        "job_title",
        "manager_id",
        "name",
        "display_name",
    }
    assert "amount" not in denied and "unit_amount" not in denied, (
        "cost analytics stay readable; it is the per-person attribution that "
        "was ruled out, not the cost"
    )


def test_workcenter_productivity_denies_the_rate_not_the_work(acl):
    """Ruling 2026-09-08: deny employee_cost and total_cost, nothing else.

    mrp_workorder stores employee_cost on this model as the employee's own
    hourly_cost when one is set, falling back to the workcenter rate -- so it
    is the rate itself, not a figure derived from hours and money on the same
    row. total_cost is that rate times duration, which gives it back.

    employee_id and duration stay readable on purpose: who worked which work
    order and for how long is ops data Purchasing and production legitimately
    read, and the ruling was about the money on the row.
    """
    rule = acl.get("mrp.workcenter.productivity")
    assert rule is not None, "the stored per-person hourly cost is unmasked"
    assert set(rule["deny"]) == {"employee_cost", "total_cost"}
    for readable in ("employee_id", "duration", "workorder_id", "workcenter_id"):
        assert readable not in rule["deny"], (
            f"{readable} is how work is attributed to a work order; the ruling "
            "denied the rate, not the record of the work"
        )


def test_cash_position_presentations_are_denied(acl):
    """Ruling: narrow Burke's cash position to the owner and Accounting.

    Named "presentations", because that is all a field rule can deny. This
    file has no per-seat notion -- field_acl is keyed on Odoo instance and the
    policy ships inside the published bundle -- so the narrowing is a deny on
    the shared org policy. Restoring these reads for those two seats means a
    second policy file and bundle, which is separate work in
    burke-mcp-deploy and has to land first if the ruling is to mean "narrow"
    rather than "deny to all".

    The journal half is the half that matters and was nearly missed.
    account.bank.statement carries the three balances the survey named, but
    kanban_dashboard on account.journal is a computed JSON string that
    carries the account balance, the last statement balance and the
    outstanding-payment balance as formatted currency -- verified read-only
    against production 2026-09-08, returned in full with redacted_fields
    null. Denying the statement model alone would have left the whole cash
    position readable in one call on the journal.

    The 2026-09-08 review (B5) then found two more one-call paths, and the
    owner ruled both denied: account.account.current_balance on asset_cash
    accounts, which the ops lane reads on production daily, and
    account.bank.statement.line.running_balance, whose latest row is the bank
    balance. What stays open is the aggregate -- a balance:sum over
    account.move.line filtered to asset_cash accounts reaches the same figure
    through a domain over account_id, which is not a denied field -- so this
    test still claims presentations, not the cash position.
    """
    assert set(acl["account.bank.statement"]["deny"]) == {
        "balance_start",
        "balance_end",
        "balance_end_real",
    }
    assert set(acl["account.journal"]["deny"]) == {
        "current_statement_balance",
        "kanban_dashboard",
        "kanban_dashboard_graph",
    }
    assert set(acl["account.bank.statement.line"]["deny"]) == {"running_balance"}
    assert set(acl["account.account"]["deny"]) == {"current_balance"}
    assert "balance" not in acl.get("account.move.line", {}).get("deny", []), (
        "the general ledger stays open by decision; denying balance here "
        "would be a new ruling, not the 2026-09-08 one"
    )


def test_absence_is_not_in_the_public_employee_whitelist(acl):
    """The ruling names hr.employee.public too; the whitelist already holds.

    hr_holidays adds is_absent, leave_date_from, leave_date_to and
    current_leave_state to the public mirror. They are withheld today because
    the rule is an exclusive whitelist rather than a list of what someone
    noticed -- which is the argument for whitelists, made in advance and
    surviving a ruling written two days later. Pinned so a "just add one
    field" edit has to argue with a test.
    """
    for model in ("hr.employee", "hr.employee.public"):
        allowed = set(acl[model]["allow"])
        for field in (
            "is_absent",
            "leave_date_from",
            "leave_date_to",
            "current_leave_state",
            "current_leave_id",
            "holiday_id",
            "leave_id",
        ):
            assert field not in allowed, f"{model} admits {field}"


# --- what is deliberately open ---------------------------------------------


def test_wildcard_is_exactly_this_set(acl):
    """A '*' rule masks a field on every model at once, so it stays pinned.

    This test used to assert no wildcard existed. That was right for the rule
    it was written against: the old '*' carried a deny on message_ids, which
    read as a privacy control and was not one -- mail.message is readable
    directly, so all it bought was a smaller payload. It was removed
    2026-08-25 and the tripwire put in its place.

    It came back 2026-09-06 for the opposite reason, and the earlier premise --
    that a wildcard is almost never what someone editing one model's rule
    intended -- no longer holds for this one. A survey that day found the same
    data class masked on one model and readable on another three separate
    times: partner_bank_id denied on account.payment and returned on
    account.bank.statement.line; work_phone and job_title withheld by
    hr.employee and handed over by hr.employee.public; and bank account
    numbers reachable through account.journal.bank_acc_number, a related field
    pointing at the very field res.partner.bank denies. A per-model list
    cannot protect a data class, because the class is reachable from every
    model that mirrors or joins to it.

    So the tripwire is kept and re-aimed rather than deleted. The wildcard is
    pinned to exactly the bank-account field names. The last two were missed on
    the first pass and caught on review: a many2one to res.partner.bank returns
    the account number in its label, so every relation to that model leaks
    whatever it is named, and account.journal.bank_account_id and
    account.move.line.employee_bank_account_id are two such relations. That is
    the same fault this wildcard exists to close, committed once more while
    closing it -- which is why the set is pinned here and not left to whoever
    edits the policy next. Any other wildcard deny --
    and in particular any wildcard on a business field like amount, balance or
    margin, which would break Purchasing and Accounting company-wide -- still
    trips this test, which is what the original guard was for.

    It now carries a second data class, on the 2026-09-08 ruling that the fact
    of a named person's absence is withheld and not only the written reason.
    holiday_id and leave_id are relations to hr.leave, and an hr.leave label
    reads as a named person on a named kind of leave for a stated duration --
    so the label is the absence fact, exactly as a res.partner.bank label is
    the account number. Masking hr.leave itself does nothing about a many2one
    to it read from account.analytic.line, hr.leave.report or
    resource.calendar.leaves, because the policy filters the model being read,
    not the model on the far end of the relation.

    display_name was considered for this set on 2026-09-08, when name and
    display_name were denied on account.analytic.line, and deliberately kept
    out. The two entries above are distinctive names that mean one data class
    wherever Odoo puts them; display_name means "the label" on every model
    there is, so a wildcard entry would take every many2one label on the
    connector with it -- a company-wide outage, not a narrowing, and exactly
    the accident the paragraph above says this test exists to catch. The
    relation leak it would have closed barely exists here: the only many2one
    to account.analytic.line in the Odoo 19 enterprise tree is timesheet_id
    on hr.timesheet.stop.timer.confirmation.wizard, a transient with no
    stored rows to search, and an x2many such as analytic_line_ids returns
    ids rather than labels.
    """
    rule = acl.get("*")
    assert rule is not None, (
        "the wildcard rule is gone: it is what keeps a masked data class from "
        "leaking through any model that mirrors or joins to it"
    )
    assert set(rule) == {"deny"}, "the wildcard must be a deny rule, never an allow"
    assert set(rule["deny"]) == {
        "acc_number",
        "bank_acc_number",
        "account_number",
        "partner_bank_id",
        "bank_account_id",
        "employee_bank_account_id",
        "holiday_id",
        "leave_id",
    }, (
        "the wildcard deny set changed: it masks a field across every model, so "
        "anything added here is company-wide by construction and deserves to be "
        "noticed"
    )


@pytest.mark.parametrize(
    "model", ["sale.order", "sale.order.line", "product.template", "product.product"]
)
def test_commercial_models_are_not_masked(acl, model):
    """Reopening these would silently undo a decision, not restore a default.

    Pinned in the same direction as the HR rules so that a well-meaning
    "tighten everything back up" has to argue with a failing test first.
    """
    assert model not in acl, (
        f"{model} is masked again. Cost and margin were opened deliberately on "
        "2026-08-25; re-masking them needs its own decision."
    )
