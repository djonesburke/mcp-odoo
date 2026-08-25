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
    """
    assert set(acl) == {
        "hr.employee",
        "hr.version",
        "res.partner.bank",
        "hr.applicant",
        "hr.bank.account.allocation.wizard.line",
        "account.payment",
        "account.move",
        "account.batch.payment",
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


# --- what is deliberately open ---------------------------------------------


def test_no_wildcard_rule(acl):
    """A '*' rule masks a field on every model at once.

    It carried a deny on message_ids, which read as a privacy control and was
    not one -- mail.message is readable directly, so the only thing it bought
    was a smaller default payload. Anything reintroduced here is company-wide
    by construction and deserves to be noticed.
    """
    assert "*" not in acl, (
        "a wildcard rule is back: it masks a field across every model, which is "
        "almost never what someone editing one model's rule intended"
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
