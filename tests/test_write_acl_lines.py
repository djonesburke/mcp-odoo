"""Tests for the record-scope parts of ``write_acl``: pinned create context,
``record_domain`` and one2many line commands.

These pin the draft-vendor-bill shape: a create must pin ``default_move_type``
to an allowed value and may not set it any other way; a write touches only
records the domain matches, read from Odoo, failing closed on a read error;
line commands are create (0) and update (1) only, with line fields limited,
and an update must name lines of the touched records.
"""

import pytest

from odoo_mcp.write_acl import WriteAclError, check_guards, parse_write_acl

LINE_FIELDS = ["product_id", "name", "quantity", "price_unit"]

POLICY = {
    "write_acl": {
        "default": {
            "account.move": {
                "operations": {
                    "create": {
                        "fields": ["partner_id", "ref", "invoice_line_ids"],
                        "max_records": 20,
                    },
                    "write": {
                        "fields": ["partner_id", "ref", "invoice_line_ids"],
                        "max_records": 20,
                    },
                },
                "create_context": {"default_move_type": ["in_invoice", "in_refund"]},
                "record_domain": [
                    ["move_type", "in", ["in_invoice", "in_refund"]],
                    ["state", "=", "draft"],
                ],
                "one2many": {
                    "invoice_line_ids": {
                        "comodel": "account.move.line",
                        "inverse": "move_id",
                        "fields": LINE_FIELDS,
                    }
                },
            }
        }
    }
}

# id -> (move_type, state)
MOVES = {
    1: ("in_invoice", "draft"),
    2: ("in_refund", "draft"),
    3: ("in_invoice", "posted"),
    4: ("out_invoice", "draft"),
}
# line id -> move id
LINES = {11: 1, 12: 1, 21: 2, 31: 3}


class _Odoo:
    def __init__(self, fail=False):
        self.fail = fail
        self.calls = []

    def execute_method(self, model, method, *args, **kwargs):
        self.calls.append((model, method, args))
        if self.fail:
            raise RuntimeError("boom")
        if model == "account.move" and method == "search":
            domain = args[0]
            ids = set(domain[0][2])
            types = set(domain[1][2])
            return [
                rid
                for rid, (mtype, state) in MOVES.items()
                if rid in ids and mtype in types and state == "draft"
            ]
        if model == "account.move.line" and method == "read":
            return [
                {"id": lid, "move_id": [LINES[lid], "M"]}
                for lid in args[0]
                if lid in LINES
            ]
        return []


@pytest.fixture
def acl():
    return parse_write_acl(POLICY, "amber.json")


CTX = {"default_move_type": "in_invoice"}


def _write(acl, ids, values, odoo=None):
    refusal = acl.check_write(
        "default", "account.move", "write", values=values, record_ids=ids
    )
    if refusal is None:
        refusal = check_guards(
            acl, odoo or _Odoo(), "default", "account.move", "write", values, ids
        )
    return refusal


# --- create: pinned context -------------------------------------------------


def test_create_with_pinned_move_type_passes(acl):
    values = {"partner_id": 7, "invoice_line_ids": [[0, 0, {"name": "x"}]]}
    assert (
        acl.check_write("default", "account.move", "create", values, context=CTX)
        is None
    )
    assert (
        check_guards(acl, _Odoo(), "default", "account.move", "create", values, None)
        is None
    )


def test_create_refund_type_passes(acl):
    ctx = {"default_move_type": "in_refund"}
    assert (
        acl.check_write("default", "account.move", "create", {"ref": "a"}, context=ctx)
        is None
    )


@pytest.mark.parametrize(
    "ctx",
    [None, {}, {"default_move_type": "out_invoice"}, {"default_move_type": "entry"}],
)
def test_create_without_allowed_move_type_is_refused(acl, ctx):
    refusal = acl.check_write(
        "default", "account.move", "create", {"ref": "a"}, context=ctx
    )
    assert refusal and "default_move_type" in refusal


def test_move_type_and_state_as_values_are_refused(acl):
    for name in ("move_type", "state", "auto_post", "journal_id"):
        refusal = acl.check_write(
            "default", "account.move", "create", {name: "x"}, context=CTX
        )
        assert refusal and name in refusal


def test_pinned_context_key_is_refused_on_write(acl):
    refusal = acl.check_write(
        "default", "account.move", "write", {"ref": "a"}, record_ids=[1], context=CTX
    )
    assert refusal and "context keys" in refusal


def test_other_default_context_on_create_is_refused(acl):
    ctx = dict(CTX, default_state="posted")
    refusal = acl.check_write(
        "default", "account.move", "create", {"ref": "a"}, context=ctx
    )
    assert refusal and "default_state" in refusal


def test_values_list_create_is_counted_and_checked(acl):
    many = [{"ref": str(i)} for i in range(21)]
    refusal = acl.check_write(
        "default", "account.move", "create", values_list=many, context=CTX
    )
    assert refusal and "20-record limit" in refusal
    refusal = acl.check_write(
        "default",
        "account.move",
        "create",
        values_list=[{"state": "posted"}],
        context=CTX,
    )
    assert refusal and "state" in refusal


# --- write: record_domain ---------------------------------------------------


def test_write_on_draft_vendor_bills_passes(acl):
    assert _write(acl, [1, 2], {"ref": "new"}) is None


@pytest.mark.parametrize("ids", [[3], [4], [1, 3], [99]])
def test_write_on_posted_customer_or_missing_record_is_refused(acl, ids):
    refusal = _write(acl, ids, {"ref": "new"})
    assert refusal and "outside" in refusal


def test_record_scope_read_error_refuses(acl):
    refusal = _write(acl, [1], {"ref": "new"}, odoo=_Odoo(fail=True))
    assert refusal and "could not be" in refusal


def test_write_without_ids_is_refused(acl):
    refusal = check_guards(
        acl, _Odoo(), "default", "account.move", "write", {"ref": "a"}, []
    )
    assert refusal and "must name its records" in refusal


def test_record_scope_domain_is_sent_with_ids(acl):
    odoo = _Odoo()
    _write(acl, [1], {"ref": "new"}, odoo=odoo)
    model, method, args = odoo.calls[0]
    assert (model, method) == ("account.move", "search")
    assert args[0][0] == ["id", "in", [1]]
    assert ["state", "=", "draft"] in args[0]


# --- one2many line commands -------------------------------------------------


def test_line_create_and_update_on_own_lines_pass(acl):
    values = {
        "invoice_line_ids": [
            [0, 0, {"product_id": 5, "quantity": 2, "price_unit": 1.5}],
            [1, 11, {"quantity": 3}],
            (1, 12, {"name": "y"}),
        ]
    }
    assert _write(acl, [1], values) is None


def test_line_update_on_another_bill_is_refused(acl):
    values = {"invoice_line_ids": [[1, 21, {"quantity": 3}]]}
    refusal = _write(acl, [1], values)
    assert refusal and "do not belong" in refusal


def test_line_update_on_unknown_line_is_refused(acl):
    refusal = _write(acl, [1], {"invoice_line_ids": [[1, 999, {"quantity": 3}]]})
    assert refusal and "do not belong" in refusal


def test_line_update_on_posted_bill_line_is_refused(acl):
    refusal = _write(acl, [1, 3], {"invoice_line_ids": [[1, 31, {"quantity": 3}]]})
    assert refusal and "outside" in refusal


@pytest.mark.parametrize(
    "command",
    [
        [2, 11, 0],
        [3, 11, 0],
        [4, 11, 0],
        [5, 0, 0],
        [6, 0, [11]],
        [0, 5, {"name": "x"}],
        [1, True, {"name": "x"}],
        [0, 0, "x"],
        [0, 0],
        "x",
    ],
)
def test_other_line_commands_are_refused(acl, command):
    refusal = acl.check_write(
        "default",
        "account.move",
        "write",
        {"invoice_line_ids": [command]},
        record_ids=[1],
    )
    assert refusal and "line commands" in refusal


def test_line_update_on_create_is_refused(acl):
    refusal = acl.check_write(
        "default",
        "account.move",
        "create",
        {"invoice_line_ids": [[1, 11, {"name": "x"}]]},
        context=CTX,
    )
    assert refusal and "only on a write" in refusal


def test_unlisted_line_field_is_refused(acl):
    for name in ("move_id", "display_type", "debit", "analytic_distribution"):
        refusal = acl.check_write(
            "default",
            "account.move",
            "write",
            {"invoice_line_ids": [[0, 0, {name: 1}]]},
            record_ids=[1],
        )
        assert refusal and name in refusal


def test_lines_not_a_list_is_refused(acl):
    refusal = acl.check_write(
        "default",
        "account.move",
        "write",
        {"invoice_line_ids": {"a": 1}},
        record_ids=[1],
    )
    assert refusal and "line commands" in refusal


# --- parse ------------------------------------------------------------------


def _with(model_rule):
    return {"write_acl": {"default": {"account.move": model_rule}}}


BASE = POLICY["write_acl"]["default"]["account.move"]


@pytest.mark.parametrize(
    "patch",
    [
        {"create_context": {"move_type": ["in_invoice"]}},
        {"create_context": {"default_move_type": []}},
        {"create_context": {"default_move_type": "in_invoice"}},
        {"record_domain": ["|", ["state", "=", "draft"], ["id", ">", 0]]},
        {"record_domain": {"state": "draft"}},
        {"one2many": {"invoice_line_ids": {"comodel": "account.move.line"}}},
        {"one2many": {"line_ids": dict(BASE["one2many"]["invoice_line_ids"])}},
        {
            "one2many": {
                "invoice_line_ids": dict(BASE["one2many"]["invoice_line_ids"], extra=1)
            }
        },
    ],
)
def test_malformed_record_scope_is_rejected(patch):
    with pytest.raises(WriteAclError):
        parse_write_acl(_with(dict(BASE, **patch)))


def test_create_context_needs_a_create_operation():
    rule = dict(BASE, operations={"write": BASE["operations"]["write"]})
    with pytest.raises(WriteAclError):
        parse_write_acl(_with(rule))


def test_rule_without_record_scope_is_unchanged():
    acl = parse_write_acl(
        {
            "write_acl": {
                "default": {
                    "res.partner": {
                        "operations": {"write": {"fields": ["ref"], "max_records": 5}}
                    }
                }
            }
        }
    )
    odoo = _Odoo()
    assert (
        check_guards(acl, odoo, "default", "res.partner", "write", {"ref": "a"}, [1])
        is None
    )
    assert odoo.calls == []
