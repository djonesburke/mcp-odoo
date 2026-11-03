"""Tests for the write-path model and field allowlist (``write_acl``).

``write_acl`` narrows a write-enabled profile to named record classes. These
tests pin: no key means no change; a key governs every instance and an
instance without an entry writes nothing; model, operation, field, record
count and context are each refused when out of scope, on preview, validate
and execute alike; the category guard holds or refuses, and fails closed on a
read error; chatter_post and side-effect methods are refused on a governed
instance; a malformed block refuses every write and aborts startup.
"""

import importlib
import json

import pytest

from odoo_mcp import tools_write
from odoo_mcp.field_policy import reset_field_policy
from odoo_mcp.write_acl import (
    WriteAclError,
    load_write_acl,
    parse_write_acl,
    report_write_acl,
    reset_write_acl_snapshot,
    write_acl_posture,
)
from tests.test_server import FakeCtx

GUARD_FIELDS = ["property_cost_method", "property_valuation_account", "route_ids"]

POLICY = {
    "write_acl": {
        "default": {
            "product.supplierinfo": {
                "operations": {
                    "create": {
                        "fields": ["product_tmpl_id", "partner_id", "price"],
                        "max_records": 3,
                    },
                    "write": {"fields": ["price", "delay"], "max_records": 5},
                }
            },
            "product.template": {
                "operations": {
                    "write": {"fields": ["categ_id", "barcode"], "max_records": 5}
                },
                "guards": [
                    {
                        "field": "categ_id",
                        "comodel": "product.category",
                        "must_match": GUARD_FIELDS,
                    }
                ],
            },
        }
    }
}

CATEGORIES = {
    10: {
        "id": 10,
        "property_cost_method": "standard",
        "property_valuation_account": [5, "Stock"],
        "route_ids": [2, 1],
    },
    11: {
        "id": 11,
        "property_cost_method": "standard",
        "property_valuation_account": [5, "Stock"],
        "route_ids": [1, 2],
    },
    12: {
        "id": 12,
        "property_cost_method": "average",
        "property_valuation_account": [5, "Stock"],
        "route_ids": [1, 2],
    },
}


class _Client:
    """Fake Odoo: fields metadata, guard reads, and a record of every write."""

    def __init__(self, template_categ=None, fail_category_read=False):
        self.template_categ = template_categ or {1: 10, 2: 10}
        self.fail_category_read = fail_category_read
        self.writes = []

    def get_model_fields(self, model):
        names = {
            "price",
            "delay",
            "partner_id",
            "product_tmpl_id",
            "categ_id",
            "barcode",
            "standard_price",
            "name",
        }
        return {name: {"type": "char", "readonly": False} for name in names}

    def execute_method(self, model, method, *args, **kwargs):
        if method in {"create", "write", "unlink", "message_post"}:
            self.writes.append((model, method, args))
            return True
        if method == "read" and model == "product.category":
            if self.fail_category_read:
                raise RuntimeError("boom")
            return [dict(CATEGORIES[cid]) for cid in args[0] if cid in CATEGORIES]
        if method == "read":
            return [
                {
                    "id": rid,
                    "display_name": f"P{rid}",
                    "categ_id": [self.template_categ[rid], "C"],
                }
                for rid in args[0]
                if rid in self.template_categ
            ]
        return []


@pytest.fixture
def policy(monkeypatch, tmp_path):
    def _set(data):
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(path))
        reset_field_policy()
        return path

    monkeypatch.setenv("ODOO_MCP_ENABLE_WRITES", "1")
    monkeypatch.delenv("MCP_CHATTER_DIRECT", raising=False)
    monkeypatch.delenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", raising=False)
    monkeypatch.delenv("ODOO_MCP_REQUIRE_WRITE_ACL", raising=False)
    reset_write_acl_snapshot()
    _set(POLICY)
    yield _set
    reset_write_acl_snapshot()
    reset_field_policy()


def _validate(client, model, operation, **kwargs):
    return tools_write.validate_write(FakeCtx(client), model, operation, **kwargs)


# ---------------------------------------------------------------------------
# Static scope: model, operation, fields, count, context
# ---------------------------------------------------------------------------


def test_no_write_acl_key_changes_nothing(policy):
    policy({"field_acl": {}})
    report = _validate(
        _Client(), "res.partner", "write", values={"name": "x"}, record_ids=[1]
    )
    assert report["success"] is True
    assert load_write_acl().active() is False


def test_in_scope_write_is_validated_and_executes(policy):
    client = _Client()
    ctx = FakeCtx(client)
    report = tools_write.validate_write(
        ctx, "product.supplierinfo", "write", values={"price": 4.5}, record_ids=[1, 2]
    )
    assert report["success"] is True
    assert report["approval_status"]["stored"] is True
    result = tools_write.execute_approved_write(ctx, report["approval"], confirm=True)
    assert result["success"] is True
    assert client.writes == [
        ("product.supplierinfo", "write", ([1, 2], {"price": 4.5}))
    ]


@pytest.mark.parametrize(
    "model, operation, kwargs, needle",
    [
        (
            "res.partner",
            "write",
            dict(values={"name": "x"}, record_ids=[1]),
            "not writable on instance",
        ),
        ("product.supplierinfo", "unlink", dict(record_ids=[1]), "operation 'unlink'"),
        (
            "product.supplierinfo",
            "write",
            dict(values={"price": 1, "standard_price": 2}, record_ids=[1]),
            "['standard_price']",
        ),
        (
            "product.supplierinfo",
            "write",
            dict(values={"price": 1}, record_ids=[1, 2, 3, 4, 5, 6]),
            "6 records exceeds the 5-record limit",
        ),
        (
            "product.supplierinfo",
            "create",
            dict(values_list=[{"price": 1}] * 4),
            "4 records exceeds the 3-record limit",
        ),
        (
            "product.supplierinfo",
            "create",
            dict(values={"product_tmpl_id": 1, "name": "x"}),
            "['name']",
        ),
        (
            "product.supplierinfo",
            "write",
            dict(
                values={"price": 1}, record_ids=[1], context={"tracking_disable": True}
            ),
            "context keys ['tracking_disable']",
        ),
        (
            "product.supplierinfo",
            "create",
            dict(values={"price": 1}, context={"default_name": "x"}),
            "context keys ['default_name']",
        ),
    ],
)
def test_out_of_scope_payload_is_refused_before_any_approval(
    policy, model, operation, kwargs, needle
):
    client = _Client()
    report = _validate(client, model, operation, **kwargs)
    assert report["success"] is False
    assert needle in report["error"]
    assert report["approval_status"]["stored"] is False
    preview = tools_write.preview_write(model, operation, **kwargs)
    assert preview["success"] is False
    assert needle in preview["error"]
    assert "approval" not in preview
    assert client.writes == []


def test_allowed_context_keys_pass(policy):
    report = _validate(
        _Client(),
        "product.supplierinfo",
        "write",
        values={"price": 1},
        record_ids=[1],
        context={"lang": "en_US"},
    )
    assert report["success"] is True


def test_instance_without_an_entry_writes_nothing(policy):
    policy({"write_acl": {"staging": POLICY["write_acl"]["default"]}})
    report = _validate(
        _Client(), "product.supplierinfo", "write", values={"price": 1}, record_ids=[1]
    )
    assert report["success"] is False
    assert "instance 'default'" in report["error"]


def test_execute_rechecks_the_file_as_it_reads_now(policy):
    """A token validated under a wider file must not execute after it narrows."""
    client = _Client()
    ctx = FakeCtx(client)
    report = tools_write.validate_write(
        ctx, "product.supplierinfo", "write", values={"delay": 3}, record_ids=[1]
    )
    assert report["success"] is True
    narrowed = json.loads(json.dumps(POLICY))
    narrowed["write_acl"]["default"]["product.supplierinfo"]["operations"]["write"][
        "fields"
    ] = ["price"]
    policy(narrowed)
    result = tools_write.execute_approved_write(ctx, report["approval"], confirm=True)
    assert result["success"] is False
    assert "['delay']" in result["error"]
    assert client.writes == []


# ---------------------------------------------------------------------------
# Category guard
# ---------------------------------------------------------------------------


def test_guard_allows_a_move_between_equal_categories(policy):
    client = _Client()
    ctx = FakeCtx(client)
    report = tools_write.validate_write(
        ctx, "product.template", "write", values={"categ_id": 11}, record_ids=[1, 2]
    )
    assert report["success"] is True, report.get("error")
    result = tools_write.execute_approved_write(ctx, report["approval"], confirm=True)
    assert result["success"] is True


def test_guard_refuses_a_move_that_changes_a_guarded_field(policy):
    client = _Client()
    report = _validate(
        client, "product.template", "write", values={"categ_id": 12}, record_ids=[1]
    )
    assert report["success"] is False
    assert "['property_cost_method']" in report["error"]
    assert "Ask Dalton" in report["error"]


def test_guard_fails_closed_on_a_read_error(policy):
    report = _validate(
        _Client(fail_category_read=True),
        "product.template",
        "write",
        values={"categ_id": 11},
        record_ids=[1],
    )
    assert report["success"] is False
    assert "could not be checked" in report["error"]


def test_guard_fails_closed_on_an_unreadable_record(policy):
    report = _validate(
        _Client(),
        "product.template",
        "write",
        values={"categ_id": 11},
        record_ids=[1, 99],
    )
    assert report["success"] is False
    assert "could not read categ_id" in report["error"]


def test_guard_refuses_a_record_with_no_current_category(policy):
    client = _Client()
    client.template_categ[3] = False
    report = _validate(
        client, "product.template", "write", values={"categ_id": 11}, record_ids=[1, 3]
    )
    assert report["success"] is False
    assert "have no categ_id now" in report["error"]


def test_guard_fails_closed_on_an_unknown_category(policy):
    report = _validate(
        _Client(), "product.template", "write", values={"categ_id": 77}, record_ids=[1]
    )
    assert report["success"] is False
    assert "[77]" in report["error"]


def test_guard_refuses_a_missing_guard_field(policy):
    data = json.loads(json.dumps(POLICY))
    data["write_acl"]["default"]["product.template"]["guards"][0]["must_match"].append(
        "not_a_field"
    )
    policy(data)
    report = _validate(
        _Client(), "product.template", "write", values={"categ_id": 11}, record_ids=[1]
    )
    assert report["success"] is False
    assert "['not_a_field']" in report["error"]


def test_guard_is_rechecked_at_execute(policy):
    """A product moved to an unequal category after validate must not execute."""
    client = _Client()
    ctx = FakeCtx(client)
    report = tools_write.validate_write(
        ctx, "product.template", "write", values={"categ_id": 11}, record_ids=[1]
    )
    assert report["success"] is True
    client.template_categ[1] = 12
    result = tools_write.execute_approved_write(ctx, report["approval"], confirm=True)
    assert result["success"] is False
    assert client.writes == []


def test_unguarded_field_on_a_guarded_model_reads_nothing(policy):
    report = _validate(
        _Client(fail_category_read=True),
        "product.template",
        "write",
        values={"barcode": "123"},
        record_ids=[1],
    )
    assert report["success"] is True


# ---------------------------------------------------------------------------
# chatter_post and execute_method on a governed instance
# ---------------------------------------------------------------------------


def test_chatter_post_is_refused(policy):
    client = _Client()
    result = tools_write.chatter_post(
        FakeCtx(client), model="product.template", record_id=1, body="Hi"
    )
    assert result["success"] is False
    assert "chatter_post is not available" in result["error"]
    assert client.writes == []


def test_side_effect_method_is_refused_even_when_allowlisted(policy, monkeypatch):
    monkeypatch.setenv(
        "ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "product.template.action_archive"
    )
    monkeypatch.setenv("ODOO_MCP_ALLOW_UNKNOWN_METHODS", "1")
    client = _Client()
    result = tools_write.execute_method(
        FakeCtx(client), "product.template", "action_archive", [[1]]
    )
    assert result["success"] is False
    assert "runs only read-only methods" in result["error"]


def test_read_only_method_still_runs(policy):
    result = tools_write.execute_method(
        FakeCtx(_Client()), "product.template", "search_count", [[]]
    )
    assert result["success"] is True


# ---------------------------------------------------------------------------
# Malformed policy, startup and posture
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "block",
    [
        [],
        {"default": []},
        {"default": {"*": {"operations": {"write": {"fields": [], "max_records": 1}}}}},
        {"default": {"m": {"operations": {}}}},
        {"default": {"m": {"operations": {"merge": {"fields": [], "max_records": 1}}}}},
        {
            "default": {
                "m": {"operations": {"write": {"fields": ["a"], "max_records": 0}}}
            }
        },
        {
            "default": {
                "m": {"operations": {"write": {"fields": "a", "max_records": 1}}}
            }
        },
        {
            "default": {
                "m": {
                    "operations": {"write": {"fields": ["a"], "max_records": 1}},
                    "guards": [{"field": "a"}],
                }
            }
        },
        {
            "default": {
                "m": {
                    "operations": {"write": {"fields": ["a"], "max_records": 1}},
                    "extra": 1,
                }
            }
        },
    ],
)
def test_malformed_block_is_rejected(block):
    with pytest.raises(WriteAclError):
        parse_write_acl({"write_acl": block})


def test_malformed_file_refuses_every_write_and_aborts_startup(policy):
    policy({"write_acl": {"default": []}})
    report = _validate(
        _Client(), "product.supplierinfo", "write", values={"price": 1}, record_ids=[1]
    )
    assert report["success"] is False
    assert "cannot be used" in report["error"]
    result = tools_write.chatter_post(
        FakeCtx(_Client()), model="x.y", record_id=1, body="Hi"
    )
    assert result["success"] is False
    lines, fatal = report_write_acl()
    assert fatal is not None
    assert "WRITE ACL ERROR" in lines[0]


def test_posture_and_startup_name_the_writable_models(policy):
    posture = write_acl_posture()
    assert posture["active"] is True
    assert posture["writable"]["default"] == {
        "product.supplierinfo": ["create", "write"],
        "product.template": ["write"],
    }
    lines, fatal = report_write_acl()
    assert fatal is None
    assert "product.supplierinfo" in lines[0]


def test_health_check_reports_write_acl(policy):
    server = importlib.import_module("odoo_mcp.server")
    report = server.runtime_security_report()
    assert report["write_acl"]["active"] is True


def test_server_lifespan_aborts_on_a_malformed_write_acl(policy):
    import asyncio

    from odoo_mcp.server_core import app_lifespan

    policy({"write_acl": {"default": {"m": {"operations": {}}}}})

    async def _enter():
        async with app_lifespan(None):
            pass

    with pytest.raises(WriteAclError):
        asyncio.run(_enter())


# ---------------------------------------------------------------------------
# Startup scope pinned; ODOO_MCP_REQUIRE_WRITE_ACL; every payload shape
# ---------------------------------------------------------------------------


def test_removing_the_key_at_runtime_does_not_unscope_a_started_server(policy):
    report_write_acl()  # what the lifespan does at startup
    policy({"field_acl": {}})
    report = _validate(
        _Client(),
        "product.template",
        "write",
        values={"standard_price": 1},
        record_ids=[1],
    )
    assert report["success"] is False
    assert "['standard_price']" in report["error"]
    chatter = tools_write.chatter_post(
        FakeCtx(_Client()), model="product.template", record_id=1, body="Hi"
    )
    assert chatter["success"] is False


def test_widening_the_file_at_runtime_does_not_widen_a_started_server(policy):
    report_write_acl()
    wider = json.loads(json.dumps(POLICY))
    wider["write_acl"]["default"]["res.partner"] = {
        "operations": {"write": {"fields": ["comment"], "max_records": 5}}
    }
    policy(wider)
    report = _validate(
        _Client(), "res.partner", "write", values={"comment": "x"}, record_ids=[1]
    )
    assert report["success"] is False
    assert "res.partner is not writable" in report["error"]


def test_narrowing_the_file_at_runtime_still_applies(policy):
    report_write_acl()
    narrower = json.loads(json.dumps(POLICY))
    del narrower["write_acl"]["default"]["product.supplierinfo"]
    policy(narrower)
    report = _validate(
        _Client(), "product.supplierinfo", "write", values={"price": 1}, record_ids=[1]
    )
    assert report["success"] is False


def test_require_flag_refuses_when_the_key_is_absent(policy, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_WRITE_ACL", "1")
    policy({"field_acl": {}})
    report = _validate(
        _Client(), "res.partner", "write", values={"comment": "x"}, record_ids=[1]
    )
    assert report["success"] is False
    assert "ODOO_MCP_REQUIRE_WRITE_ACL" in report["error"]
    lines, fatal = report_write_acl()
    assert fatal is not None


def test_require_flag_refuses_when_the_file_is_missing(policy, monkeypatch, tmp_path):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_WRITE_ACL", "1")
    monkeypatch.setenv("ODOO_MCP_FIELD_POLICY_FILE", str(tmp_path / "gone.json"))
    report = _validate(
        _Client(), "res.partner", "write", values={"comment": "x"}, record_ids=[1]
    )
    assert report["success"] is False
    _, fatal = report_write_acl()
    assert fatal is not None


def test_require_flag_is_quiet_when_the_key_is_present(policy, monkeypatch):
    monkeypatch.setenv("ODOO_MCP_REQUIRE_WRITE_ACL", "1")
    _, fatal = report_write_acl()
    assert fatal is None
    assert write_acl_posture()["required"] is True


def test_guarded_field_in_a_batch_create_is_refused():
    acl = parse_write_acl(
        {
            "write_acl": {
                "default": {
                    "product.template": {
                        "operations": {
                            "create": {"fields": ["name", "categ_id"], "max_records": 5}
                        },
                        "guards": [
                            {
                                "field": "categ_id",
                                "comodel": "product.category",
                                "must_match": ["x"],
                            }
                        ],
                    }
                }
            }
        }
    )
    from odoo_mcp.write_acl import check_guards

    refusal = check_guards(
        acl,
        None,
        "default",
        "product.template",
        "create",
        None,
        None,
        [{"name": "a"}, {"name": "b", "categ_id": 3}],
    )
    assert refusal is not None and "cannot be set on create" in refusal


def test_values_and_values_list_are_both_checked():
    acl = parse_write_acl(POLICY)
    refusal = acl.check_write(
        "default",
        "product.supplierinfo",
        "write",
        values={"price": 1},
        values_list=[{"standard_price": 2}],
        record_ids=[1],
    )
    assert refusal is not None and "['standard_price']" in refusal
    refusal = acl.check_write(
        "default",
        "product.supplierinfo",
        "write",
        values={"price": 1},
        values_list=[{"price": 2}],
        record_ids=list(range(6)),
    )
    assert refusal is not None and "6 records" in refusal
