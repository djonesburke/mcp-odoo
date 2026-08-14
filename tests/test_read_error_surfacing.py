"""A failed read must not be served as "no data".

Found against production on 2026-08-13: asking ``search_records`` for a field
that does not exist returned ``success: true, count: 0, error: null`` on any
model. ``res.groups.full_name`` no longer exists in Odoo 19, so a perfectly
ordinary request answered "there are no such records" about records that were
sitting right there.

That is the worst failure shape this server can have. An error is recoverable —
the reader retries. A confident empty answer is not: it gets believed, and for
Matt and Amber, who reach Odoo by guessing field names in English, a mistyped
field would read as a fact about the business.

The root cause was ``except Exception: return []`` in ``OdooClient.search_read``
and ``read_records``. These tests pin the contract at the tool layer, where it
is visible to a user, rather than only at the client.
"""

from __future__ import annotations

import importlib

from tests.test_batch_write import FakeCtx


class _FailingClient:
    """Raises on the read path the way Odoo does for a bad field name."""

    def __init__(self, message="Invalid field 'totally_bogus_field_xyz' on model 'res.partner'"):
        self.message = message

    def get_model_fields(self, model):
        return {"name": {"type": "char"}, "id": {"type": "integer"}}

    def search_read(self, *args, **kwargs):
        raise ValueError(self.message)

    def read_records(self, *args, **kwargs):
        raise ValueError(self.message)


class _EmptyClient:
    """Succeeds and genuinely matches nothing."""

    def get_model_fields(self, model):
        return {"name": {"type": "char"}, "id": {"type": "integer"}}

    def search_read(self, *args, **kwargs):
        return []

    def read_records(self, *args, **kwargs):
        return []


def test_search_records_surfaces_the_error_instead_of_an_empty_result():
    server = importlib.import_module("odoo_mcp.server")
    result = server.search_records(
        FakeCtx(_FailingClient()), "res.partner", fields=["id", "name"]
    )
    assert result["success"] is False
    assert "totally_bogus_field_xyz" in result["error"]


def test_read_record_surfaces_the_error_instead_of_record_not_found():
    """"Record not found" for a record that exists is a wrong answer, not an error."""
    server = importlib.import_module("odoo_mcp.server")
    result = server.read_record(
        FakeCtx(_FailingClient()), "res.partner", 1, fields=["id", "name"]
    )
    assert result["success"] is False
    assert "Record not found" not in result["error"]
    assert "totally_bogus_field_xyz" in result["error"]


def test_a_genuine_empty_search_still_reads_as_empty():
    """The fix must not turn "nothing matched" into an error.

    Without this, the change would trade a false negative for a false alarm.
    """
    server = importlib.import_module("odoo_mcp.server")
    result = server.search_records(
        FakeCtx(_EmptyClient()), "res.partner", fields=["id", "name"]
    )
    assert result["success"] is True
    assert result["count"] == 0


def test_a_genuinely_missing_record_still_reads_as_not_found():
    server = importlib.import_module("odoo_mcp.server")
    result = server.read_record(
        FakeCtx(_EmptyClient()), "res.partner", 999999, fields=["id", "name"]
    )
    assert result["success"] is False
    assert "Record not found" in result["error"]
