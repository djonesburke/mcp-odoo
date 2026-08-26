"""Tests for API key lifecycle classification.

No fixture in this file contains a credential, a credential-shaped string, or
a 40-character token. A plausible fake secret in a repository is the thing
that later gets grepped and mistaken for a real one, so the records here carry
only ids, labels, users, scopes, and dates.
"""

from datetime import datetime, timezone

import pytest

from odoo_mcp.credential_lifecycle import (
    APIKEY_FIELDS,
    FORBIDDEN_APIKEY_FIELDS,
    CredentialLifecycleError,
    assert_projection_safe,
    build_expiry_report,
    clamp_warn_days,
    classify_instance_kind,
    classify_key,
    determine_visibility,
    parse_expiration,
    rotation_doc,
)

NOW = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)


def key_record(**overrides):
    record = {
        "id": 12,
        "name": "Claude Code MCP",
        "user_id": [6, "Dalton Jones"],
        "scope": False,
        "create_date": "2026-07-22 15:04:11",
        "expiration_date": "2026-08-21 00:00:00",
    }
    record.update(overrides)
    return record


# --- the projection may never carry key material -------------------------


def test_projection_excludes_key_and_index_fields():
    assert FORBIDDEN_APIKEY_FIELDS.isdisjoint(APIKEY_FIELDS)
    assert "key" not in APIKEY_FIELDS
    assert "index" not in APIKEY_FIELDS
    assert_projection_safe()


@pytest.mark.parametrize("leaked", sorted(FORBIDDEN_APIKEY_FIELDS))
def test_projection_guard_rejects_key_material_fields(leaked):
    with pytest.raises(CredentialLifecycleError) as excinfo:
        assert_projection_safe([*APIKEY_FIELDS, leaked])
    assert leaked in str(excinfo.value)


# --- expiry parsing ------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    ["2026-08-21 00:00:00", "2026-08-21T00:00:00", "2026-08-21"],
)
def test_parse_expiration_accepts_odoo_datetime_shapes(raw):
    parsed, problem = parse_expiration(raw)
    assert problem is None
    assert parsed == datetime(2026, 8, 21, 0, 0, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("raw", [False, None, "", "   "])
def test_parse_expiration_reports_absent_distinctly(raw):
    parsed, problem = parse_expiration(raw)
    assert parsed is None
    assert problem == "absent"


@pytest.mark.parametrize("raw", ["soon", "21/08/2026", 12345])
def test_parse_expiration_reports_unparseable_distinctly(raw):
    parsed, problem = parse_expiration(raw)
    assert parsed is None
    assert problem == "unparseable"


def test_parse_expiration_normalizes_naive_datetime_to_utc():
    parsed, problem = parse_expiration(datetime(2026, 8, 21, 0, 0, 0))
    assert problem is None
    assert parsed == datetime(2026, 8, 21, 0, 0, 0, tzinfo=timezone.utc)


# --- per-key classification ---------------------------------------------


def test_key_outside_window_is_ok():
    entry = classify_key(
        key_record(expiration_date="2026-09-30 00:00:00"), now=NOW, warn_days=14
    )
    assert entry["state"] == "ok"
    assert entry["days_remaining"] == 49


def test_key_just_outside_window_is_ok():
    entry = classify_key(
        key_record(expiration_date="2026-08-26 12:00:00"), now=NOW, warn_days=14
    )
    assert entry["state"] == "ok"
    assert entry["days_remaining"] == 15


def test_key_on_the_window_boundary_is_expiring():
    entry = classify_key(
        key_record(expiration_date="2026-08-25 12:00:00"), now=NOW, warn_days=14
    )
    assert entry["state"] == "expiring"
    assert entry["days_remaining"] == 14


def test_key_expiring_within_the_window_names_the_date():
    entry = classify_key(key_record(), now=NOW, warn_days=14)
    assert entry["state"] == "expiring"
    assert entry["days_remaining"] == 9
    assert "2026-08-21 00:00:00" in entry["detail"]
    assert "Dalton Jones" in entry["detail"]


def test_key_expiring_within_a_day_is_expiring_not_expired():
    entry = classify_key(
        key_record(expiration_date="2026-08-11 23:00:00"), now=NOW, warn_days=14
    )
    assert entry["state"] == "expiring"
    assert entry["days_remaining"] == 0


def test_past_expiry_is_expired():
    entry = classify_key(
        key_record(expiration_date="2026-08-04 00:00:00"), now=NOW, warn_days=14
    )
    assert entry["state"] == "expired"
    assert entry["days_remaining"] < 0
    assert "EXPIRED" in entry["detail"]


def test_absent_expiry_is_a_finding_not_a_pass():
    entry = classify_key(key_record(expiration_date=False), now=NOW, warn_days=14)
    assert entry["state"] == "no_expiry"
    assert entry["days_remaining"] is None
    assert "never expire" in entry["detail"]


def test_unparseable_expiry_is_a_finding_not_a_pass():
    entry = classify_key(key_record(expiration_date="whenever"), now=NOW, warn_days=14)
    assert entry["state"] == "unparseable_expiry"
    assert "not as distant" in entry["detail"]


def test_false_scope_is_reported_as_unscoped():
    entry = classify_key(key_record(scope=False), now=NOW, warn_days=14)
    assert entry["unscoped"] is True
    assert entry["scope"] is None


def test_named_scope_is_reported_as_scoped():
    entry = classify_key(key_record(scope="rpc"), now=NOW, warn_days=14)
    assert entry["unscoped"] is False
    assert entry["scope"] == "rpc"


def test_classification_never_echoes_unrequested_record_keys():
    entry = classify_key(
        key_record(key="should-never-be-read", index="also-never"),
        now=NOW,
        warn_days=14,
    )
    assert "key" not in entry
    assert "index" not in entry


# --- visibility ----------------------------------------------------------


def test_visibility_own_user_only_says_others_are_not_covered():
    entries = [classify_key(key_record(), now=NOW, warn_days=14)]
    visibility, detail = determine_visibility(entries, caller_uid=6)
    assert visibility == "own_user_only"
    assert "NOT covered" in detail


def test_visibility_all_users_when_other_owners_are_visible():
    entries = [
        classify_key(key_record(), now=NOW, warn_days=14),
        classify_key(
            key_record(id=13, user_id=[11, "Matt"]), now=NOW, warn_days=14
        ),
    ]
    visibility, detail = determine_visibility(entries, caller_uid=6)
    assert visibility == "all_users"
    assert "2 user(s)" in detail


def test_visibility_unknown_without_a_caller_uid():
    entries = [classify_key(key_record(), now=NOW, warn_days=14)]
    visibility, _ = determine_visibility(entries, caller_uid=None)
    assert visibility == "unknown"


# --- instance kind (rotation runbook routing table) ----------------------


def test_absent_neutralization_parameter_means_production():
    kind, detail = classify_instance_kind([], None)
    assert kind == "production"
    assert "production" in detail


def test_set_neutralization_parameter_means_staging():
    kind, _ = classify_instance_kind(
        [{"key": "database.is_neutralized", "value": "True"}], None
    )
    assert kind == "staging"


def test_unreadable_neutralization_probe_is_unknown_not_production():
    kind, detail = classify_instance_kind(None, {"stage": "probe", "error": {}})
    assert kind == "unknown"
    assert "Do not treat this as production" in detail


def test_false_neutralization_value_is_unknown():
    kind, _ = classify_instance_kind(
        [{"key": "database.is_neutralized", "value": "False"}], None
    )
    assert kind == "unknown"


# --- whole report --------------------------------------------------------


def test_report_reproduces_the_live_prod_key_state():
    report = build_expiry_report(
        [key_record()],
        now=NOW,
        warn_days=14,
        caller_uid=6,
        instance="prod",
        database="prod-db.example.com",
        instance_kind="production",
        instance_kind_detail="probe says production",
    )
    assert report["status"] == "expiring"
    assert report["visible_key_count"] == 1
    assert report["counts"]["expiring"] == 1
    assert report["visibility"] == "own_user_only"
    assert report["database"] == "prod-db.example.com"
    assert report["fields_read"] == list(APIKEY_FIELDS)
    assert any("2026-08-21" in action for action in report["actions"])
    assert any("unscoped" in action for action in report["actions"])


def test_empty_result_is_never_reported_as_all_clear():
    report = build_expiry_report(
        [], now=NOW, warn_days=14, caller_uid=6, database="prod-db"
    )
    assert report["status"] == "no_keys_visible"
    assert "NOT an all-clear" in report["summary"]
    assert report["visible_key_count"] == 0


def test_report_status_takes_the_most_severe_state():
    report = build_expiry_report(
        [
            key_record(id=1, expiration_date="2026-12-01 00:00:00"),
            key_record(id=2, expiration_date=False),
            key_record(id=3, expiration_date="2026-08-01 00:00:00"),
            key_record(id=4, expiration_date="2026-08-20 00:00:00"),
        ],
        now=NOW,
        warn_days=14,
        caller_uid=6,
    )
    assert report["status"] == "expired"
    assert report["counts"] == {
        "expired": 1,
        "expiring": 1,
        "unparseable_expiry": 0,
        "no_expiry": 1,
        "ok": 1,
    }
    assert [entry["id"] for entry in report["keys"]] == [3, 4, 2, 1]
    assert len(report["actions"]) == 4


def test_healthy_report_still_states_the_window():
    report = build_expiry_report(
        [key_record(scope="rpc", expiration_date="2027-01-01 00:00:00")],
        now=NOW,
        warn_days=14,
        caller_uid=6,
        database="prod-db",
    )
    assert report["status"] == "ok"
    assert "more than 14 day(s)" in report["summary"]
    assert report["actions"] == []


def test_report_carries_the_rotation_doc_when_configured(monkeypatch):
    monkeypatch.setenv("ODOO_MCP_ROTATION_DOC", "burke-os/runbooks/x.md")
    assert rotation_doc() == "burke-os/runbooks/x.md"
    report = build_expiry_report([key_record()], now=NOW, warn_days=14, caller_uid=6)
    assert report["rotation_doc"] == "burke-os/runbooks/x.md"


def test_report_omits_the_rotation_doc_when_unset(monkeypatch):
    monkeypatch.delenv("ODOO_MCP_ROTATION_DOC", raising=False)
    assert rotation_doc() is None
    report = build_expiry_report([key_record()], now=NOW, warn_days=14, caller_uid=6)
    assert "rotation_doc" not in report


def test_report_ignores_non_dict_rows():
    report = build_expiry_report(
        [key_record(), "unexpected", None], now=NOW, warn_days=14, caller_uid=6
    )
    assert report["visible_key_count"] == 1


@pytest.mark.parametrize(
    "given,expected",
    [(14, 14), (0, 0), (-5, 0), (9999, 365), ("30", 30), (None, 14), ("x", 14)],
)
def test_clamp_warn_days(given, expected):
    assert clamp_warn_days(given) == expected
