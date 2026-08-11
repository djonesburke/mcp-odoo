"""Odoo API key lifecycle monitoring (read-only; never touches key material).

Odoo emits no warning before an API key expires. When a key ages out, the
transport returns a bare authentication failure, and every downstream read
surfaces that as an empty result — indistinguishable from a genuinely empty
search. This module turns that silence into a dated, named finding.

Safety contract, enforced by structure rather than by diligence:

* ``res.users.apikeys`` exposes no ``key`` or ``index`` field through the ORM,
  so there is no key material reachable on this path.
* :data:`APIKEY_FIELDS` is a fixed projection. Callers cannot widen it, and
  :data:`FORBIDDEN_APIKEY_FIELDS` names what must never enter it.
* Nothing here reads a credential from the environment, the client, or the
  configuration, so no failure path can interpolate one into an error string.

Reporting rules, which exist because this server already has a long list of
conditions that render as "no data":

* An absent expiry is a finding (``no_expiry``), not a pass — such a key never
  trips the warning window and never dies.
* An unparseable expiry is a finding (``unparseable_expiry``), not a pass.
* Zero visible keys is a finding (``no_keys_visible``), never an all-clear.
* An unreadable instance-kind check reports ``unknown``, never "production".
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

APIKEY_MODEL = "res.users.apikeys"

#: The only fields ever requested from :data:`APIKEY_MODEL`. Fixed on purpose:
#: no tool argument widens it.
APIKEY_FIELDS: Tuple[str, ...] = (
    "id",
    "name",
    "user_id",
    "scope",
    "create_date",
    "expiration_date",
)

#: Field names that must never appear in :data:`APIKEY_FIELDS`. ``index`` holds
#: the leading characters of the key itself, so it is partial key material.
FORBIDDEN_APIKEY_FIELDS = frozenset({"key", "index"})

NEUTRALIZED_PARAMETER = "database.is_neutralized"

#: Optional pointer to the deployment's rotation procedure, echoed in the
#: report so the alert names its own remedy. Not a credential.
ROTATION_DOC_ENV = "ODOO_MCP_ROTATION_DOC"

DEFAULT_WARN_DAYS = 14
MAX_WARN_DAYS = 365

#: Most-severe first. The overall status is the first state present.
KEY_STATE_PRIORITY: Tuple[str, ...] = (
    "expired",
    "expiring",
    "unparseable_expiry",
    "no_expiry",
    "ok",
)

_DATETIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
)


class CredentialLifecycleError(ValueError):
    """Raised when the fixed field projection has been compromised."""


def assert_projection_safe(fields: Iterable[str] = APIKEY_FIELDS) -> None:
    """Fail loudly if the projection ever grows a key-material field."""
    leaked = sorted(FORBIDDEN_APIKEY_FIELDS.intersection(fields))
    if leaked:
        raise CredentialLifecycleError(
            f"Refusing to read {leaked} from {APIKEY_MODEL}: key material is "
            "never read by this server."
        )


def clamp_warn_days(warn_days: Any) -> int:
    """Coerce ``warn_days`` into 0..:data:`MAX_WARN_DAYS`."""
    try:
        value = int(warn_days)
    except (TypeError, ValueError):
        return DEFAULT_WARN_DAYS
    return max(0, min(value, MAX_WARN_DAYS))


def rotation_doc() -> Optional[str]:
    """Deployment-configured rotation procedure reference, if any."""
    value = os.environ.get(ROTATION_DOC_ENV, "").strip()
    return value or None


def parse_expiration(value: Any) -> Tuple[Optional[datetime], Optional[str]]:
    """Parse an Odoo datetime string into an aware UTC datetime.

    Returns ``(datetime, None)`` on success, ``(None, "absent")`` when Odoo
    reports no expiry (``False``), and ``(None, "unparseable")`` when a value
    is present but not a datetime this code understands. The two failures are
    kept distinct because they mean different things and neither means "fine".
    """
    if value is None or value is False or value == "":
        return None, "absent"
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc), None
        return value.astimezone(timezone.utc), None
    if not isinstance(value, str):
        return None, "unparseable"
    text = value.strip()
    if not text:
        return None, "absent"
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc), None
        except ValueError:
            continue
    return None, "unparseable"


def _user_reference(value: Any) -> Tuple[Optional[int], Optional[str]]:
    """Split an Odoo many2one payload into ``(uid, display name)``."""
    if isinstance(value, (list, tuple)) and value:
        uid = int(value[0]) if isinstance(value[0], int) else None
        name = str(value[1]) if len(value) > 1 and value[1] else None
        return uid, name
    if isinstance(value, int):
        return value, None
    return None, None


def _scope_of(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def classify_key(
    record: Dict[str, Any], *, now: datetime, warn_days: int
) -> Dict[str, Any]:
    """Turn one ``res.users.apikeys`` row into a dated lifecycle finding."""
    uid, user_name = _user_reference(record.get("user_id"))
    raw_expiry = record.get("expiration_date")
    expires_at, problem = parse_expiration(raw_expiry)
    scope = _scope_of(record.get("scope"))
    label = str(record.get("name") or "").strip() or None

    entry: Dict[str, Any] = {
        "id": record.get("id"),
        "name": label,
        "uid": uid,
        "user": user_name,
        "scope": scope,
        "unscoped": scope is None,
        "create_date": record.get("create_date") or None,
        "expiration_date": raw_expiry if isinstance(raw_expiry, str) else None,
        "days_remaining": None,
        "state": "ok",
        "detail": "",
    }

    who = user_name or (f"uid {uid}" if uid is not None else "an unknown user")
    named = f"API key {label!r}" if label else f"API key id {record.get('id')}"

    if problem == "absent":
        entry["state"] = "no_expiry"
        entry["detail"] = (
            f"{named} on {who} has no expiration date. It will never expire and "
            "will never trigger this warning; it also cannot age out of use."
        )
        return entry
    if problem == "unparseable" or expires_at is None:
        entry["state"] = "unparseable_expiry"
        entry["detail"] = (
            f"{named} on {who} reports an expiration date this server could not "
            "parse. Treat the expiry as unknown, not as distant."
        )
        return entry

    delta = expires_at - now
    days = delta.days
    entry["days_remaining"] = days

    if delta.total_seconds() <= 0:
        entry["state"] = "expired"
        entry["detail"] = (
            f"{named} on {who} EXPIRED on {entry['expiration_date']} "
            f"({abs(days)} day(s) ago). Any client still holding it is failing "
            "authentication now."
        )
    elif days <= warn_days:
        entry["state"] = "expiring"
        entry["detail"] = (
            f"{named} on {who} expires in {days} day(s) on "
            f"{entry['expiration_date']}. Rotate before that date; Odoo will "
            "not warn again."
        )
    else:
        entry["detail"] = (
            f"{named} on {who} expires in {days} day(s) on "
            f"{entry['expiration_date']}."
        )
    return entry


def _sort_key(entry: Dict[str, Any]) -> Tuple[int, int, int]:
    """Order findings most-urgent first, stable by id."""
    try:
        priority = KEY_STATE_PRIORITY.index(str(entry.get("state")))
    except ValueError:
        priority = len(KEY_STATE_PRIORITY)
    days = entry.get("days_remaining")
    remaining = days if isinstance(days, int) else 0
    identifier = entry.get("id")
    return (priority, remaining, identifier if isinstance(identifier, int) else 0)


def classify_instance_kind(
    rows: Any, error: Optional[Dict[str, Any]]
) -> Tuple[str, str]:
    """Map the neutralization probe onto the rotation runbook's routing table.

    An unreadable probe is ``unknown`` — an unanswered question is not a pass,
    and must never be reported as production or staging.
    """
    if error is not None:
        return (
            "unknown",
            f"Could not read {NEUTRALIZED_PARAMETER}; the instance kind is "
            "unconfirmed. Do not treat this as production or as staging.",
        )
    if not rows:
        return (
            "production",
            f"{NEUTRALIZED_PARAMETER} is not set, which indicates production.",
        )
    value: Any = None
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        value = rows[0].get("value")
    truthy = str(value).strip().lower() not in {"", "false", "0", "none"}
    if truthy:
        return (
            "staging",
            f"{NEUTRALIZED_PARAMETER} is set, which indicates a neutralized "
            "(staging) database.",
        )
    return (
        "unknown",
        f"{NEUTRALIZED_PARAMETER} exists but reads as false; the instance kind "
        "is unconfirmed.",
    )


def determine_visibility(
    entries: Sequence[Dict[str, Any]], caller_uid: Optional[int]
) -> Tuple[str, str]:
    """State how much of the key estate this connection can actually see.

    Odoo restricts non-system users to their own key records, so a clean
    report from one user's credential says nothing about anyone else's keys.
    Reporting that explicitly is what keeps a partial view from reading like
    an organization-wide all-clear.
    """
    uids = {entry.get("uid") for entry in entries if entry.get("uid") is not None}
    if caller_uid is None:
        return (
            "unknown",
            "The calling user id could not be determined, so the coverage of "
            "this report is unknown.",
        )
    if not uids:
        return (
            "unknown",
            "No key owners were visible, so the coverage of this report is "
            "unknown.",
        )
    if uids <= {caller_uid}:
        return (
            "own_user_only",
            f"Only uid {caller_uid}'s own keys are visible. Other users' keys "
            "are NOT covered by this report — a record rule limits this "
            "credential to its own records, or no other user holds a key.",
        )
    return (
        "all_users",
        f"Keys for {len(uids)} user(s) are visible, so this credential can see "
        "beyond its own records.",
    )


def build_expiry_report(
    records: Iterable[Dict[str, Any]],
    *,
    now: datetime,
    warn_days: int = DEFAULT_WARN_DAYS,
    caller_uid: Optional[int] = None,
    instance: Optional[str] = None,
    database: Optional[str] = None,
    instance_kind: str = "unknown",
    instance_kind_detail: str = "",
) -> Dict[str, Any]:
    """Assemble the full lifecycle report from raw ``res.users.apikeys`` rows."""
    entries = [
        classify_key(record, now=now, warn_days=warn_days)
        for record in records
        if isinstance(record, dict)
    ]
    entries.sort(key=_sort_key)

    counts: Dict[str, int] = {state: 0 for state in KEY_STATE_PRIORITY}
    for entry in entries:
        state = str(entry.get("state"))
        counts[state] = counts.get(state, 0) + 1

    visibility, visibility_detail = determine_visibility(entries, caller_uid)
    where = database or instance or "the connected database"

    if not entries:
        status = "no_keys_visible"
        summary = (
            f"No API key records are visible on {where}. This is NOT an "
            "all-clear: it means either this user holds no API key, or a "
            "record rule limits visibility to the caller's own records. "
            "Confirm in Odoo under Preferences > Account Security."
        )
    else:
        status = next(
            (state for state in KEY_STATE_PRIORITY if counts.get(state)),
            "ok",
        )
        attention = [
            entry for entry in entries if entry.get("state") != "ok"
        ]
        if attention:
            summary = (
                f"{len(attention)} of {len(entries)} visible API key(s) on "
                f"{where} need attention (warning window: {warn_days} day(s))."
            )
        else:
            summary = (
                f"All {len(entries)} visible API key(s) on {where} expire more "
                f"than {warn_days} day(s) from now."
            )

    actions: List[str] = [
        str(entry["detail"]) for entry in entries if entry.get("state") != "ok"
    ]
    unscoped = [entry for entry in entries if entry.get("unscoped")]
    if unscoped:
        actions.append(
            f"{len(unscoped)} visible key(s) are unscoped, so each carries the "
            "full rights of its owning user."
        )

    report: Dict[str, Any] = {
        "checked_at": now.astimezone(timezone.utc).isoformat(),
        "instance": instance,
        "database": database,
        "instance_kind": instance_kind,
        "instance_kind_detail": instance_kind_detail,
        "warn_days": warn_days,
        "status": status,
        "summary": summary,
        "visibility": visibility,
        "visibility_detail": visibility_detail,
        "caller_uid": caller_uid,
        "visible_key_count": len(entries),
        "counts": counts,
        "keys": entries,
        "actions": actions,
        "fields_read": list(APIKEY_FIELDS),
    }
    doc = rotation_doc()
    if doc:
        report["rotation_doc"] = doc
    return report
