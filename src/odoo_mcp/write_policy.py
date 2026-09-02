"""Write-enablement flags and the reviewed side-effect method policy."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from .tool_helpers import truthy_env

POLICY_FILE_ENV = "ODOO_MCP_POLICY_FILE"
DEFAULT_POLICY_FILENAME = "odoo_mcp_policy.json"


def writes_enabled() -> bool:
    """Return whether destructive approved writes are enabled for this process."""
    return truthy_env("ODOO_MCP_ENABLE_WRITES")


def chatter_direct_enabled() -> bool:
    """Return True when chatter_post may bypass approval-token gating."""
    return truthy_env("MCP_CHATTER_DIRECT")


def policy_file_path() -> Optional[str]:
    """Return the side-effect policy file path, or None when not configured."""
    explicit = os.environ.get(POLICY_FILE_ENV, "").strip()
    if explicit:
        return explicit
    if os.path.exists(DEFAULT_POLICY_FILENAME):
        return DEFAULT_POLICY_FILENAME
    return None


DEFAULT_INSTANCE_NAME = "default"


def _method_names(entries: Any) -> List[str]:
    """Pull method names out of one policy list.

    Entries may be plain strings ("sale.order.action_confirm") or objects with
    a "method" key plus free-form review metadata (reviewed_by, date, reason).
    """
    names: List[str] = []
    for entry in entries or []:
        if isinstance(entry, str):
            name = entry.strip()
        elif isinstance(entry, dict):
            name = str(entry.get("method", "")).strip()
        else:
            name = ""
        if name:
            names.append(name)
    return names


def load_side_effect_policy() -> Dict[str, Any]:
    """Load reviewed side-effect methods from the version-controllable policy file.

    ``allowed_side_effect_methods`` takes either shape:

    - a **flat list**, which applies to every configured instance. This is the
      original form and stays supported so no deployed config breaks.
    - an **object keyed by instance name**, mirroring ``field_acl``::

          "allowed_side_effect_methods": {
            "default": [],
            "staging": ["stock.picking.action_assign"]
          }

      Keys are literal instance names, exactly as in ``field_acl`` — there is
      no inherited fallback. An instance with no key gets no methods, so
      enabling one to test it on staging never enables it on production.

    Returns ``{"path", "methods", "by_instance", "error"}``. ``by_instance`` is
    ``None`` for the flat form and a mapping for the keyed form; ``methods``
    carries the flat list and is empty for the keyed form. A broken policy file
    contributes no methods (fail closed) and surfaces its error in the runtime
    posture.
    """
    path = policy_file_path()
    if path is None:
        return {"path": None, "methods": [], "by_instance": None, "error": None}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"path": path, "methods": [], "by_instance": None, "error": str(exc)}
    if not isinstance(data, dict):
        return {
            "path": path,
            "methods": [],
            "by_instance": None,
            "error": f"policy file {path} must contain a JSON object",
        }

    raw = data.get("allowed_side_effect_methods")
    if raw is None or isinstance(raw, list):
        return {
            "path": path,
            "methods": _method_names(raw),
            "by_instance": None,
            "error": None,
        }
    if isinstance(raw, dict):
        by_instance: Dict[str, List[str]] = {}
        for key, entries in raw.items():
            name = str(key).strip()
            if not name:
                continue
            if not isinstance(entries, list):
                # Fail closed on a malformed instance entry rather than
                # silently treating it as "no methods" — an operator who
                # mistyped the shape must not read that as a working gate.
                return {
                    "path": path,
                    "methods": [],
                    "by_instance": None,
                    "error": (
                        f"allowed_side_effect_methods[{name!r}] must be a list "
                        "of methods"
                    ),
                }
            by_instance[name] = _method_names(entries)
        return {
            "path": path,
            "methods": [],
            "by_instance": by_instance,
            "error": None,
        }
    return {
        "path": path,
        "methods": [],
        "by_instance": None,
        "error": (
            "allowed_side_effect_methods must be a list, or an object keyed "
            "by instance name"
        ),
    }


def allowed_side_effect_methods(
    instance: str = DEFAULT_INSTANCE_NAME,
) -> List[str]:
    """Return exact model.method names reviewed for side effects on ``instance``.

    Resolution order, most permissive first:

    1. ``ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS`` — a CSV list that applies to
       **every** instance, so it cannot express a staging-only method.
    2. the policy file — a flat list applies to every instance; a keyed object
       is consulted for ``instance`` alone and contributes nothing when that
       instance has no key.
    """
    raw_value = os.environ.get("ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS", "")
    from_env = [item.strip() for item in raw_value.split(",") if item.strip()]
    policy = load_side_effect_policy()
    by_instance = policy.get("by_instance")
    if by_instance is None:
        from_file = policy["methods"]
    else:
        from_file = by_instance.get(instance, [])
    merged: List[str] = []
    for name in [*from_env, *from_file]:
        if name not in merged:
            merged.append(name)
    return merged


def side_effect_method_allowed(
    model: str, method: str, instance: str = DEFAULT_INSTANCE_NAME
) -> bool:
    """Check exact side-effect allowlist entries for one instance."""
    return f"{model}.{method}" in set(allowed_side_effect_methods(instance))
