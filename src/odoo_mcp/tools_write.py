"""
MCP tools: write domain.

Includes: preview_write, validate_write, execute_approved_write,
chatter_post, execute_method + WriteConfirmation + elicitation logic.
"""

import base64
import hashlib
import json
import os
import stat
import xmlrpc.client
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional

from mcp.server.elicitation import ElicitationResult
from mcp.server.mcpserver import Context, Elicit, Resolve
from pydantic import Field

from .agent_tools import (
    build_approval_token,
    build_write_preview_report,
    validate_write_report,
    verify_write_approval,
)
from .audit import record_write_event
from .diagnostics import DESTRUCTIVE_METHODS, classify_method_safety
from .field_policy import get_field_policy
from .tool_helpers import (
    max_attachment_upload_bytes,
    normalize_domain_input,
    truthy_env,
    validate_method_name,
    validate_model_name,
)
from .write_policy import chatter_direct_enabled, side_effect_method_allowed, writes_enabled
from .rate_limit import check_rate
from .server_core import (
    DESTRUCTIVE_TOOL,
    PREVIEW_TOOL,
    READ_ONLY_TOOL,
    WRITE_APPROVAL_TTL_SECONDS,
    WriteConfirmation,
    ELICIT_WRITES_ENV,
    mcp,
    _app_context,
    _resolve_odoo,
    register_write_approval,
    require_validated_write_approval,
    restrict_attachment_upload_path,
    write_approval_payload,
)

_FROM_PATH_SUFFIX = "_from_path"

# Odoo serializes XML-RPC responses with allow_none=False, so a method that
# returns None executes (and commits) server-side, then faults with this text.
_NONE_MARSHAL_FAULT_MARKER = "cannot marshal None unless allow_none is enabled"


def _assert_handle_is_the_checked_entry(handle_stat: os.stat_result, path: Path) -> None:
    """Prove the open descriptor is the directory entry that was validated.

    ``O_NOFOLLOW`` is the POSIX way to refuse a swapped-in symlink, but it
    **does not exist on Windows** — ``getattr(os, "O_NOFOLLOW", 0)`` degrades
    to ``0`` there, so on the platform Burke actually deploys on, the open
    silently followed whatever the final component pointed at. This check is
    the portable enforcement: compare the identity of the file we opened
    against the identity of the entry at ``path``, read *without* following a
    final symlink.

    Ordering makes this race-free in the direction that matters. Both stats
    describe state after the open, so an attacker who swaps the entry at any
    point produces a mismatch and gets refused; the only way to match is for
    the descriptor to be the entry itself.

    Residual, unchanged from upstream and equally true on POSIX: this covers
    the final path component only, so a swapped *parent directory* is out of
    scope, and a hard link inside the upload root is indistinguishable from
    the file it links to (it is the same file, by definition). Neither is
    closed by ``O_NOFOLLOW`` either — this restores parity with POSIX, it does
    not exceed it.
    """
    try:
        link_stat = os.lstat(str(path))
    except OSError as exc:
        raise ValueError(
            f"{path} could not be re-checked after opening; refusing to read it"
        ) from exc

    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if reparse_flag and getattr(link_stat, "st_file_attributes", 0) & reparse_flag:
        raise ValueError(
            f"{path} is a symlink or junction; refusing to read through it"
        )
    if stat.S_ISLNK(link_stat.st_mode):
        raise ValueError(
            f"{path} is a symlink; refusing to read through it"
        )
    if not link_stat.st_ino or not handle_stat.st_ino:
        # Some network filesystems report no usable file id. Without one the
        # identity comparison below proves nothing, and this module fails
        # closed rather than reading bytes it cannot vouch for.
        raise ValueError(
            f"{path} is on a filesystem that reports no file id, so the file "
            "read cannot be verified as the file that was checked"
        )
    if (link_stat.st_dev, link_stat.st_ino) != (handle_stat.st_dev, handle_stat.st_ino):
        raise ValueError(
            f"{path} changed between validation and read; refusing to read it"
        )


def _read_attachment_source_file(path: Path, cap: int) -> bytes:
    """Open, size-check, and read ``path`` through a single file descriptor.

    ``restrict_attachment_upload_path`` only proves the path was inside a
    trusted root *at resolve time*. A writable upload root still leaves a
    TOCTOU window between that check and the read: the entry on disk could
    be swapped for a symlink pointing outside the root before we get to it.
    Opening once and deriving the size cap, the identity check, and the hash
    from that same fd closes the gap — everything checked describes the bytes
    actually returned, not a stale ``stat()`` of a since-swapped file.

    ``O_NOFOLLOW`` refuses the swap up front where the platform has it;
    ``_assert_handle_is_the_checked_entry`` is what enforces it everywhere,
    Windows included.
    """
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise ValueError(f"{path} does not exist or is not a regular file") from exc
    with os.fdopen(fd, "rb") as handle:
        file_stat = os.fstat(handle.fileno())
        if not stat.S_ISREG(file_stat.st_mode):
            raise ValueError(f"{path} does not exist or is not a regular file")
        _assert_handle_is_the_checked_entry(file_stat, path)
        if file_stat.st_size > cap:
            raise ValueError(
                f"{path} is {file_stat.st_size} bytes; cap is {cap} "
                "(raise ODOO_MCP_MAX_ATTACHMENT_UPLOAD_BYTES to allow it)"
            )
        return handle.read()


def _resolve_binary_from_path_fields(
    values: Dict[str, Any],
) -> tuple[Dict[str, Any], Dict[str, str]]:
    """Replace ``<field>_from_path`` entries with a content fingerprint.

    Lets a caller attach a local file (e.g. a resume) to an Odoo binary field
    without ever putting the base64 content in a tool call — the content
    would otherwise have to pass through the calling agent's context, which
    does not scale past a few hundred KB.

    Returns ``(values, real_base64_by_field)``. The returned ``values`` dict
    only ever holds a ``sha256:<hex>:<byte length>`` fingerprint for each
    resolved field — safe to hash into the approval token, store, and echo
    back to the caller. The real base64 is returned separately so it can be
    stored server-side only (see ``register_write_approval``) and substituted
    back in at execution time (see ``_execute_approved_write_gated``).
    """
    values = dict(values)
    resolved: Dict[str, str] = {}
    for key in [k for k in values if k.endswith(_FROM_PATH_SUFFIX)]:
        real_field = key[: -len(_FROM_PATH_SUFFIX)]
        if real_field in values:
            raise ValueError(f"pass either {real_field!r} or {key!r}, not both")
        raw_path = values.pop(key)
        path = restrict_attachment_upload_path(str(raw_path))
        data = _read_attachment_source_file(path, max_attachment_upload_bytes())
        digest = hashlib.sha256(data).hexdigest()
        values[real_field] = f"sha256:{digest}:{len(data)}"
        resolved[real_field] = base64.b64encode(data).decode("ascii")
    return values, resolved


def _srv() -> Any:
    """Late import of server module to resolve patchable symbols at call time."""
    from . import server
    return server


_MAX_VALUE_CHARS = 80
_MAX_LISTED_RECORDS = 20
_REDACTED_MARKER = "<hidden by field policy>"


def _render_value(value: Any) -> str:
    """Render one field value for a confirmation prompt, bounded in length."""
    text = json.dumps(value, default=str)
    if len(text) > _MAX_VALUE_CHARS:
        return text[:_MAX_VALUE_CHARS] + "..."
    return text


def _record_label(record: Dict[str, Any]) -> str:
    """Best human-readable name for a record, or "" when none is readable."""
    for key in ("display_name", "name", "complete_name"):
        label = record.get(key)
        if isinstance(label, str) and label.strip():
            return label.strip()
    return ""


def _same_value(before: Any, after: Any) -> bool:
    """Whether a proposed write value would actually change the stored one.

    Odoo returns many2one fields as ``[id, "Display Name"]`` while a write
    passes the bare id, so a naive comparison reports every relation as
    changed and buries the fields that really do change.
    """
    if (
        isinstance(before, (list, tuple))
        and len(before) == 2
        and isinstance(before[0], int)
        and isinstance(after, int)
        and not isinstance(after, bool)
    ):
        return before[0] == after
    if before is False and (after is None or after == ""):
        return True
    return bool(before == after)


def _collect_current_state(
    ctx: Context,
    *,
    model: str,
    operation: str,
    record_ids: Optional[List[int]],
    values: Optional[Dict[str, Any]],
    instance: Optional[str],
) -> Dict[str, Any]:
    """Read what a write is about to overwrite, so a human can see before -> after.

    Approval prompts that echo only the proposed values read like a diff but
    are half of one: they cannot show that a field is already at the target
    value, and on ``unlink`` they identify records by bare integer id. This
    reads the affected records once, at validate time, through the same field
    ACL as every other read path — a denied field is reported as hidden, never
    surfaced in a confirmation dialog.

    Best-effort by design. A failed read returns ``available: False`` with a
    reason that the prompt states out loud; it does not block validation,
    because an Odoo hiccup should not be able to take the write path down. The
    human still holds the decision either way.
    """
    normalized_operation = (operation or "").strip().lower()
    if normalized_operation == "create":
        return {"available": True, "operation": "create", "records": []}
    ids = [int(rid) for rid in record_ids or []]
    if not ids:
        return {
            "available": False,
            "operation": normalized_operation,
            "reason": "the approval names no record ids",
        }
    fields = ["id", "display_name"]
    if normalized_operation == "write":
        fields += [name for name in sorted(values or {}) if name not in fields]
    read_ids = ids[:_MAX_LISTED_RECORDS]
    try:
        instance_name, odoo = _resolve_odoo(ctx, instance)
        records = odoo.read_records(model, read_ids, fields=fields)
    except Exception as exc:  # noqa: BLE001 — reported to the human, never raised
        return {
            "available": False,
            "operation": normalized_operation,
            "reason": f"could not read the current records ({type(exc).__name__})",
        }
    if not isinstance(records, list):
        return {
            "available": False,
            "operation": normalized_operation,
            "reason": "the current-state read returned no usable records",
        }
    redacted_records, redacted_fields = get_field_policy().redact_records(
        instance_name, model, records
    )
    found_ids = {
        int(record["id"]) for record in redacted_records if record.get("id") is not None
    }
    return {
        "available": True,
        "operation": normalized_operation,
        "records": redacted_records,
        "redacted_fields": redacted_fields,
        "missing_ids": [rid for rid in read_ids if rid not in found_ids],
        "not_listed": max(0, len(ids) - len(read_ids)),
    }


def _format_record_lines(current_state: Dict[str, Any]) -> List[str]:
    """One "id  label" line per affected record, plus what could not be shown."""
    lines = []
    for record in current_state.get("records") or []:
        label = _record_label(record)
        lines.append(f"  {record.get('id')}  {label}" if label else f"  {record.get('id')}")
    for missing in current_state.get("missing_ids") or []:
        lines.append(f"  {missing}  <no such record, or not readable>")
    not_listed = int(current_state.get("not_listed") or 0)
    if not_listed:
        lines.append(f"  ... and {not_listed} more not listed here")
    return lines


def _format_change_lines(
    values: Dict[str, Any], current_state: Dict[str, Any]
) -> List[str]:
    """Per-field ``before -> after`` lines, flagging fields already at target."""
    records = current_state.get("records") or []
    redacted = set(current_state.get("redacted_fields") or [])
    lines = []
    for field in sorted(values):
        after = _render_value(values[field])
        if field in redacted:
            lines.append(f"  {field}: {_REDACTED_MARKER} -> {after}")
            continue
        befores = {_render_value(record.get(field)) for record in records}
        unchanged = records and all(
            _same_value(record.get(field), values[field]) for record in records
        )
        if unchanged:
            lines.append(f"  {field}: {after} (unchanged - already set)")
        elif len(befores) == 1:
            lines.append(f"  {field}: {befores.pop()} -> {after}")
        elif befores:
            lines.append(f"  {field}: <varies across records> -> {after}")
        else:
            lines.append(f"  {field}: <current value unread> -> {after}")
    return lines


def _write_elicitation_message(
    approval: Dict[str, Any], current_state: Optional[Dict[str, Any]] = None
) -> str:
    """Render the pending write for a human: what it touches, and what changes.

    ``current_state`` is the snapshot captured at validate time and held
    server-side (see ``_collect_current_state``). When it is absent the prompt
    says so in as many words rather than quietly degrading to a list of
    proposed values that looks like a diff.
    """
    operation = str(approval.get("operation") or "?").strip().lower()
    model = str(approval.get("model") or "?")
    record_ids = approval.get("record_ids") or []
    values = approval.get("values") or {}
    values_list = approval.get("values_list")
    instance = str(approval.get("instance") or "default")

    lines = [
        f"Odoo write pending approval: {operation} on {model}",
        f"Instance: {instance}",
    ]
    state: Dict[str, Any] = (
        current_state
        if isinstance(current_state, dict) and current_state.get("available")
        else {}
    )
    have_state = bool(state)

    if operation == "unlink":
        lines.append(f"DELETES {len(record_ids)} record(s) - this cannot be undone:")
        lines.extend(
            _format_record_lines(state) if have_state else [f"  {record_ids}"]
        )
    elif operation == "create":
        count = len(values_list) if isinstance(values_list, list) else 1
        lines.append(f"Creates {count} new record(s) with:")
        for entry in (values_list if isinstance(values_list, list) else [values])[
            :_MAX_LISTED_RECORDS
        ]:
            lines.extend(
                f"  {field}: {_render_value(value)}"
                for field, value in sorted((entry or {}).items())
            )
    else:
        if record_ids:
            lines.append(f"Records ({len(record_ids)}):")
            lines.extend(
                _format_record_lines(state) if have_state else [f"  {record_ids}"]
            )
        if values:
            lines.append("Changes:")
            lines.extend(
                _format_change_lines(values, state)
                if have_state
                else [
                    f"  {field} -> {_render_value(value)}"
                    for field, value in sorted(values.items())
                ]
            )

    if operation != "create" and not have_state:
        reason = "not captured"
        if isinstance(current_state, dict):
            reason = str(current_state.get("reason") or reason)
        lines.append(
            f"WARNING: current values could not be read ({reason}) - the above "
            "shows only what the write will set, not what it replaces."
        )
    return "\n".join(lines)


def _client_elicitation_gap(ctx: Context) -> Optional[str]:
    """Why this client cannot be relied on to prompt a human, or None.

    Returns None when the capability cannot be introspected at all — there the
    ``ctx.elicit`` call itself is the authority on whether a human was asked.
    """
    capabilities = getattr(ctx, "client_capabilities", None)
    if capabilities is None:
        return None
    elicitation = getattr(capabilities, "elicitation", None)
    if elicitation is None:
        return "the client declared no elicitation capability"
    if getattr(elicitation, "form", None) is None:
        # Form mode is the only mode that can carry a confirmation. Anything
        # else is a client that cannot ask a human, whatever else it declares.
        # Testing for url-mode *specifically* used to let the commonest shape
        # through: an elicitation object with neither field set. Observed from
        # claude-code 2.1.234, which then declines on its own, so the refusal
        # was audited as a human decision and read like the operator said no.
        if getattr(elicitation, "url", None) is not None:
            return (
                "the client offers only URL-mode elicitation, which cannot carry "
                "a confirmation form"
            )
        return "the client declared an elicitation capability with no form mode"
    return None


def _client_identity(ctx: Context) -> Optional[str]:
    """Best-effort client name/version from the MCP initialize handshake.

    Audit trail only. Absent on the direct-call path and on any client that
    does not send ``clientInfo``, so every lookup here is defensive.
    """
    for path in (
        ("session", "client_params", "clientInfo"),
        ("session", "client_params", "client_info"),
        ("client_params", "clientInfo"),
    ):
        node: Any = ctx
        for attr in path:
            node = getattr(node, attr, None)
            if node is None:
                break
        if node is None:
            continue
        name = getattr(node, "name", None)
        if not name:
            continue
        version = getattr(node, "version", None)
        return f"{name} {version}" if version else str(name)
    return None


def _client_elicitation_posture(ctx: Context) -> str:
    """What the client *claims* it can prompt with, as an audit-friendly label.

    ``_client_elicitation_gap`` returns None both when the capability is
    adequate and when it cannot be introspected, because those two cases need
    identical runtime treatment: trust ``ctx.elicit``. They are entirely
    different facts to whoever reads the log afterwards — one is a human who
    said no, the other may be a client that answered without asking anybody.
    Recording the posture is what lets those be told apart after the fact.
    """
    capabilities = getattr(ctx, "client_capabilities", None)
    if capabilities is None:
        posture = "uninspectable"
    else:
        elicitation = getattr(capabilities, "elicitation", None)
        if elicitation is None:
            posture = "declared-none"
        elif getattr(elicitation, "form", None) is not None:
            posture = "form"
        elif getattr(elicitation, "url", None) is not None:
            posture = "url-only"
        else:
            posture = "declared-empty"
    identity = _client_identity(ctx)
    return f"{posture}; client={identity}" if identity else posture


def _elicit_audit_detail(ctx: Context, detail: Optional[str]) -> str:
    """Pair an elicitation outcome with the client posture that produced it."""
    posture = _client_elicitation_posture(ctx)
    if detail:
        return f"{detail}; client_elicitation={posture}"
    return f"client_elicitation={posture}"


def _approval_current_state(
    ctx: Context, approval: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Fetch the validate-time snapshot for this approval, if one was stored."""
    try:
        record = require_validated_write_approval(_app_context(ctx), approval)
    except Exception:  # noqa: BLE001 — a missing snapshot only degrades the prompt
        return None
    if not isinstance(record, dict):
        return None
    state = record.get("current_state")
    return state if isinstance(state, dict) else None


def _resolve_write_confirmation(
    approval: Dict[str, Any], ctx: Context
) -> WriteConfirmation | Elicit[WriteConfirmation]:
    """Use MRTR on modern clients and preserve token fallback elsewhere.

    Burke behavior 3: when the confirmation gate is ON and the client cannot
    present a form, this refuses instead of approving. Upstream returned
    ``approve=True`` there, so a client that could not prompt silently turned
    "confirm every write" into "write freely" — the operator had asked for a
    gate and got none, with no signal. ``execute_approved_write_tool`` names
    that case separately so the refusal does not read as a human decision.
    """
    if not truthy_env(ELICIT_WRITES_ENV):
        return WriteConfirmation(approve=True)
    if _client_elicitation_gap(ctx) is not None:
        return WriteConfirmation(approve=False)
    return Elicit(
        _write_elicitation_message(approval, _approval_current_state(ctx, approval)),
        WriteConfirmation,
    )


# Python 3.10 wraps Annotated defaults of None in Optional, hiding Resolve.
_DIRECT_CALL_REVIEW = object()


async def _elicit_write_confirmation(
    ctx: Context, approval: Dict[str, Any]
) -> tuple[str, Optional[str]]:
    """Ask the human via MCP elicitation when ODOO_MCP_ELICIT_WRITES=1.

    Returns (decision, detail): "skipped" (gate off), "approved",
    "declined", or "unsupported" (the client could not be asked at all).

    Burke behavior 3: "unsupported" is a refusal, not a fallback. Upstream let
    it fall through to the token flow — but every gate in that flow is one the
    calling agent satisfies by itself, so an unaskable client meant the write
    executed with no human anywhere in it.
    """
    if not truthy_env(ELICIT_WRITES_ENV):
        return "skipped", None
    gap = _client_elicitation_gap(ctx)
    if gap is not None:
        return "unsupported", gap
    try:
        result = await ctx.elicit(
            message=_write_elicitation_message(
                approval, _approval_current_state(ctx, approval)
            ),
            schema=WriteConfirmation,
        )
    except Exception as exc:
        return "unsupported", str(exc)
    data = getattr(result, "data", None)
    if (
        getattr(result, "action", None) == "accept"
        and data is not None
        and data.approve
    ):
        return "approved", None
    return "declined", str(getattr(result, "action", "declined"))


@mcp.tool(
    description="Preview create, write, or unlink without executing it",
    annotations=PREVIEW_TOOL,
    structured_output=True,
)
def preview_write(
    model: str,
    operation: str,
    values: Optional[Dict[str, Any]] = None,
    values_list: Optional[List[Dict[str, Any]]] = None,
    record_ids: Optional[List[int]] = None,
    context: Optional[Dict[str, Any]] = None,
    instance: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a canonical approval token for a later approved write.

    Batch create: pass ``values_list`` (one dict per record, max 100) —
    executes as a single atomic Odoo ``create(vals_list)`` call.
    """
    try:
        validate_model_name(model)
        report = build_write_preview_report(
            model=model,
            operation=operation,
            values=values,
            values_list=values_list,
            record_ids=record_ids,
            context=context,
            instance=_srv().resolve_instance_name(instance),
        )
        record_write_event(
            "preview",
            outcome="success" if report.get("success") else "rejected",
            model=model,
            operation=str(operation).strip().lower(),
            record_ids=[int(rid) for rid in record_ids or []],
            instance=_srv().resolve_instance_name(instance),
            token=str((report.get("approval") or {}).get("token") or "") or None,
        )
        return report
    except Exception as e:
        return {"success": False, "tool": "preview_write", "error": str(e)}


@mcp.tool(
    description="Validate a standard write payload against optional fields_get metadata",
    annotations=READ_ONLY_TOOL,
    structured_output=True,
)
def validate_write(
    ctx: Context,
    model: str,
    operation: str,
    values: Optional[Dict[str, Any]] = None,
    values_list: Optional[List[Dict[str, Any]]] = None,
    record_ids: Optional[List[int]] = None,
    context: Optional[Dict[str, Any]] = None,
    fields_metadata: Optional[Dict[str, Any]] = None,
    use_live_metadata: bool = True,
    instance: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate write shape and return an approval payload when safe."""
    try:
        validate_model_name(model)
        instance_name = _srv().resolve_instance_name(instance)

        resolved_binary_values: Dict[str, Any] = {}
        if values:
            values, resolved_binary_values = _resolve_binary_from_path_fields(values)
        if resolved_binary_values and (fields_metadata is not None or not use_live_metadata):
            return {
                "success": False,
                "tool": "validate_write",
                "error": (
                    "*_from_path uploads require validation against trusted live "
                    "Odoo metadata; call with use_live_metadata=True (the default) "
                    "and no explicit fields_metadata."
                ),
            }

        metadata_source = "input" if fields_metadata is not None else "none"
        if fields_metadata is None and use_live_metadata:
            metadata_source = "server"
            _, odoo = _resolve_odoo(ctx, instance)
            fields_metadata = odoo.get_model_fields(model)
            if "error" in fields_metadata:
                return {
                    "success": False,
                    "tool": "validate_write",
                    "error": fields_metadata["error"],
                    "metadata_used": {"fields_get": False, "source": metadata_source},
                }
            if not fields_metadata:
                return {
                    "success": False,
                    "tool": "validate_write",
                    "error": "live fields_get metadata was empty; refusing to approve writes",
                    "metadata_used": {"fields_get": False, "source": metadata_source},
                    "approval_status": {
                        "stored": False,
                        "source": metadata_source,
                        "reason": "trusted live metadata was empty",
                    },
                }
        report = validate_write_report(
            model=model,
            operation=operation,
            values=values,
            values_list=values_list,
            record_ids=record_ids,
            context=context,
            fields_metadata=fields_metadata,
            metadata_source=metadata_source,
            instance=instance_name,
        )
        trusted_live_metadata = (
            metadata_source == "server"
            and isinstance(fields_metadata, dict)
            and bool(fields_metadata)
        )
        if trusted_live_metadata:
            # Burke behavior 4: capture what this write is about to overwrite,
            # here rather than in preview_write, because this is the step that
            # already holds a live Odoo connection and the step whose approval
            # record execute_approved_write reads back.
            current_state = _collect_current_state(
                ctx,
                model=model,
                operation=operation,
                record_ids=record_ids,
                values=values,
                instance=instance,
            )
            report["current_state"] = current_state
            stored = register_write_approval(
                _app_context(ctx),
                report,
                resolved_binary_values=resolved_binary_values or None,
                current_state=current_state,
            )
            report["approval_status"] = {
                "stored": stored,
                "expires_in_seconds": WRITE_APPROVAL_TTL_SECONDS,
                "source": metadata_source,
            }
        else:
            report["approval_status"] = {
                "stored": False,
                "source": metadata_source,
                "reason": (
                    "execute_approved_write requires validation against trusted "
                    "live Odoo fields_get metadata"
                ),
            }
        record_write_event(
            "validate",
            outcome=(
                "approved" if report["approval_status"].get("stored") else "rejected"
            ),
            model=model,
            operation=str(operation).strip().lower(),
            record_ids=[int(rid) for rid in record_ids or []],
            instance=instance_name,
            token=str((report.get("approval") or {}).get("token") or "") or None,
            detail=None if report.get("success") else "validation issues present",
        )
        return report
    except Exception as e:
        return {"success": False, "tool": "validate_write", "error": str(e)}


@mcp.tool(
    name="execute_approved_write",
    description="Execute a previously previewed and confirmed standard write",
    annotations=DESTRUCTIVE_TOOL,
    structured_output=True,
)
async def execute_approved_write_tool(
    ctx: Context,
    approval: Dict[str, Any],
    confirm: bool = False,
    review: Annotated[
        ElicitationResult[WriteConfirmation], Resolve(_resolve_write_confirmation)
    ] = _DIRECT_CALL_REVIEW,  # type: ignore[assignment]
) -> Dict[str, Any]:
    """Tool entry point: era-portable human confirmation, then the sync gates."""
    if review is _DIRECT_CALL_REVIEW:
        # Direct Python callers bypass MCP dependency resolution.
        decision, detail = await _elicit_write_confirmation(ctx, approval)
    else:
        data = getattr(review, "data", None)
        approved = (
            getattr(review, "action", None) == "accept"
            and data is not None
            and data.approve
        )
        decision = "approved" if approved else "declined"
        detail = str(getattr(review, "action", "declined"))
    blocked_reason = None
    if decision == "unsupported":
        blocked_reason = detail or "the client could not present a confirmation prompt"
    elif decision == "declined" and truthy_env(ELICIT_WRITES_ENV):
        # The MRTR resolver refuses the same way a human does; only the client
        # capability distinguishes "nobody was asked" from "someone said no".
        blocked_reason = _client_elicitation_gap(ctx)
    if blocked_reason is not None:
        record_write_event(
            "elicit",
            outcome="blocked",
            model=str(approval.get("model") or "") or None,
            operation=str(approval.get("operation") or "") or None,
            instance=str(approval.get("instance") or "") or None,
            token=str(approval.get("token") or "") or None,
            detail=_elicit_audit_detail(ctx, blocked_reason),
        )
        return {
            "success": False,
            "tool": "execute_approved_write",
            "error": (
                f"{ELICIT_WRITES_ENV}=1 requires a human to confirm this write, "
                f"but no human could be asked: {blocked_reason}. Refusing to "
                "execute. Run this write from a client that supports "
                f"elicitation, or unset {ELICIT_WRITES_ENV} to accept "
                "agent-only approval."
            ),
        }
    if decision == "declined":
        record_write_event(
            "elicit",
            outcome="declined",
            model=str(approval.get("model") or "") or None,
            operation=str(approval.get("operation") or "") or None,
            instance=str(approval.get("instance") or "") or None,
            token=str(approval.get("token") or "") or None,
            detail=_elicit_audit_detail(ctx, detail),
        )
        return {
            "success": False,
            "tool": "execute_approved_write",
            "error": "write declined by the human reviewer via elicitation",
        }
    return execute_approved_write(ctx, approval, confirm)


def execute_approved_write(
    ctx: Context,
    approval: Dict[str, Any],
    confirm: bool = False,
) -> Dict[str, Any]:
    """Execute create/write/unlink only after token, confirm, and env gates pass."""
    report = _execute_approved_write_gated(ctx, approval, confirm)
    safe_record_ids = [
        int(rid)
        for rid in approval.get("record_ids") or []
        if isinstance(rid, (int, str)) and str(rid).isdigit()
    ]
    record_write_event(
        "execute",
        outcome="success" if report.get("success") else "denied",
        model=str(approval.get("model") or "") or None,
        operation=str(approval.get("operation") or "") or None,
        record_ids=safe_record_ids,
        instance=str(approval.get("instance") or "") or None,
        token=str(approval.get("token") or "") or None,
        detail=report.get("error"),
    )
    return report


def _execute_approved_write_gated(
    ctx: Context,
    approval: Dict[str, Any],
    confirm: bool,
) -> Dict[str, Any]:
    """Run every write gate and the final execution; audit-free inner body."""
    try:
        is_valid, _ = verify_write_approval(approval)
        if not is_valid:
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": (
                    "approval token does not match the canonical payload; "
                    "re-run preview_write and validate_write"
                ),
            }
        app_context = _app_context(ctx)
        validation_record = require_validated_write_approval(app_context, approval)
        if validation_record is None:
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": (
                    "approval token has not been validated in this server session "
                    "or has expired; call validate_write first"
                ),
            }
        if write_approval_payload(approval) != validation_record.get("payload"):
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": "approval payload does not match the stored validation record",
            }
        if not confirm:
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": "confirm=true is required for destructive execution",
            }
        if not writes_enabled():
            return {
                "success": False,
                "tool": "execute_approved_write",
                "error": "write execution disabled; set ODOO_MCP_ENABLE_WRITES=1 to enable",
            }

        model = str(approval.get("model", ""))
        operation = str(approval.get("operation", "")).strip().lower()
        validate_model_name(model)
        if operation not in {"create", "write", "unlink"}:
            raise ValueError("operation must be one of create, write, or unlink")

        values = dict(approval.get("values") or {})
        resolved_binary_values = validation_record.get("resolved_binary_values") or {}
        for field_name, real_base64 in resolved_binary_values.items():
            # The client only ever held a sha256 fingerprint for these fields
            # (see _resolve_binary_from_path_fields) — swap in the real base64
            # that the server read from disk at validate_write time.
            if field_name in values:
                values[field_name] = real_base64
        values_list = approval.get("values_list")
        record_ids = [int(record_id) for record_id in approval.get("record_ids") or []]
        context = dict(approval.get("context") or {})
        kwargs: Dict[str, Any] = {"context": context} if context else {}
        if operation == "create" and values_list is not None:
            args: List[Any] = [list(values_list)]
        elif operation == "create":
            args = [values]
        elif operation == "write":
            args = [record_ids, values]
        else:
            args = [record_ids]

        approval_instance = str(approval.get("instance") or "") or None
        if (
            approval_instance is None
            or approval_instance == _srv().resolve_default_instance_name()
        ):
            odoo = app_context.odoo
        else:
            _, odoo = app_context.get_client(approval_instance)

        result = odoo.execute_method(model, operation, *args, **kwargs)
        app_context.write_approvals.pop(str(approval.get("token", "")), None)
        return {
            "success": True,
            "tool": "execute_approved_write",
            "model": model,
            "operation": operation,
            "result": result,
            "instance": approval_instance or _srv().resolve_default_instance_name(),
        }
    except Exception as e:
        return {"success": False, "tool": "execute_approved_write", "error": str(e)}


def _build_chatter_payload(
    *,
    model: str,
    record_id: int,
    body: str,
    message_type: str,
    subtype_xmlid: Optional[str],
    partner_ids: Optional[List[int]],
    attachment_ids: Optional[List[int]],
    instance: str = "default",
) -> Dict[str, Any]:
    """Build the canonical message_post call payload (deterministic ordering)."""
    kwargs: Dict[str, Any] = {"body": body, "message_type": message_type}
    if subtype_xmlid:
        kwargs["subtype_xmlid"] = subtype_xmlid
    if partner_ids:
        kwargs["partner_ids"] = [int(pid) for pid in partner_ids]
    if attachment_ids:
        kwargs["attachment_ids"] = [int(aid) for aid in attachment_ids]
    return {
        "model": model,
        "method": "message_post",
        "record_ids": [int(record_id)],
        "kwargs": kwargs,
        "instance": instance or "default",
    }


@mcp.tool(
    description=(
        "Post a chatter message on a mail.thread record. Default mode requires "
        "an approval token returned from a preview call; set MCP_CHATTER_DIRECT=1 "
        "to bypass and post immediately."
    ),
    annotations=DESTRUCTIVE_TOOL,
    structured_output=True,
)
def chatter_post(
    ctx: Context,
    model: str,
    record_id: int,
    body: str,
    message_type: str = "comment",
    subtype_xmlid: Optional[str] = None,
    partner_ids: Optional[List[int]] = None,
    attachment_ids: Optional[List[int]] = None,
    approval: Optional[Dict[str, Any]] = None,
    confirm: bool = False,
    instance: Optional[str] = None,
) -> Dict[str, Any]:
    """Post a message on the chatter of a mail.thread-derived record.

    Modes:
    - Default (gated): first call returns ``mode=preview`` with an approval
      token. Re-call with the same arguments plus ``approval`` and
      ``confirm=true`` to send.
    - Direct (``MCP_CHATTER_DIRECT=1``): the message is posted on the first
      call without a token.

    Allowed ``message_type`` values: ``comment`` (default), ``notification``.

    Both modes require ``ODOO_MCP_ENABLE_WRITES=1``: posting to the chatter is a
    write, and on a ``comment`` it notifies followers by email.
    """
    try:
        # Checked at entry, ahead of both the preview/token branch and the
        # MCP_CHATTER_DIRECT branch, so a server that cannot execute the post
        # never hands out an approval token it would later refuse to honour.
        if not writes_enabled():
            return {
                "success": False,
                "tool": "chatter_post",
                "error": "write execution disabled; set ODOO_MCP_ENABLE_WRITES=1 to enable",
            }

        instance_name, odoo = _resolve_odoo(ctx, instance)
        validate_model_name(model)
        if record_id < 1:
            raise ValueError("record_id must be greater than 0")
        body_text = (body or "").strip()
        if not body_text:
            raise ValueError("body must be a non-empty string")
        if message_type not in {"comment", "notification"}:
            raise ValueError("message_type must be 'comment' or 'notification'.")

        canonical = _build_chatter_payload(
            model=model,
            record_id=record_id,
            body=body_text,
            message_type=message_type,
            subtype_xmlid=subtype_xmlid,
            partner_ids=partner_ids,
            attachment_ids=attachment_ids,
            instance=instance_name,
        )
        token = build_approval_token(canonical)

        direct_mode = chatter_direct_enabled()
        if direct_mode:
            result = odoo.execute_method(
                model,
                "message_post",
                [record_id],
                **canonical["kwargs"],
            )
            record_write_event(
                "chatter_post",
                outcome="success",
                model=model,
                operation="message_post",
                record_ids=[record_id],
                instance=instance_name,
                detail="direct mode",
            )
            return {
                "success": True,
                "mode": "direct",
                "model": model,
                "record_id": record_id,
                "approval_required": False,
                "result": result,
            }

        if approval is None:
            return {
                "success": True,
                "mode": "preview",
                "model": model,
                "record_id": record_id,
                "approval": {**canonical, "token": token},
                "warnings": [
                    "Preview only. Re-call chatter_post with the returned approval "
                    "and confirm=true to actually post."
                ],
            }

        provided_token = str(approval.get("token", ""))
        if provided_token != token:
            raise ValueError(
                "Approval token does not match the chatter payload — re-run preview."
            )
        if not confirm:
            raise ValueError(
                "confirm=true is required to execute an approved chatter post."
            )

        result = odoo.execute_method(
            model,
            "message_post",
            [record_id],
            **canonical["kwargs"],
        )
        record_write_event(
            "chatter_post",
            outcome="success",
            model=model,
            operation="message_post",
            record_ids=[record_id],
            instance=instance_name,
            token=provided_token,
        )
        return {
            "success": True,
            "mode": "execute",
            "model": model,
            "record_id": record_id,
            "approval_required": True,
            "result": result,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool(
    description="Execute a custom method on an Odoo model",
    annotations=DESTRUCTIVE_TOOL,
    structured_output=True,
)
def execute_method(
    ctx: Context,
    model: Annotated[
        str, Field(description="Technical Odoo model name, for example 'res.partner'.")
    ],
    method: Annotated[
        str,
        Field(
            description=(
                "Odoo model method to call; direct create, write, and unlink are blocked."
            )
        ),
    ],
    args: Annotated[
        Optional[List[Any]], Field(description="Optional positional method arguments.")
    ] = None,
    kwargs: Annotated[
        Optional[Dict[str, Any]], Field(description="Optional keyword method arguments.")
    ] = None,
    instance: Annotated[
        Optional[str],
        Field(description="Optional configured Odoo instance name; uses the default if omitted."),
    ] = None,
) -> Dict[str, Any]:
    """
    Execute a custom method on an Odoo model

    Parameters:
        model: The model name (e.g., 'res.partner')
        method: Method name to execute
        args: Positional arguments
        kwargs: Keyword arguments

    Returns:
        Dictionary containing:
        - success: Boolean indicating success
        - result: Result of the method (if success)
        - error: Error message (if failure)
    """
    try:
        validate_model_name(model)
        validate_method_name(method)
        safety = classify_method_safety(method)
        if method in DESTRUCTIVE_METHODS:
            return {
                "success": False,
                "error": (
                    "Direct execute_method blocks create/write/unlink. Use "
                    "preview_write -> validate_write -> execute_approved_write."
                ),
            }
        # The allowlist is resolved per instance, so the instance has to be
        # known before the gate can answer: a method reviewed for staging must
        # not open the same door on production.
        instance_name, odoo = _resolve_odoo(ctx, instance)
        refusal = check_rate(instance_name, "execute_method")
        if refusal is not None:
            return refusal
        review_required = safety["safety"] in {"side_effect", "unknown"}
        if (
            review_required
            and not side_effect_method_allowed(model, method, instance_name)
            and not truthy_env("ODOO_MCP_ALLOW_UNKNOWN_METHODS")
        ):
            return {
                "success": False,
                "error": (
                    "Unreviewed side-effect methods are blocked by default on "
                    f"instance '{instance_name}'. Review custom source, then add "
                    "the exact 'model.method' to the policy file "
                    "(ODOO_MCP_POLICY_FILE, default ./odoo_mcp_policy.json, "
                    "re-read on every request — see odoo_mcp_policy.json.example). "
                    "allowed_side_effect_methods takes either a flat list, which "
                    "applies to every instance, or an object keyed by instance "
                    f"name, where only the '{instance_name}' key is consulted "
                    "here. ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS=model.method "
                    "applies to every instance; set "
                    "ODOO_MCP_ALLOW_UNKNOWN_METHODS=1 only for trusted "
                    "deployments."
                ),
                "classification": safety,
            }
        args = args or []
        kwargs = kwargs or {}

        search_methods = ["search", "search_count", "search_read"]
        if method in search_methods and args:
            normalized_args = list(args)
            if len(normalized_args) > 0:
                normalized_args[0] = normalize_domain_input(normalized_args[0])
                args = normalized_args

        try:
            result = odoo.execute_method(model, method, *args, **kwargs)
        except xmlrpc.client.Fault as fault:
            if _NONE_MARSHAL_FAULT_MARKER not in str(fault.faultString or ""):
                raise
            # Odoo already executed and committed the call; only serializing
            # the None return value failed. Report success, not a phantom
            # failure that tempts a retry of a side-effect method.
            return {
                "success": True,
                "result": None,
                "warning": (
                    "Method executed and committed server-side; Odoo could not "
                    "marshal its None return value over XML-RPC, so no result "
                    "payload is available. Verify state with a read if needed."
                ),
            }
        return {"success": True, "result": result}
    except Exception as e:
        return {"success": False, "error": str(e)}
