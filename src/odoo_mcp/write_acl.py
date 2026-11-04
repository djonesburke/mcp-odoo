"""Write-path model and field allowlist (``write_acl``), fail closed.

The read-path ``field_acl`` (:mod:`field_policy`) decides what a profile may
*see*. Nothing decided what a write-enabled profile may *change*: with
``ODOO_MCP_ENABLE_WRITES=1`` every model and field the Odoo user can write was
reachable through ``preview_write`` -> ``validate_write`` ->
``execute_approved_write``, plus ``chatter_post`` and allowlisted side-effect
methods. ``write_acl`` narrows a write-enabled profile to named record classes.

It lives in the same policy file as ``field_acl`` (``ODOO_MCP_FIELD_POLICY_FILE``,
else ``ODOO_MCP_POLICY_FILE``, else ``./odoo_mcp_policy.json``)::

    {
      "write_acl": {
        "default": {
          "product.supplierinfo": {
            "operations": {
              "create": {"fields": ["product_tmpl_id", "partner_id", "price"],
                         "max_records": 20},
              "write":  {"fields": ["price", "delay"], "max_records": 100}
            }
          },
          "product.template": {
            "operations": {"write": {"fields": ["categ_id", "barcode"],
                                     "max_records": 100}},
            "guards": [{"field": "categ_id", "comodel": "product.category",
                        "must_match": ["property_cost_method"]}]
          }
        }
      }
    }

Semantics:

- **No ``write_acl`` key: no change.** Existing deployments are unaffected.
- **A ``write_acl`` key governs every instance.** An instance with no entry may
  write nothing; there is no ``*`` wildcard and no inherited fallback, so a
  rule written for staging never opens production.
- On a governed instance a write is refused unless its model is listed, its
  operation is listed for that model, every value key is in that operation's
  ``fields``, the record count is within ``max_records``, and the ``context``
  carries no key outside :data:`ALLOWED_CONTEXT_KEYS` (a ``default_*`` key
  would set a field the list does not name).
- A **guard** applies when its ``field`` is in the values of a ``write``: every
  touched record's current value of ``field`` and the new value must point at
  ``comodel`` records that are equal on every ``must_match`` field. Any read
  failure, missing record or missing field refuses the write.
- **Record scope** (optional): ``create_context`` pins ``default_*`` keys a
  create must carry; ``record_domain`` must match every record a write or
  unlink names, read from Odoo; ``one2many`` limits line commands to create
  and update, with listed line fields, on the touched records' own lines.
- ``chatter_post`` is refused on a governed instance, and ``execute_method``
  runs only methods the classifier calls read-only there: the side-effect
  allowlist and ``ODOO_MCP_ALLOW_UNKNOWN_METHODS`` do not apply.
- The policy is re-read on every check, and checked again at execute time, so
  tightening the file takes effect without a restart and a token validated
  under an older file cannot execute past a newer one. The scope loaded at
  startup is kept too, and a write must pass both: editing the file while the
  server runs can narrow the scope but never widen or remove it.
- ``ODOO_MCP_REQUIRE_WRITE_ACL=1`` makes the key mandatory: a missing file or
  key aborts startup and, at runtime, refuses every write, as a malformed
  block does. A scoped connector sets it, so deleting the key is no way out.
- A malformed ``write_acl`` refuses every write at check time and aborts
  startup (:func:`report_write_acl`), as a malformed ``field_acl`` does.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

from .field_policy import field_policy_file_path
from .tool_helpers import truthy_env

WRITE_ACL_KEY = "write_acl"
REQUIRE_WRITE_ACL_ENV = "ODOO_MCP_REQUIRE_WRITE_ACL"
OPERATIONS = frozenset({"create", "write", "unlink"})
# Context keys that cannot change which fields a write sets. Everything else
# is refused: ``default_*`` keys set fields on create, and keys such as
# ``tracking_disable`` hide the change from the record's chatter.
ALLOWED_CONTEXT_KEYS = frozenset({"lang", "tz"})


class WriteAclError(ValueError):
    """Raised when a ``write_acl`` block is present but malformed (fail closed)."""


@dataclass(frozen=True)
class OperationRule:
    fields: FrozenSet[str]
    max_records: int


@dataclass(frozen=True)
class Guard:
    field: str
    comodel: str
    must_match: Tuple[str, ...]


@dataclass(frozen=True)
class One2manyRule:
    """Line edits through a one2many: which line fields, and on which comodel."""

    comodel: str
    inverse: str
    fields: FrozenSet[str]


@dataclass(frozen=True)
class ModelWriteRule:
    operations: Dict[str, OperationRule]
    guards: Tuple[Guard, ...]
    # Context keys a create must carry, each pinned to allowed values. This
    # is how a readonly selection such as account.move move_type is chosen:
    # through its default_* key, never as a value.
    create_context: Dict[str, FrozenSet[Any]] = field(default_factory=dict)
    # Every record a write or unlink touches must match this domain when the
    # guard reads it (for example state = draft).
    record_domain: Tuple[Any, ...] = ()
    one2many: Dict[str, One2manyRule] = field(default_factory=dict)


class WriteAcl:
    """Validated per-(instance, model) write rules."""

    def __init__(
        self,
        by_instance: Optional[Dict[str, Dict[str, ModelWriteRule]]],
        path: Optional[str] = None,
    ) -> None:
        # ``None`` means no write_acl key at all (pass-through); an empty
        # mapping means the key is present and allows nothing anywhere.
        self._by_instance = by_instance
        self.path = path

    def active(self) -> bool:
        return self._by_instance is not None

    def instances(self) -> List[str]:
        return sorted(self._by_instance or {})

    def governs(self, instance: str) -> bool:
        """True when writes on ``instance`` are limited by this policy."""
        return self._by_instance is not None

    def rule(self, instance: str, model: str) -> Optional[ModelWriteRule]:
        if self._by_instance is None:
            return None
        return self._by_instance.get(instance, {}).get(model)

    def check_write(
        self,
        instance: str,
        model: str,
        operation: str,
        values: Optional[Dict[str, Any]] = None,
        values_list: Optional[List[Dict[str, Any]]] = None,
        record_ids: Optional[Iterable[Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Return a refusal string, or ``None`` when the payload is in scope.

        Reads nothing from Odoo; guards are checked by :func:`check_guards`.
        Refusals name the model, operation and field names, never a value.
        """
        if self._by_instance is None:
            return None
        op = str(operation or "").strip().lower()
        rule = self.rule(instance, model)
        if rule is None:
            return (
                f"write_acl ({self.path}): model {model} is not writable on "
                f"instance '{instance}' with this connector."
            )
        op_rule = rule.operations.get(op)
        if op_rule is None:
            return (
                f"write_acl ({self.path}): operation '{op}' is not allowed on "
                f"{model} (allowed: {sorted(rule.operations) or 'none'})."
            )
        pinned = rule.create_context if op == "create" else {}
        allowed_context = ALLOWED_CONTEXT_KEYS | set(pinned)
        if context:
            extra = sorted(str(key) for key in context if key not in allowed_context)
            if extra:
                return (
                    f"write_acl ({self.path}): context keys {extra} are not "
                    f"allowed on a scoped write (allowed: {sorted(allowed_context)})."
                )
        for key, allowed_values in sorted(pinned.items()):
            if (context or {}).get(key) not in allowed_values:
                return (
                    f"write_acl ({self.path}): a create on {model} must set context "
                    f"{key} to one of {sorted(allowed_values)} with this connector."
                )
        # Every shape a caller can pass is checked, whichever one the
        # operation actually uses: values and values_list both, and record_ids
        # for any write or unlink.
        entries: List[Dict[str, Any]] = [values] if values else []
        if values_list is not None:
            entries += [entry for entry in values_list if isinstance(entry, dict)]
        if op in {"write", "unlink"}:
            count = len(list(record_ids or []))
        else:
            count = len(values_list) if values_list is not None else 1
        if count > op_rule.max_records:
            return (
                f"write_acl ({self.path}): {count} records exceeds the "
                f"{op_rule.max_records}-record limit for {op} on {model}; split "
                "the batch."
            )
        names: set[str] = set()
        for entry in entries:
            names.update(str(key) for key in entry)
        denied = sorted(names - op_rule.fields)
        if denied:
            return (
                f"write_acl ({self.path}): fields {denied} are not writable on "
                f"{model} for {op} with this connector (allowed: "
                f"{sorted(op_rule.fields)})."
            )
        for entry in entries:
            for name, sub in sorted(rule.one2many.items()):
                if name in entry:
                    refusal = self._check_line_commands(
                        model, op, name, sub, entry[name]
                    )
                    if refusal is not None:
                        return refusal
        return None

    def _check_line_commands(
        self, model: str, op: str, name: str, sub: One2manyRule, commands: Any
    ) -> Optional[str]:
        """Static shape check of one2many commands: create (0) and update (1) only.

        Update ids are checked against the touched records by
        :func:`check_guards`, which reads them.
        """
        bad = (
            f"write_acl ({self.path}): {model}.{name} takes only create (0) and "
            f"update (1) line commands with this connector, each with a values "
            f"object limited to {sorted(sub.fields)}"
        )
        if not isinstance(commands, (list, tuple)):
            return f"{bad}."
        for command in commands:
            if (
                not isinstance(command, (list, tuple))
                or len(command) != 3
                or not isinstance(command[2], dict)
            ):
                return f"{bad}."
            code, line_id, line_values = command
            if code == 0 and line_id in (0, False):
                pass
            elif (
                code == 1
                and op == "write"
                and isinstance(line_id, int)
                and not isinstance(line_id, bool)
            ):
                pass
            else:
                return f"{bad}; update (1) is allowed only on a write."
            denied = sorted(set(map(str, line_values)) - sub.fields)
            if denied:
                return (
                    f"write_acl ({self.path}): line fields {denied} are not "
                    f"writable on {model}.{name} with this connector (allowed: "
                    f"{sorted(sub.fields)})."
                )
        return None

    def check_chatter(self, instance: str) -> Optional[str]:
        if self._by_instance is None:
            return None
        return (
            f"write_acl ({self.path}): chatter_post is not available on instance "
            f"'{instance}' with this connector; it is limited to the record "
            "edits its write_acl lists."
        )

    def check_side_effect_method(
        self, instance: str, model: str, method: str
    ) -> Optional[str]:
        if self._by_instance is None:
            return None
        return (
            f"write_acl ({self.path}): {model}.{method} is not a read-only "
            f"method, and instance '{instance}' runs only read-only methods "
            "with this connector."
        )


def _id_of(value: Any) -> Any:
    """Normalize a many2one read value ([id, name] / id / False) to an id."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else False
    return value


def _comparable(value: Any) -> Any:
    """Make a read value comparable: many2one -> id, x2many -> sorted ids."""
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and isinstance(value[0], int) and isinstance(value[1], str):
            return value[0]
        return tuple(sorted(value))
    return value


def _check_record_scope(
    acl: WriteAcl,
    odoo: Any,
    model: str,
    op: str,
    rule: ModelWriteRule,
    values: Optional[Dict[str, Any]],
    record_ids: Optional[Iterable[Any]],
) -> Optional[str]:
    """Refuse unless every touched record matches ``record_domain`` and every
    line a one2many update (1) names belongs to a touched record."""
    if op not in {"write", "unlink"}:
        return None
    ids = sorted({int(rid) for rid in record_ids or []})
    line_updates: Dict[str, List[int]] = {}
    for name in rule.one2many:
        commands = (values or {}).get(name)
        if not isinstance(commands, (list, tuple)):
            commands = []
        line_updates[name] = sorted(
            {
                cmd[1]
                for cmd in commands
                if isinstance(cmd, (list, tuple))
                and len(cmd) == 3
                and cmd[0] == 1
                and isinstance(cmd[1], int)
                and not isinstance(cmd[1], bool)
            }
        )
    if not rule.record_domain and not any(line_updates.values()):
        return None
    if not ids:
        return f"write_acl ({acl.path}): a {op} on {model} must name its records."
    try:
        if rule.record_domain:
            found = odoo.execute_method(
                model,
                "search",
                [["id", "in", ids], *rule.record_domain],
                context={"active_test": False},
            )
            if sorted(int(i) for i in found or []) != ids:
                return (
                    f"write_acl ({acl.path}): some {model} records are outside "
                    f"this connector's scope {list(rule.record_domain)}; nothing "
                    "was changed. Ask Dalton."
                )
        for name, line_ids in sorted(line_updates.items()):
            if not line_ids:
                continue
            sub = rule.one2many[name]
            lines = odoo.execute_method(
                sub.comodel,
                "read",
                line_ids,
                [sub.inverse],
                context={"active_test": False},
            )
            owners = {_id_of(row.get(sub.inverse)) for row in lines or []}
            if len(lines or []) != len(line_ids) or not owners <= set(ids):
                return (
                    f"write_acl ({acl.path}): {model}.{name} updates lines that "
                    f"do not belong to the {model} records named; refusing the write."
                )
    except Exception as exc:  # fail closed on any read error
        return (
            f"write_acl ({acl.path}): the scope of {model} records could not be "
            f"checked ({type(exc).__name__}); refusing the write."
        )
    return None


def check_guards(
    acl: WriteAcl,
    odoo: Any,
    instance: str,
    model: str,
    operation: str,
    values: Optional[Dict[str, Any]],
    record_ids: Optional[Iterable[Any]],
    values_list: Optional[List[Dict[str, Any]]] = None,
) -> Optional[str]:
    """Return a refusal string unless every applicable guard holds.

    Reads the touched records' current ``field`` and the old and new
    ``comodel`` records through ``odoo``. Fails closed on every error.
    """
    if isinstance(acl, WriteAclSet):
        for member in acl.members:
            refusal = check_guards(
                member,
                odoo,
                instance,
                model,
                operation,
                values,
                record_ids,
                values_list,
            )
            if refusal is not None:
                return refusal
        return None
    rule = acl.rule(instance, model)
    if rule is None:
        return None
    op = str(operation or "").strip().lower()
    refusal = _check_record_scope(acl, odoo, model, op, rule, values, record_ids)
    if refusal is not None:
        return refusal
    if not rule.guards:
        return None
    create_entries = [values or {}]
    create_entries += [e for e in values_list or [] if isinstance(e, dict)]
    for guard in rule.guards:
        if op == "create" and any(guard.field in entry for entry in create_entries):
            return (
                f"write_acl ({acl.path}): {guard.field} cannot be set on create "
                f"of {model} with this connector; it is guarded on write only."
            )
        if op != "write" or not values or guard.field not in values:
            continue
        ids = [int(rid) for rid in record_ids or []]
        new_id = _id_of(values[guard.field])
        if not isinstance(new_id, int) or isinstance(new_id, bool) or not ids:
            return (
                f"write_acl ({acl.path}): {guard.field} on {model} must be set "
                f"to one {guard.comodel} id on named records."
            )
        try:
            current = odoo.execute_method(
                model,
                "read",
                ids,
                [guard.field],
                context={"active_test": False},
            )
            old_ids = {_id_of(row.get(guard.field)) for row in current}
            if len(current) != len(set(ids)):
                return (
                    f"write_acl ({acl.path}): could not read {guard.field} on "
                    f"every {model} record; refusing the write."
                )
            if False in old_ids:
                # No current target means nothing to compare against, so this
                # is not a move between equal records. Ask Dalton.
                return (
                    f"write_acl ({acl.path}): some {model} records have no "
                    f"{guard.field} now; setting a first {guard.comodel} is not a "
                    "move between equal ones, so this connector refuses it. Ask Dalton."
                )
            category_ids = sorted({new_id, *old_ids})
            categories = odoo.execute_method(
                guard.comodel,
                "read",
                category_ids,
                list(guard.must_match),
                context={"active_test": False},
            )
        except Exception as exc:  # fail closed on any read error
            return (
                f"write_acl ({acl.path}): guard on {model}.{guard.field} could "
                f"not be checked ({type(exc).__name__}); refusing the write."
            )
        by_id = {row.get("id"): row for row in categories if isinstance(row, dict)}
        if set(by_id) != set(category_ids):
            return (
                f"write_acl ({acl.path}): {guard.comodel} records "
                f"{sorted(set(category_ids) - set(by_id))} could not be read; "
                "refusing the write."
            )
        target = by_id[new_id]
        for old_id in sorted(old_ids):
            source = by_id[old_id]
            missing = [
                name
                for name in guard.must_match
                if name not in source or name not in target
            ]
            if missing:
                return (
                    f"write_acl ({acl.path}): {guard.comodel} fields {missing} "
                    "could not be read; refusing the write."
                )
            differ = [
                name
                for name in guard.must_match
                if _comparable(source[name]) != _comparable(target[name])
            ]
            if differ:
                return (
                    f"write_acl ({acl.path}): moving {model} from {guard.comodel} "
                    f"{old_id} to {new_id} changes {differ}; this connector moves "
                    "only between categories equal on those fields. Ask Dalton."
                )
    return None


def _parse_operation(where: str, spec: Any) -> OperationRule:
    if not isinstance(spec, dict):
        raise WriteAclError(f"{where} must be an object")
    fields = spec.get("fields")
    if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
        raise WriteAclError(f"{where}.fields must be a list of field names")
    max_records = spec.get("max_records")
    if (
        not isinstance(max_records, int)
        or isinstance(max_records, bool)
        or max_records < 1
    ):
        raise WriteAclError(f"{where}.max_records must be a positive integer")
    return OperationRule(
        fields=frozenset(f.strip() for f in fields if f.strip()),
        max_records=max_records,
    )


def _parse_guard(where: str, spec: Any) -> Guard:
    if not isinstance(spec, dict):
        raise WriteAclError(f"{where} must be an object")
    field = spec.get("field")
    comodel = spec.get("comodel")
    must_match = spec.get("must_match")
    if not isinstance(field, str) or not field.strip():
        raise WriteAclError(f"{where}.field must be a field name")
    if not isinstance(comodel, str) or not comodel.strip():
        raise WriteAclError(f"{where}.comodel must be a model name")
    if (
        not isinstance(must_match, list)
        or not must_match
        or not all(isinstance(f, str) and f.strip() for f in must_match)
    ):
        raise WriteAclError(
            f"{where}.must_match must be a non-empty list of field names"
        )
    return Guard(
        field=field.strip(),
        comodel=comodel.strip(),
        must_match=tuple(f.strip() for f in must_match),
    )


def _parse_create_context(
    where: str, spec: Any, ops: Dict[str, Any]
) -> Dict[str, FrozenSet[Any]]:
    if not isinstance(spec, dict):
        raise WriteAclError(f"{where} must be an object")
    if spec and "create" not in ops:
        raise WriteAclError(f"{where} needs a create operation")
    pinned: Dict[str, FrozenSet[Any]] = {}
    for key, allowed in spec.items():
        if not str(key).startswith("default_"):
            raise WriteAclError(f"{where}: only default_* keys can be pinned")
        if (
            not isinstance(allowed, list)
            or not allowed
            or not all(isinstance(v, str) for v in allowed)
        ):
            raise WriteAclError(f"{where}.{key} must be a non-empty list of values")
        pinned[str(key)] = frozenset(allowed)
    return pinned


def _parse_record_domain(where: str, spec: Any) -> Tuple[Any, ...]:
    if not isinstance(spec, list) or not all(
        isinstance(term, list)
        and len(term) == 3
        and isinstance(term[0], str)
        and isinstance(term[1], str)
        for term in spec
    ):
        # Plain [field, operator, value] terms only, implicitly ANDed: no
        # '|' or '!' that could turn a narrowing domain into a wider one.
        raise WriteAclError(f"{where} must be a list of [field, operator, value] terms")
    return tuple(spec)


def _parse_one2many(
    where: str, spec: Any, ops: Dict[str, Any]
) -> Dict[str, One2manyRule]:
    if not isinstance(spec, dict):
        raise WriteAclError(f"{where} must be an object")
    rules: Dict[str, One2manyRule] = {}
    for name, sub in spec.items():
        if not isinstance(sub, dict) or set(sub) - {"comodel", "inverse", "fields"}:
            raise WriteAclError(
                f"{where}.{name} must be an object with comodel, inverse and fields"
            )
        comodel, inverse, fields = (
            sub.get("comodel"),
            sub.get("inverse"),
            sub.get("fields"),
        )
        if not isinstance(comodel, str) or not comodel.strip():
            raise WriteAclError(f"{where}.{name}.comodel must be a model name")
        if not isinstance(inverse, str) or not inverse.strip():
            raise WriteAclError(f"{where}.{name}.inverse must be a field name")
        if not isinstance(fields, list) or not all(isinstance(f, str) for f in fields):
            raise WriteAclError(f"{where}.{name}.fields must be a list of field names")
        if not any(
            name in (op_spec or {}).get("fields", []) for op_spec in ops.values()
        ):
            raise WriteAclError(f"{where}.{name} is not in any operation's fields")
        rules[str(name)] = One2manyRule(
            comodel=comodel.strip(),
            inverse=inverse.strip(),
            fields=frozenset(f.strip() for f in fields if f.strip()),
        )
    return rules


def parse_write_acl(data: Dict[str, Any], path: Optional[str] = None) -> WriteAcl:
    """Validate the ``write_acl`` block of a policy object."""
    if WRITE_ACL_KEY not in data:
        return WriteAcl(None, path)
    acl = data[WRITE_ACL_KEY]
    if not isinstance(acl, dict):
        raise WriteAclError(f"'{WRITE_ACL_KEY}' must be an object")
    by_instance: Dict[str, Dict[str, ModelWriteRule]] = {}
    for instance, models in acl.items():
        if not isinstance(models, dict):
            raise WriteAclError(f"write_acl['{instance}'] must be an object")
        rules: Dict[str, ModelWriteRule] = {}
        for model, spec in models.items():
            where = f"write_acl['{instance}']['{model}']"
            if model == "*":
                raise WriteAclError(f"{where}: no wildcard; name each model")
            if not isinstance(spec, dict):
                raise WriteAclError(f"{where} must be an object")
            unknown = sorted(
                set(spec)
                - {
                    "operations",
                    "guards",
                    "comment",
                    "create_context",
                    "record_domain",
                    "one2many",
                }
            )
            if unknown:
                raise WriteAclError(f"{where} has unknown keys {unknown}")
            ops = spec.get("operations")
            if not isinstance(ops, dict) or not ops:
                raise WriteAclError(f"{where}.operations must be a non-empty object")
            bad_ops = sorted(set(ops) - OPERATIONS)
            if bad_ops:
                raise WriteAclError(
                    f"{where}.operations has unknown operations {bad_ops}"
                )
            guards_raw = spec.get("guards", [])
            if not isinstance(guards_raw, list):
                raise WriteAclError(f"{where}.guards must be a list")
            rules[model] = ModelWriteRule(
                operations={
                    op: _parse_operation(f"{where}.operations.{op}", op_spec)
                    for op, op_spec in ops.items()
                },
                guards=tuple(
                    _parse_guard(f"{where}.guards[{i}]", g)
                    for i, g in enumerate(guards_raw)
                ),
                create_context=_parse_create_context(
                    f"{where}.create_context", spec.get("create_context", {}), ops
                ),
                record_domain=_parse_record_domain(
                    f"{where}.record_domain", spec.get("record_domain", [])
                ),
                one2many=_parse_one2many(
                    f"{where}.one2many", spec.get("one2many", {}), ops
                ),
            )
        by_instance[str(instance)] = rules
    return WriteAcl(by_instance, path)


def load_write_acl() -> WriteAcl:
    """Load ``write_acl`` from the field-policy file; raise WriteAclError if malformed.

    Re-read on every call: writes are rare next to reads, and a cached copy
    would let a token validated under an older, wider file execute after the
    file was narrowed.
    """
    path = field_policy_file_path()
    if path is None:
        return WriteAcl(None, None)
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WriteAclError(f"Cannot read write policy file {path}: {exc}")
    if not isinstance(data, dict):
        raise WriteAclError(f"Write policy file {path} must contain an object")
    return parse_write_acl(data, path)


class _BrokenWriteAcl(WriteAcl):
    """Stand-in for a malformed or required-but-missing scope: allows nothing."""

    def __init__(self, error: str) -> None:
        super().__init__({}, None)
        self.error = error

    def check_write(
        self, instance: str, model: str, *args: Any, **kwargs: Any
    ) -> Optional[str]:
        return f"write_acl cannot be used, so every write is refused: {self.error}"

    def check_chatter(self, instance: str) -> Optional[str]:
        return f"write_acl cannot be used, so chatter_post is refused: {self.error}"

    def check_side_effect_method(
        self, instance: str, model: str, method: str
    ) -> Optional[str]:
        return f"write_acl cannot be used, so side-effect methods are refused: {self.error}"


class WriteAclSet(WriteAcl):
    """Several scopes a write must satisfy at once (startup and current file)."""

    def __init__(self, members: List[WriteAcl]) -> None:
        super().__init__(None, None)
        self.members = members

    def active(self) -> bool:
        return any(m.active() for m in self.members)

    def governs(self, instance: str) -> bool:
        return any(m.governs(instance) for m in self.members)

    def check_write(self, *args: Any, **kwargs: Any) -> Optional[str]:
        for member in self.members:
            refusal = member.check_write(*args, **kwargs)
            if refusal is not None:
                return refusal
        return None

    def check_chatter(self, instance: str) -> Optional[str]:
        for member in self.members:
            refusal = member.check_chatter(instance)
            if refusal is not None:
                return refusal
        return None

    def check_side_effect_method(
        self, instance: str, model: str, method: str
    ) -> Optional[str]:
        for member in self.members:
            refusal = member.check_side_effect_method(instance, model, method)
            if refusal is not None:
                return refusal
        return None


# The scope the server started with (set by report_write_acl at startup).
_startup_acl: Optional[WriteAcl] = None


def reset_write_acl_snapshot() -> None:
    """Drop the startup scope (intended for tests)."""
    global _startup_acl
    _startup_acl = None


def _load_checked() -> WriteAcl:
    """Load the file, then enforce ODOO_MCP_REQUIRE_WRITE_ACL; raise if unusable."""
    acl = load_write_acl()
    if truthy_env(REQUIRE_WRITE_ACL_ENV) and not acl.active():
        raise WriteAclError(
            f"{REQUIRE_WRITE_ACL_ENV} is set but the policy file "
            f"({acl.path or 'none configured'}) has no '{WRITE_ACL_KEY}' key"
        )
    return acl


def current_write_acl() -> WriteAcl:
    """The scope for this call: the startup scope and the file as it reads now.

    A malformed file, or a missing scope while one is required, yields a
    refuse-all policy. Once the server started scoped, the startup scope stays
    in force, so the file can narrow it but not widen or remove it.
    """
    try:
        current = _load_checked()
    except WriteAclError as exc:
        current = _BrokenWriteAcl(str(exc))
    if _startup_acl is None or not _startup_acl.active():
        return current
    return WriteAclSet([_startup_acl, current])


def write_acl_posture() -> Dict[str, Any]:
    """Non-secret posture: whether write_acl is active and what it names."""
    try:
        acl = load_write_acl()
    except WriteAclError as exc:
        return {"active": True, "error": str(exc), "writable": {}}
    if not acl.active():
        return {"active": False, "required": truthy_env(REQUIRE_WRITE_ACL_ENV)}
    writable: Dict[str, Dict[str, List[str]]] = {}
    for instance in acl.instances():
        writable[instance] = {
            model: sorted(rule.operations)
            for model, rule in sorted((acl._by_instance or {})[instance].items())
        }
    return {
        "active": True,
        "required": truthy_env(REQUIRE_WRITE_ACL_ENV),
        "startup_scope_pinned": _startup_acl is not None and _startup_acl.active(),
        "file": acl.path,
        "writable": writable,
    }


def report_write_acl() -> Tuple[List[str], Optional[WriteAclError]]:
    """Startup lines for write_acl plus a fatal error when it is malformed.

    Also records the startup scope that every later write must satisfy.
    """
    global _startup_acl
    try:
        acl = _load_checked()
    except WriteAclError as exc:
        return (
            [
                f"[odoo-mcp] WRITE ACL ERROR: {exc} — refusing to start rather "
                "than running with an unreadable write scope."
            ],
            exc,
        )
    _startup_acl = acl
    if not acl.active():
        return (
            ["[odoo-mcp] write ACL: none — writes are not narrowed by model."],
            None,
        )
    posture = write_acl_posture()
    scoped = "; ".join(
        f"{instance}: {', '.join(models) or 'nothing'}"
        for instance, models in posture["writable"].items()
    )
    return (
        [
            f"[odoo-mcp] write ACL: {acl.path} (writable models — {scoped or 'none'}; "
            "an instance with no key writes nothing)"
        ],
        None,
    )
