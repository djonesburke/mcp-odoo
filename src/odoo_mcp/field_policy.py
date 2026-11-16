"""Read-path field-level access control policy (single enforcement choke point).

Opt-in, per-instance, per-model field allow/deny rules applied to every path
that returns record data: read tools, aggregate validation, the knowledge
indexer, ``odoo://`` resources, and ``get_model_fields`` metadata. Denied
fields are refused as *filters* as well as withheld as output
(:meth:`FieldPolicy.check_domain`), because a domain over a denied field
answers a question about it without ever returning the column.

Design mirrors :mod:`write_policy`: env var -> JSON file -> validated,
cached structure. No policy file means no behavior change (zero-friction
upgrade). A malformed policy fails closed (raises at load, aborting startup)
rather than silently running unprotected.

Policy shape (a ``field_acl`` key in the shared policy file, or a dedicated
file via ``ODOO_MCP_FIELD_POLICY_FILE``)::

    {
      "field_acl": {
        "default":    { "res.partner": { "deny": ["credit_limit", "comment"] },
                        "*":           { "deny": ["message_ids"] } },
        "subsidiary": { "hr.employee": { "allow": ["name", "work_email"] } }
      }
    }

Each model entry has exactly one of ``deny`` (blacklist) or ``allow``
(exclusive whitelist). ``*`` is a per-instance model wildcard whose rules
merge with the specific model's. ``id`` is never redactable.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

from .write_policy import policy_file_path

FIELD_POLICY_FILE_ENV = "ODOO_MCP_FIELD_POLICY_FILE"
FIELD_ACL_KEY = "field_acl"
ALWAYS_KEPT = frozenset({"id"})

# Domain leaves whose value is itself a domain over the related model.
SUBDOMAIN_OPERATORS = frozenset({"any", "not any", "any!", "not any!"})
# A domain is caller data; cap the walk rather than trust its nesting.
MAX_DOMAIN_DEPTH = 8


# An aggregate or group-by name the policy can read: a plain field path. Odoo's
# legacy ``read_group`` matches its ``fields`` entries with an unanchored
# regex, so ``wage!`` reaches Odoo as ``wage``; anything else is refused.
_FIELD_PATH_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")

# Odoo stores a Binary field (``attachment=True``, the default) as an
# ``ir.attachment`` row tagged ``res_model`` / ``res_field``. These columns of
# that row are the field's content, or a way to fetch it.
ATTACHMENT_MODEL = "ir.attachment"
ATTACHMENT_CONTENT_FIELDS = frozenset(
    {"datas", "raw", "db_datas", "index_content", "access_token", "checksum"}
)

# ``(model, field) -> comodel`` for a relational field, ``None`` for any other
# field. Raises when the model's field metadata cannot be read.
ComodelResolver = Callable[[str, str], Optional[str]]


class DomainTooDeepError(ValueError):
    """Raised when a domain nests past :data:`MAX_DOMAIN_DEPTH` (fail closed)."""


class UnresolvedRelationError(ValueError):
    """Raised when a relation hop cannot be attributed to a model (fail closed)."""


def comodel_resolver(client: Any) -> ComodelResolver:
    """Build a :data:`ComodelResolver` over ``client.get_model_fields``.

    Field metadata is read once per model for the life of the resolver, and
    only when a caller's path actually hops through a relation.
    """
    cache: Dict[str, Dict[str, Any]] = {}

    def resolve(model: str, field: str) -> Optional[str]:
        metadata = cache.get(model)
        if metadata is None:
            metadata = client.get_model_fields(model)
            if not isinstance(metadata, dict) or isinstance(
                metadata.get("error"), str
            ):
                raise UnresolvedRelationError(model)
            cache[model] = metadata
        info = metadata.get(field)
        relation = info.get("relation") if isinstance(info, dict) else None
        return relation if isinstance(relation, str) and relation else None

    return resolve


def _path_model_fields(
    model: str, segments: List[str], comodel_of: ComodelResolver
) -> Tuple[List[Tuple[str, str]], str]:
    """Attribute each segment of a dotted path to the model that owns it.

    Returns the ``(model, field)`` pairs and the model owning the last
    segment. A segment that is not relational (a date part, a property key)
    keeps the path on the same model.
    """
    pairs: List[Tuple[str, str]] = []
    current = model
    for index, segment in enumerate(segments):
        pairs.append((current, segment))
        if index < len(segments) - 1:
            current = comodel_of(current, segment) or current
    return pairs, current


def _domain_model_fields(
    model: str, domain: Any, comodel_of: ComodelResolver, _depth: int = 0
) -> List[Tuple[str, str]]:
    """``(model, field)`` for every segment a domain filters on.

    The comodel-aware twin of :func:`_domain_field_segments`: each hop of a
    dotted path, and each ``any`` / ``not any`` sub-domain, is attributed to
    the related model it really belongs to. Raises
    :class:`UnresolvedRelationError` when a sub-domain's model cannot be
    resolved, and :class:`DomainTooDeepError` past the depth cap.
    """
    if _depth > MAX_DOMAIN_DEPTH:
        raise DomainTooDeepError(
            f"domain nesting exceeds {MAX_DOMAIN_DEPTH} levels"
        )
    pairs: List[Tuple[str, str]] = []
    if not isinstance(domain, (list, tuple)):
        return pairs
    for leaf in domain:
        if isinstance(leaf, str) or not isinstance(leaf, (list, tuple)):
            continue
        if len(leaf) == 3 and isinstance(leaf[0], str):
            name, operator, value = leaf
            segments = [s.strip() for s in name.split(".") if s.strip()]
            leaf_pairs, last_model = _path_model_fields(model, segments, comodel_of)
            pairs.extend(leaf_pairs)
            if (
                isinstance(operator, str)
                and operator.strip().lower() in SUBDOMAIN_OPERATORS
            ):
                target = comodel_of(last_model, segments[-1]) if segments else None
                if not target:
                    raise UnresolvedRelationError(name)
                pairs.extend(
                    _domain_model_fields(target, value, comodel_of, _depth + 1)
                )
            continue
        pairs.extend(_domain_model_fields(model, leaf, comodel_of, _depth + 1))
    return pairs


def _domain_has_relation_hop(domain: Any, _depth: int = 0) -> bool:
    """True when a domain reaches past the model being read.

    A dotted name or a sub-domain operator. Anything nested past the depth
    cap counts as a hop, so the caller walks it and refuses it there.
    """
    if _depth > MAX_DOMAIN_DEPTH:
        return True
    if not isinstance(domain, (list, tuple)):
        return False
    for leaf in domain:
        if isinstance(leaf, str) or not isinstance(leaf, (list, tuple)):
            continue
        if len(leaf) == 3 and isinstance(leaf[0], str):
            operator = leaf[1]
            if "." in leaf[0] or (
                isinstance(operator, str)
                and operator.strip().lower() in SUBDOMAIN_OPERATORS
            ):
                return True
            continue
        if _domain_has_relation_hop(leaf, _depth + 1):
            return True
    return False


def _domain_field_segments(domain: Any, _depth: int = 0) -> List[str]:
    """Every path segment of every field a domain filters on.

    Walks the domain recursively so a field hidden inside an ``any`` /
    ``not any`` sub-domain is seen too, and keeps **every** segment of a
    dotted path (``workorder_id.time_ids.employee_cost`` -> ``workorder_id``,
    ``time_ids``, ``employee_cost``). Odoo 17+ rewrites ``a.b.c op v`` into
    ``a any (b any (c op v))``, so the dotted and the ``any``-chain spellings
    are the same query; attributing every segment to the outer model is what
    makes the two forms check alike. Logic operators (``&``, ``|``, ``!``)
    carry no field name.

    Segments past the first, like sub-domain leaves, are attributed to the
    *same* model rather than to the related model: resolving the comodel
    would need an Odoo read, and over-refusing is the fail-closed direction.
    The accepted cost is that an open field on a related model is refused
    when the outer model denies a field of that name.

    Raises :class:`DomainTooDeepError` past :data:`MAX_DOMAIN_DEPTH` instead
    of returning the segments found so far: a padded chain would otherwise
    hide a denied leaf below the cap and pass unchecked.
    """
    if _depth > MAX_DOMAIN_DEPTH:
        raise DomainTooDeepError(
            f"domain nesting exceeds {MAX_DOMAIN_DEPTH} levels"
        )
    segments: List[str] = []
    if not isinstance(domain, (list, tuple)):
        return segments
    for leaf in domain:
        if isinstance(leaf, str) or not isinstance(leaf, (list, tuple)):
            continue
        if len(leaf) == 3 and isinstance(leaf[0], str):
            name, operator, value = leaf
            segments.extend(s.strip() for s in name.split(".") if s.strip())
            if (
                isinstance(operator, str)
                and operator.strip().lower() in SUBDOMAIN_OPERATORS
            ):
                segments.extend(_domain_field_segments(value, _depth + 1))
            continue
        # Any other nesting is treated as a domain in its own right.
        segments.extend(_domain_field_segments(leaf, _depth + 1))
    return segments


def _order_field_segments(order: Any) -> List[str]:
    """Every path segment of every field an ``order`` string sorts on.

    ``order`` is comma-separated terms, each a field path with an optional
    direction (``asc`` / ``desc``) and ``nulls first|last``. ``read_group``
    orders may also carry a ``:granularity`` or ``:aggregate`` suffix
    (``date_deadline:month``, ``amount:sum``); only the field name before the
    colon counts. Dotted paths keep every segment, as in
    :func:`_domain_field_segments`; surrounding double quotes are dropped
    from each name. The virtual ``__count`` key names no field.

    Raises :class:`ValueError` for anything that is not a string, so the
    caller refuses it instead of passing a shape it cannot read.
    """
    if not isinstance(order, str):
        raise ValueError("order must be a string")
    segments: List[str] = []
    for term in order.split(","):
        parts = term.split()
        if not parts:
            continue
        name = parts[0].split(":", 1)[0]
        if name == "__count":
            continue
        # Odoo accepts a double-quoted field name in an order term.
        segments.extend(
            s.strip().strip('"').strip() for s in name.split(".") if s.strip()
        )
    return [s for s in segments if s]


class FieldPolicyError(ValueError):
    """Raised when a field policy file is present but malformed (fail closed)."""


@dataclass(frozen=True)
class ModelFieldRule:
    mode: str  # "deny" or "allow"
    fields: FrozenSet[str]


class FieldPolicy:
    """Validated, per-(instance, model) field rules with merge + redaction."""

    def __init__(self, by_instance: Dict[str, Dict[str, ModelFieldRule]]) -> None:
        self._by_instance = by_instance

    def active(self) -> bool:
        return bool(self._by_instance)

    def instances(self) -> List[str]:
        return sorted(self._by_instance)

    def _effective(
        self, instance: str, model: str
    ) -> Optional[Tuple[Optional[FrozenSet[str]], FrozenSet[str]]]:
        """Merge the instance's ``*`` and specific-model rules.

        Returns ``(allow, deny)`` where ``allow`` is ``None`` (no whitelist)
        or the intersection of whitelists, and ``deny`` is the union of
        blacklists. ``None`` means no policy applies (pass-through).
        """
        models = self._by_instance.get(instance)
        if not models:
            return None
        star = models.get("*")
        specific = models.get(model)
        if star is None and specific is None:
            return None
        allow: Optional[set[str]] = None
        deny: set[str] = set()
        for rule in (star, specific):
            if rule is None:
                continue
            if rule.mode == "deny":
                deny |= rule.fields
            else:
                allow = set(rule.fields) if allow is None else (allow & rule.fields)
        return (frozenset(allow) if allow is not None else None, frozenset(deny))

    def filter_fields(
        self, instance: str, model: str, field_names: Iterable[str]
    ) -> Tuple[List[str], List[str]]:
        """Split field names into (kept, redacted) for one (instance, model)."""
        effective = self._effective(instance, model)
        names = list(field_names)
        if effective is None:
            return names, []
        allow, deny = effective
        kept: List[str] = []
        redacted: List[str] = []
        for name in names:
            if name in ALWAYS_KEPT:
                kept.append(name)
            elif allow is not None and name not in allow:
                redacted.append(name)
            elif name in deny:
                redacted.append(name)
            else:
                kept.append(name)
        return kept, redacted

    def redact_record(
        self, instance: str, model: str, record: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Return a copy of ``record`` with denied keys removed + their names.

        An ``ir.attachment`` row also loses its content columns when it backs
        a field that is restricted on the model owning it
        (:meth:`_attachment_masked_keys`).
        """
        masked = (
            self._attachment_masked_keys(instance, record)
            if model == ATTACHMENT_MODEL
            else []
        )
        effective = self._effective(instance, model)
        if effective is None and not masked:
            return record, []
        kept, redacted = self.filter_fields(instance, model, record.keys())
        kept_set = set(kept) - set(masked)
        redacted = redacted + [name for name in masked if name not in redacted]
        filtered = {k: v for k, v in record.items() if k in kept_set}
        return filtered, redacted

    def attachment_field_restricted(
        self, instance: str, res_model: Any, res_field: Any
    ) -> bool:
        """True when an attachment backs a field restricted on its owner.

        ``res_field`` empty means an ordinary attachment, which backs no
        field. A field-backed row whose owning model is missing cannot be
        judged and counts as restricted.
        """
        if not self._by_instance.get(instance) or not res_field:
            return False
        if not isinstance(res_model, str) or not res_model:
            return True
        return bool(self.restricted_fields(instance, res_model, [str(res_field)]))

    def _attachment_masked_keys(
        self, instance: str, record: Dict[str, Any]
    ) -> List[str]:
        """Content columns of an ``ir.attachment`` row that must be withheld.

        Inert on an instance with no rules. Otherwise a row that carries
        content but not its ``res_field`` column cannot be told apart from
        one backing a masked field, so its content is withheld too.
        """
        if not self._by_instance.get(instance):
            return []
        present = [key for key in record if key in ATTACHMENT_CONTENT_FIELDS]
        if not present:
            return []
        if "res_field" not in record or self.attachment_field_restricted(
            instance, record.get("res_model"), record["res_field"]
        ):
            return present
        return []

    def redact_records(
        self, instance: str, model: str, records: Iterable[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Redact a list of records; returns (records, sorted redacted names)."""
        out: List[Dict[str, Any]] = []
        redacted: set[str] = set()
        for record in records:
            filtered, names = self.redact_record(instance, model, record)
            out.append(filtered)
            redacted.update(names)
        return out, sorted(redacted)

    def restricted_fields(
        self, instance: str, model: str, field_names: Iterable[str]
    ) -> List[str]:
        """Field names that would be redacted (for get_model_fields marking)."""
        _, redacted = self.filter_fields(instance, model, field_names)
        return redacted

    def governs(self, instance: str, model: str) -> bool:
        """True when some rule applies to ``model`` on ``instance``."""
        return self._effective(instance, model) is not None

    def check_aggregate(
        self,
        instance: str,
        model: str,
        fields: Iterable[str],
        comodel_of: Optional[ComodelResolver] = None,
    ) -> Optional[str]:
        """Return an error string if any aggregate/groupby field is denied.

        Each name is cut at ``:`` (granularity or aggregate suffix) and then
        into its dotted segments, every one checked against ``model`` as in
        :meth:`check_domain`: ``contract_id.wage`` reaches the denied field
        through the relation. With ``comodel_of`` each segment past a relation
        is also checked against the related model's own rules.

        On an instance with rules, a name that is not a plain field path is
        refused: Odoo's legacy ``read_group`` reads ``wage!`` as ``wage``, so
        a decorated name would otherwise pass this check and still be summed.
        """
        names: List[str] = []
        heads: List[str] = []
        for field in fields:
            head = str(field).split(":", 1)[0].strip()
            heads.append(head)
            names.extend(s.strip() for s in head.split(".") if s.strip())
        if self._by_instance.get(instance):
            malformed = sorted({h for h in heads if not _FIELD_PATH_RE.match(h)})
            if malformed:
                return (
                    f"Field policy cannot check {malformed} on {model}: an "
                    "aggregate or group-by name must be a plain field path, "
                    "so a denied field could be hidden in it."
                )
        _, redacted = self.filter_fields(instance, model, names)
        if redacted:
            return (
                "Field policy denies access to "
                f"{sorted(set(redacted))} on {model}; aggregation on restricted "
                "fields is blocked to prevent inference."
            )
        if comodel_of is None or not self._by_instance.get(instance):
            return None
        dotted = [h.split(".") for h in heads if "." in h]
        if not dotted:
            return None
        try:
            pairs = [
                pair
                for segments in dotted
                for pair in _path_model_fields(model, segments, comodel_of)[0]
            ]
        except Exception:
            return self._unresolved_relation_error(model)
        return self._related_block(instance, model, pairs, "aggregation on")

    def redact_aggregate_rows(
        self, instance: str, model: str, rows: Iterable[Any]
    ) -> List[Any]:
        """Drop denied columns from ``read_group`` rows.

        The request is refused up front when it names a denied field; this
        covers a column Odoo adds unasked (legacy ``read_group`` with no
        measures sums every numeric field). Keys starting ``__`` are Odoo's
        own; ``<field>:<suffix>`` and ``<field>_count`` follow their field.
        """
        if self._effective(instance, model) is None:
            return list(rows)

        def restricted(key: str) -> bool:
            head = key.split(":", 1)[0].split(".", 1)[0]
            if not self.restricted_fields(instance, model, [head]):
                return False
            if not head.endswith("_count"):
                return True
            base = head[: -len("_count")]
            return bool(self.restricted_fields(instance, model, [base]))

        out: List[Any] = []
        for row in rows:
            if isinstance(row, dict):
                row = {
                    key: value
                    for key, value in row.items()
                    if not isinstance(key, str)
                    or key.startswith("__")
                    or not restricted(key)
                }
            out.append(row)
        return out

    def _unresolved_relation_error(self, model: str) -> str:
        return (
            f"Field policy cannot check this request on {model}: it reaches "
            "through a relation whose related model could not be resolved, "
            "so a denied field could be hidden behind it. The request is "
            "refused rather than passed unchecked."
        )

    def _related_block(
        self,
        instance: str,
        model: str,
        pairs: Iterable[Tuple[str, str]],
        verb: str,
    ) -> Optional[str]:
        """Error string when a ``(model, field)`` pair names a denied field."""
        denied = sorted(
            {
                f"{owner}.{name}"
                for owner, name in pairs
                if self.restricted_fields(instance, owner, [name])
            }
        )
        if not denied:
            return None
        return (
            f"Field policy denies access to {denied}, reached through a "
            f"relation from {model}; {verb} restricted fields is blocked to "
            "prevent inference."
        )

    def check_domain(
        self,
        instance: str,
        model: str,
        domain: Any,
        comodel_of: Optional[ComodelResolver] = None,
    ) -> Optional[str]:
        """Return an error string if a domain filters on a denied field.

        Two passes. The first (:meth:`_check_domain_outer`) judges every
        segment against ``model`` and reads nothing from Odoo. The second runs
        only when ``comodel_of`` is given, the instance has rules and the
        domain hops through a relation: each segment is then also judged
        against the related model it belongs to, so ``employee_id.wage`` from
        a model with no rule on ``wage`` is refused when the employee model
        denies it. A hop that cannot be resolved is refused.
        """
        block = self._check_domain_outer(instance, model, domain)
        if block is not None:
            return block
        if (
            comodel_of is None
            or not self._by_instance.get(instance)
            or not _domain_has_relation_hop(domain)
        ):
            return None
        try:
            pairs = _domain_model_fields(model, domain, comodel_of)
        except DomainTooDeepError:
            return (
                f"Field policy cannot check this domain on {model}: its "
                f"nesting exceeds {MAX_DOMAIN_DEPTH} levels, so a denied "
                "field could be hidden below the limit. The domain is "
                "refused rather than passed unchecked; flatten it and retry."
            )
        except Exception:
            return self._unresolved_relation_error(model)
        return self._related_block(instance, model, pairs, "filtering on")

    def _check_domain_outer(
        self, instance: str, model: str, domain: Any
    ) -> Optional[str]:
        """Check every domain segment against ``model``'s own rules.

        Redacting the *output* of a read leaves the filter itself as an
        inference channel: a domain on a denied field turns any column that
        is still allowed -- or the row count on its own -- into an answer
        about the denied one. One aggregate grouped by month and filtered to
        a single employee is the per-person series; one count bisected over
        dates is a named person's absence. Closing that is why this exists
        (2026-09-08 adversarial review, finding B3).

        Fails closed, reads nothing from Odoo, and names only the model and
        the field names -- never a value carried in the domain, which may be
        the very record content the rule withholds. An empty ``allow`` list
        therefore refuses every domain except one over ``id``. A domain that
        nests past :data:`MAX_DOMAIN_DEPTH` is refused outright rather than
        checked to the cap and passed, because the segments below the cap are
        exactly where a padded chain would hide a denied leaf.

        Models no rule applies to are pass-through, depth included: with no
        policy file this method is inert, which is the upgrade guarantee.
        """
        if self._effective(instance, model) is None:
            return None
        try:
            segments = _domain_field_segments(domain)
        except DomainTooDeepError:
            return (
                f"Field policy cannot check this domain on {model}: its "
                f"nesting exceeds {MAX_DOMAIN_DEPTH} levels, so a denied "
                "field could be hidden below the limit. The domain is "
                "refused rather than passed unchecked; flatten it and retry."
            )
        if not segments:
            return None
        _, redacted = self.filter_fields(instance, model, segments)
        if redacted:
            return (
                "Field policy denies access to "
                f"{sorted(set(redacted))} on {model}; filtering on restricted "
                "fields is blocked to prevent inference."
            )
        return None

    def check_order(self, instance: str, model: str, order: Any) -> Optional[str]:
        """Return an error string if an ``order`` sorts on a denied field.

        Sorting is a ranking of the withheld column: order by a masked wage
        and the row sequence is the wage order, however the column itself is
        redacted. Same rules as :meth:`check_domain`: every segment of a
        dotted path is checked against the outer model, nothing is read from
        Odoo, the error names the model and field names only, and models no
        rule applies to pass through. An ``order`` that is not a string is
        refused on a model with rules, since it cannot be read.
        """
        if order is None or self._effective(instance, model) is None:
            return None
        try:
            segments = _order_field_segments(order)
        except ValueError:
            return (
                f"Field policy cannot check the order on {model}: it is not "
                "a string, so a denied field could be hidden in it."
            )
        if not segments:
            return None
        _, redacted = self.filter_fields(instance, model, segments)
        if redacted:
            return (
                "Field policy denies access to "
                f"{sorted(set(redacted))} on {model}; ordering by restricted "
                "fields is blocked to prevent inference."
            )
        return None


def _parse_field_policy(data: Dict[str, Any]) -> FieldPolicy:
    acl = data.get(FIELD_ACL_KEY, {})
    if not isinstance(acl, dict):
        raise FieldPolicyError(f"'{FIELD_ACL_KEY}' must be an object")
    by_instance: Dict[str, Dict[str, ModelFieldRule]] = {}
    for instance, models in acl.items():
        if not isinstance(models, dict):
            raise FieldPolicyError(f"field_acl['{instance}'] must be an object")
        rules: Dict[str, ModelFieldRule] = {}
        for model, spec in models.items():
            if not isinstance(spec, dict):
                raise FieldPolicyError(
                    f"field_acl['{instance}']['{model}'] must be an object"
                )
            has_deny = "deny" in spec
            has_allow = "allow" in spec
            if has_deny == has_allow:
                raise FieldPolicyError(
                    f"field_acl['{instance}']['{model}'] needs exactly one of "
                    "'deny' or 'allow'"
                )
            mode = "deny" if has_deny else "allow"
            raw = spec[mode]
            if not isinstance(raw, list) or not all(
                isinstance(item, str) for item in raw
            ):
                raise FieldPolicyError(
                    f"field_acl['{instance}']['{model}']['{mode}'] must be a "
                    "list of field-name strings"
                )
            rules[model] = ModelFieldRule(
                mode=mode,
                fields=frozenset(item.strip() for item in raw if item.strip()),
            )
        by_instance[instance] = rules
    return FieldPolicy(by_instance)


def field_policy_file_path() -> Optional[str]:
    """Dedicated field-policy file, else the shared write-policy file."""
    explicit = os.environ.get(FIELD_POLICY_FILE_ENV, "").strip()
    if explicit:
        return explicit
    return policy_file_path()


def load_field_policy() -> FieldPolicy:
    """Load and validate the field policy; raise FieldPolicyError if malformed."""
    path = field_policy_file_path()
    if path is None:
        return FieldPolicy({})
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FieldPolicyError(f"Cannot read field policy file {path}: {exc}")
    if not isinstance(data, dict):
        raise FieldPolicyError(f"Field policy file {path} must contain an object")
    return _parse_field_policy(data)


_policy: Optional[FieldPolicy] = None
_policy_lock = threading.Lock()


def get_field_policy() -> FieldPolicy:
    """Process-wide field policy, loaded lazily and cached."""
    global _policy
    with _policy_lock:
        if _policy is None:
            _policy = load_field_policy()
        return _policy


def reset_field_policy() -> None:
    """Drop the cached policy (intended for tests and lifespan reload)."""
    global _policy
    with _policy_lock:
        _policy = None


def field_policy_posture() -> Dict[str, Any]:
    """Non-secret health posture: whether field ACL is active and scope counts."""
    try:
        policy = get_field_policy()
    except FieldPolicyError as exc:
        return {"active": False, "error": str(exc)}
    return {
        "active": policy.active(),
        "instances_with_rules": len(policy.instances()),
    }
