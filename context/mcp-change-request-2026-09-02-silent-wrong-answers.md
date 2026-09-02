# Change request outcome — silent wrong answers, and a per-instance side-effect allowlist

- **Date**: 2026-09-02
- **Provenance**: a change request drafted 2026-08-08 in a consumer project while
  configuring a third-party dashboards module. That module has since been
  abandoned, so the dashboards references in the original are the *provenance of
  the bug reports*, not a live use case.
- **Status**: **done** — implemented, tested, and gated. This file records what
  was verified and what turned out not to need fixing, so the same reports are
  not re-investigated from scratch.
- **Why it is filed here**: implementation lands in this repo. Consumer
  projects analyse and hand off; they do not write MCP server code.

---

## 1. Three of the four reported bugs did not need fixing

The original request listed four "successful-looking response containing a wrong
answer" bugs. Each was re-tested live, read-only, against a real Odoo 19
instance before any code was written.

| Report | Verdict |
| --- | --- |
| **3a** — an invalid field name in `fields` yields `success: true, count: 0` | **Already fixed.** Now `success: false` with Odoo's own `Invalid field '<name>' on '<model>'`. |
| **3b** — `ilike` against a translated field silently matches nothing | **Does not reproduce.** `[["name","ilike","<term>"]]` on `res.groups` returns every matching row. The translated/jsonb domain is built correctly. |
| **3c** — `read_record` and `search_records` disagree about record existence | **Does not reproduce.** The record reported missing reads back fine, and the `in`-operator domain returns it. |
| **3d** — `measures: ["__count"]` errors with HTTP 500 | **Reproduced exactly.** Fixed. |

**All three non-reproducing reports share one root cause that was already
fixed**: Odoo failures were being rendered as empty results. `search_read` and
`read` each caught every exception and returned `[]`, so an invalid field, an
expired API key and a genuinely empty result were indistinguishable — and a
`read` that failed surfaced as `Record not found: <model> ID <n>` for a record
that exists. That is enough to produce all of 3a, 3b and 3c, including the two
zero-row observations. The client now re-raises and every caller wraps it in a
structured error envelope.

**Lesson worth keeping:** a report of the form "this query returned zero rows
and should not have" is, in this server, far more likely to be a swallowed
transport error than a domain-construction bug. Check the error path before
theorising about operators.

## 2. What was fixed

### `__count` (report 3d)

`measures: ["__count"]` was normalized to `"__count:sum"`. `__count` is Odoo's
native row-count aggregate and names no field, so Odoo answered with `Invalid
field '__count' on model '<model>' for '__count:sum'` — a 500 naming a field
that was never the problem, sending the caller to look for it. Now:

- `__count` reaches `formatted_read_group` verbatim (Odoo accepts it there);
- it is dropped from legacy `read_group`'s `fields`, which returns the row
  count regardless and rejects it as a field;
- it contributes no field name to the field-ACL check;
- `__count:<agg>` is refused client-side with a message naming the working
  forms.

### An unbounded `json` column in curated default reads — **not in the original request**

Found while re-testing 3b/3c. Smart-field selection skipped `binary` but not
`json`, so a default `fields=None` read could return tens of kilobytes of blob
for one record: `res.groups.view_group_hierarchy` renders the entire group
graph, and a single record measured **~84 KB**. For an agent caller that is not
a formatting nuisance, it is context destroyed without warning. `json` now
joins `binary` as a type the curated selection declines to guess at. An
explicit `fields=[...]` still serves it.

Related, and **left alone deliberately**: `_is_skip_metadata` also tests
`meta.get("automatic")` and `meta.get("compute")`, but `FIELDS_GET_ATTRIBUTES`
does not request either attribute, so both branches are unreachable in
practice. Fixing that means changing which attributes are requested from
`fields_get`, which changes selection on every model — too broad to bundle into
a bug fix. Filed here rather than silently changed.

### Per-instance side-effect allowlist (Part 1 of the request)

The original justification for this was a dashboards method, and that module is
gone. It was re-justified on general merit and **implemented anyway**, because
the trap is not specific to that module: on 2026-08-11 a legitimate staging test
of `stock.picking.action_assign` was blocked by exactly this shape, and the
worker correctly refused to widen the file. Where staging-first is the standing
rule, "arm production in order to test staging" is a recurring cost, not a
hypothetical one.

`allowed_side_effect_methods` now accepts either form:

```json
{
  "allowed_side_effect_methods": {
    "default": [],
    "staging": ["stock.picking.action_assign"]
  }
}
```

- The **flat list** still works and still applies to every instance, so no
  deployed config breaks.
- Keys in the **object** form are literal instance names, matching `field_acl`
  exactly. There is no inherited fallback: an instance with no key allows
  nothing, which is the fail-closed direction.
- A malformed instance entry contributes no methods and surfaces its error in
  the runtime posture.
- `ODOO_MCP_ALLOWED_SIDE_EFFECT_METHODS` is unchanged and still applies to
  every instance — it cannot express a staging-only method, and that is now
  documented rather than implied.

The gate moved to *after* instance resolution, because it cannot answer
"is this allowed?" without knowing where. Its refusal message now names the
instance it consulted.

### Loud policy resolution at startup (Part 4 of the request)

The request's first half is **moot**: the `.env.example` carrying the wrong
`ODOO_MCP_POLICY_FILE` path was deleted from the deployment repo before this
work started, so there is nothing left to correct there.

The second half was real and is done. Both policy files resolve through a chain
that can end in "nothing configured", and the two ends fail in opposite
directions. No side-effect policy allows no methods — safe. No **field** policy
applies **no masking at all**, every field of every model served, and that state
was reachable in complete silence: an unset variable with no policy file in the
working directory produced no signal anywhere, so a redeploy that moved the file
lost masking with nothing to notice. The server now prints on every start:

- which field-ACL file answered and how many instances carry rules — or a
  prominent warning that no masking is active;
- which side-effect file answered, and whether its list is shared across
  instances or keyed per instance, with per-instance counts.

A configured-but-unreadable policy file still aborts startup (unchanged, fail
closed) — now after saying why, instead of as a bare traceback from the
lifespan.

## 3. Out of scope, as instructed

No general SQL execution was added, and no view-listing tool was built. If a
narrow need for one appears it should be proposed and signed off separately.

## 4. Gates

`pytest` (1124 passed), `ruff check`, `mypy src`, and `lint-imports` all pass.
