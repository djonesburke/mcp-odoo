# Field-level ACL (read-path policy)

Odoo's own access control is model- and record-level: a user who can read
`res.partner` can read *every* stored field on the records they see —
including `credit_limit`, internal `comment`, or message history. When an AI
agent reads on that user's behalf, those fields land in the model's context.

Field ACL is an **opt-in, server-side** layer that removes designated fields
from everything the MCP server returns, so sensitive columns never reach the
agent even though the underlying Odoo credential can read them. It is the
first open-source Odoo MCP server to offer this; until now only commercial
bridges did.

> Defense in depth, not a replacement for Odoo ACLs. This is enforced in the
> MCP server process. It protects the agent/LLM surface; it does not change
> what the Odoo credential itself can do.

## Enabling it

No policy file → **no behavior change**. To enable, add a `field_acl` key to
your existing policy file (`ODOO_MCP_POLICY_FILE`, default
`./odoo_mcp_policy.json`), or point `ODOO_MCP_FIELD_POLICY_FILE` at a
dedicated file. See [`odoo_mcp_policy.json.example`](../odoo_mcp_policy.json.example).

```json
{
  "field_acl": {
    "default": {
      "res.partner": { "deny": ["credit_limit", "comment"] },
      "hr.employee": { "allow": ["name", "work_email", "department_id"] },
      "*":           { "deny": ["message_ids"] }
    },
    "subsidiary": {
      "account.move.line": { "deny": ["balance"] }
    }
  }
}
```

### Schema

- **Per instance.** Top-level keys are instance names (use `default` for the
  default instance). An instance with no entry is unaffected — policies never
  leak across instances.
- **Per model.** Each model entry has **exactly one** of:
  - `deny` — a blacklist; listed fields are removed.
  - `allow` — an exclusive whitelist; only listed fields are kept.
- **`*` wildcard** — a per-instance model wildcard. Its rules merge with the
  specific model's: `deny` sets union, `allow` sets intersect.
- **`id` is never redactable** — record identity is always returned.

A malformed policy (both `deny` and `allow`, neither, wrong types, bad JSON)
**fails closed**: the server aborts at startup rather than silently running
unprotected.

## What it enforces

| Surface | Behavior |
| --- | --- |
| `search_records`, `read_record` | Denied fields removed from each record; response gains `redacted_fields: [...]`. |
| `aggregate_records` | Grouping or aggregating on a denied field is **rejected** with a clear error (prevents value inference). |
| **Domains**, on every read path | Filtering on a denied field is **rejected** before Odoo is read, on `search_records`, `aggregate_records`, `index_knowledge`, `search_across_instances`, `aggregate_across_instances` and the `odoo://search/...` resource. Redacting the output alone leaves the filter as an inference channel: narrow the rows to one denied value and every column still returned -- or the bare row count -- answers a question about it. Dotted paths are matched on their first segment (`employee_id.name` is `employee_id`) and `any` / `not any` sub-domains are walked. |
| `get_model_fields` | Denied fields are **marked** `"access": "restricted"` (not hidden) so the agent knows the field exists and can explain the redaction; `restricted_fields` listed. |
| `index_knowledge` | Denied fields are excluded before BM25 indexing, so their values are never cached or searchable. |
| `odoo://record/...`, `odoo://search/...` resources | Denied fields removed; `_redacted_fields` noted. |
| `health_check` | `runtime.field_acl` reports whether ACL is active and how many instances have rules — never the policy contents. |

`redacted_fields` notes are deliberate: the agent is told *that* fields were
withheld, so it does not hallucinate their absence or values.

## Limits (read this)

- **Curated tools are not field-redacted.** `search_employee` and
  `search_holidays` return a fixed, curated projection of
  identity/calendar fields. They never return arbitrary stored fields, so
  they are outside the *redaction* path by design — a fixed projection with
  required fields cannot be answered field by field.
  Put sensitive employee fields behind a `deny`/`allow` on `hr.employee` and
  read them through `read_record`/`search_records`, which are enforced.
  **`search_holidays` does, however, fail closed.** Its projection is the
  employee link, the dates, the description and the state of a named person's
  time off, which is squarely the kind of thing a policy on `hr.leave` is
  written to withhold — so before reading, it asks the policy whether any
  field it projects is restricted on `hr.leave.report.calendar`, and refuses
  with an explanatory error if so. Being outside redaction is a design
  choice; answering around the mask is not. With no policy file it behaves
  exactly as before.
- **A sub-domain is judged against the model being read**, not the related
  model: an `any` / `not any` leaf carries a domain over the comodel, and
  resolving which model that is would need an Odoo read on the refusal path.
  So a sub-domain field name is checked against the outer model's rules,
  which can refuse a read that a comodel-aware check would have allowed.
  That is the fail-closed direction and the reason it is not "fixed".
- **`read_attachment`** returns attachment metadata + content. Field ACL
  applies to the metadata dict; it does not parse attachment *payloads*. Do
  not rely on it to redact secrets embedded inside attachment bytes.
- **Writes are governed by the write policy, not this one.** Field ACL is a
  read-path control. The gated write workflow (`preview_write` →
  `validate_write` → `execute_approved_write`) is unchanged; a field you hide
  from reads can still be written if write execution is enabled and the
  Odoo credential allows it.
- **Server-side only.** A different client using the same Odoo credential
  directly (not through this MCP server) is unaffected.

## Threat model

**Protects against:** an AI agent (or a prompt-injected one) reading
sensitive fields it has no business surfacing — PII, credit limits, margins,
internal notes — and against those values leaking into a local knowledge
index or an aggregate it could otherwise infer.

**Does not protect against:** a compromised Odoo credential used outside the
server, Odoo-side data exfiltration, or secrets hidden inside attachment
binaries. Pair field ACL with proper Odoo record rules and least-privilege
API credentials.

## Verifying

With `res.partner.credit_limit` denied for `default`:

```bash
# credit_limit is absent and reported as redacted
uvx odoo-mcp --health   # runtime.field_acl.active == true
```

Then via your agent: `read_record` on a partner returns no `credit_limit`
and lists it under `redacted_fields`; `aggregate_records` grouping by
`credit_limit` errors; `get_model_fields` shows `credit_limit` with
`"access": "restricted"`. Removing the policy file restores byte-identical
v0.9.0 behavior.
