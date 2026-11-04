# Write ACL (`write_acl`)

`field_acl` decides what a connector may **read**. `write_acl` decides what a
write-enabled connector may **change**. Without it, `ODOO_MCP_ENABLE_WRITES=1`
reaches every model and field the Odoo user can write. With it, the connector
writes only the record classes the file names.

It is a key in the same policy file as `field_acl`
(`ODOO_MCP_FIELD_POLICY_FILE`, else `ODOO_MCP_POLICY_FILE`, else
`./odoo_mcp_policy.json`).

```json
{
  "write_acl": {
    "default": {
      "product.supplierinfo": {
        "operations": {
          "create": {"fields": ["product_tmpl_id", "partner_id", "price"], "max_records": 20},
          "write":  {"fields": ["price", "delay"], "max_records": 100}
        }
      },
      "product.template": {
        "operations": {"write": {"fields": ["categ_id", "barcode"], "max_records": 100}},
        "guards": [
          {"field": "categ_id", "comodel": "product.category",
           "must_match": ["property_cost_method", "property_valuation"]}
        ]
      }
    }
  }
}
```

## Rules

| Situation | Result |
|---|---|
| No `write_acl` key | No change. Writes behave as before. |
| `write_acl` present, instance has no entry | That instance writes nothing. No `*` wildcard, no fallback. |
| Model not listed | Refused. |
| Operation not listed for the model (`unlink` included) | Refused. |
| A value key not in that operation's `fields` | Refused. Applies to every entry of a `values_list`. |
| More records than `max_records` | Refused; split the batch. Counts `record_ids` for write/unlink and entries for create. |
| A `context` key other than `lang` or `tz` | Refused. `default_*` keys would set unlisted fields on create; `tracking_disable` would hide the change from the chatter. |
| Guard `field` in a write's values | Each touched record's current `comodel` and the new one are read; the write runs only if they are equal on every `must_match` field. Any read error, missing record or missing field refuses. A guarded field cannot be set on create. |
| `chatter_post` | Refused on a governed instance. |
| `execute_method` | Only methods the classifier calls read-only. The side-effect allowlist and `ODOO_MCP_ALLOW_UNKNOWN_METHODS` do not apply. |
| Malformed `write_acl` | Startup aborts. If the file breaks while running, every write is refused. |
| `ODOO_MCP_REQUIRE_WRITE_ACL=1` and no file or no key | Startup aborts; at runtime every write is refused. A scoped connector sets it. |
| File edited while the server runs | A write must pass both the scope loaded at startup and the file as it reads now. Narrowing works at once; widening or deleting the key changes nothing until a restart, and with the require flag a restart without the key does not start. |

## Where it is checked

`preview_write` (no token for an out-of-scope payload), `validate_write` (no
approval stored; the guard runs here with the live client), and
`execute_approved_write` (static check and guard again, against the file as it
reads at that moment, intersected with the scope loaded at startup). The
file is re-read on every check, so narrowing it takes effect without a
restart, and a token validated under a wider file cannot execute after it
narrows; widening it does nothing until a restart.

`health_check` reports `write_acl.active` and, per instance, the writable
models and operations. Startup prints one `write ACL:` line.

## What it does not do

- It does not replace Odoo's own access rights. The connector still runs as
  its Odoo user, and Odoo refuses what that user cannot do.
- It does not prompt anyone. The per-call human prompt is the client's
  permission rule on `execute_approved_write`.
- It does not check values beyond the guard. A price of 0 is a valid price.
- It does not protect the policy file. Anyone, or any agent, who can edit the
  file and restart the server can change the scope at that restart. The
  deployment's posture check compares the installed file with the reviewed one.
