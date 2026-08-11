# API key lifecycle — `check_api_key_expiry`

Odoo never warns before an API key expires. When a key ages out, the transport
returns a bare authentication failure, and every downstream read renders that
as an empty result — indistinguishable from a search that genuinely matched
nothing. `check_api_key_expiry` turns that silence into a dated, named finding.

```
check_api_key_expiry(warn_days=14, instance=None)
```

Read-only, no side effects, no new capability. Works identically on any
configured instance.

## What it never does

The tool reads a **fixed six-field projection** of `res.users.apikeys`:
`id`, `name`, `user_id`, `scope`, `create_date`, `expiration_date`. There is no
argument that widens it.

Two independent properties keep key material out of the result:

1. `res.users.apikeys` exposes no `key` or `index` field through the ORM. There
   is nothing of that kind to read on this path. (`index` would be partial key
   material — it holds the key's leading characters.)
2. `assert_projection_safe()` raises before any Odoo call if the projection
   ever grows one of those names, and a parametrised test asserts it.

Nothing in `credential_lifecycle.py` reads a credential from the environment,
the client, or the configuration — so no failure path can interpolate one into
an error message. Errors return the standard envelope with `debug` redacted by
`sanitize_odoo_error`.

The recommended `field_acl` stanza (in `odoo_mcp_policy.json.example`) adds a
whitelist on `res.users.apikeys` for the *other* read paths — `search_records`,
the knowledge indexer, `odoo://` resources. On Odoo 19 that closes no present
hole; it guarantees a future Odoo that adds a key-bearing field cannot surface
it.

## Three results that are findings, not passes

This server has a long list of conditions that all render as "no data". This
tool is built so it cannot become another one.

| Result | `status` | Why it is not an all-clear |
| --- | --- | --- |
| No expiration date | `no_expiry` | The key never trips the warning window and never dies. Reported separately, never counted as `ok`. |
| Unparseable expiration date | `unparseable_expiry` | The expiry is unknown, not distant. |
| Zero visible keys | `no_keys_visible` | Means either this user holds no key, or a record rule limits visibility to the caller's own records. The summary says so in those words. |

Per-key states are `expired`, `expiring`, `unparseable_expiry`, `no_expiry`,
`ok`. The report's `status` is the most severe state present, and `keys` is
sorted most-urgent first.

## Visibility is reported, not assumed

Odoo restricts non-system users to their own `res.users.apikeys` records. A
clean report from one user's credential therefore says nothing about anyone
else's keys.

`visibility` is **derived** from whether every visible key belongs to the
caller's uid:

- `own_user_only` — other users' keys are not covered, and
  `visibility_detail` states that explicitly.
- `all_users` — this credential sees beyond its own records.
- `unknown` — the caller's uid could not be determined.

Without this field, "0 keys expiring" from a restricted user's machine reads
exactly like "nothing expiring anywhere".

## Which instance answered

The response carries `instance`, `database`, and `instance_kind`, derived from
the `database.is_neutralized` parameter:

| Probe result | `instance_kind` |
| --- | --- |
| Parameter absent | `production` |
| Parameter set and truthy | `staging` |
| Parameter unreadable | `unknown` |

An unreadable probe is never reported as production or staging — an unanswered
question is not a pass. The probe failure is attached as `metadata_errors` and
does not fail the report.

This matters where a staging database is a clone of a production snapshot: the
same credential authenticates against both, and only the database name
distinguishes them. Without `database` in the response, "the key expires in 9
days" would not say *whose* key estate was examined.

## Configuration

| Variable | Default | Effect |
| --- | --- | --- |
| `ODOO_MCP_ROTATION_DOC` | unset | Free-text pointer to the deployment's rotation procedure, echoed as `rotation_doc` so an alert names its own remedy. Omitted from the response when unset. Not a credential. |

## Running it on a schedule

**A tool nobody calls prevents nothing.** Both key incidents this tool exists
to prevent were silence, not slow response — so the monitor only pays for
itself once something calls it on a cadence and surfaces a non-`ok` status to a
human.

That scheduler lives outside this repo, by design: the server is invoked by an
MCP client and has no timer of its own. Two mechanisms were considered and
rejected:

- **Folding it into `health_check`** — that tool deliberately reports local
  posture without opening Odoo, and this check requires a live call.
- **A startup-banner check** — adds Odoo latency and a failure surface to every
  session start, and writes to a stream nobody reads.

Call it daily from whatever already runs scheduled agent work, and treat any
`status` other than `ok` as actionable. Until such a schedule exists, a
calendar reminder set two weeks before the known expiry is the fallback, not a
substitute.
