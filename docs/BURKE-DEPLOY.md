# Burke Truck & Equipment — Odoo MCP deployment

Hand this to whoever sets up a machine. Target: **local stdio on Windows**, one
pinned build across all Burke PCs.

> **This file lives in a PUBLIC repository.** Every Burke-specific value below is
> a `<PLACEHOLDER>`. Get the real values from Dalton — they are not written down
> here, and must not be added to this file.

---

## 1. What this build is

| | |
|---|---|
| Package version | `1.3.0+burke.10` |
| Upstream base | `erpipe-org/mcp-odoo` tag `v1.3.0` |
| Fork | `djonesburke/mcp-odoo`, branch `burke/hardening-1.3.0` |
| Burke delta | five write-safety behaviors (§5) + read-path error surfacing (§8) + version readout + field-ACL policy + `check_api_key_expiry` (§9) + optional `ODOO_PASSWORD` (§10) + read-only team bundle (§12) + this doc |

The `+burke.N` local-version suffix is the point of the version stamp: if
`health_check` or `--version` reports a bare `1.3.0`, the machine is running
**vanilla upstream from PyPI, not this build.** That distinction is the whole
reason the suffix exists — check it first when something behaves unexpectedly.

Note that upstream v1.3.0 exposes **no version at all** — no `--version` flag and
no version field in `health_check`. Burke added both (`server_core.package_version()`,
surfaced in `--version`, `--health`, and the `health_check` tool), because bumping
the version number achieves nothing if no one can read it back. This is a Burke
delta to re-audit on each upstream bump: if upstream later adds its own version
readout, drop ours rather than carrying two.

### ⚠ Command-name collision — read before installing

`odoo-mcp` is **also** the console-script name of an unrelated package,
`odoo-mcp-multi` (Vauxoo). If that package is already installed via `uv tool`,
its binary owns the name `odoo-mcp` on that machine and will shadow this one.

Check before and after installing:

```bash
uv tool list
```

If `odoo-mcp-multi` appears and you need both, do **not** rely on the bare
`odoo-mcp` command. Invoke this build explicitly by module (§2, option B),
which cannot be shadowed.

---

## 2. Install

### Option A — pinned uv tool install (preferred for a normal PC)

```bash
uv tool install --force git+https://github.com/djonesburke/mcp-odoo@burke/hardening-1.3.0
```

Verify it is *this* build and not upstream or the Vauxoo package:

```bash
odoo-mcp --version
```

Expect `1.3.0+burke.10`. A bare `1.3.0` means PyPI upstream; anything `0.x` means
you hit `odoo-mcp-multi`.

### Option B — explicit module invocation (immune to the name collision)

```bash
uvx --from git+https://github.com/djonesburke/mcp-odoo@burke/hardening-1.3.0 python -m odoo_mcp --version
```

Pin to a **tag** rather than a branch once one is cut, so the four PCs cannot
drift apart between installs.

---

## 3. Claude Desktop configuration

This is the hand-configured path, for an operator's own PC. For a read-only
team machine, build the `.mcpb` bundle instead (§12) — it needs no JSON editing
and cannot be configured wrong on arrival.

`%APPDATA%\Claude\claude_desktop_config.json`. Replace every `<...>`.

```json
{
  "mcpServers": {
    "odoo-staging": {
      "command": "odoo-mcp",
      "args": [],
      "env": {
        "ODOO_URL": "<https://staging.example.com>",
        "ODOO_DB": "<staging-db-name>",
        "ODOO_USERNAME": "<user@example.com>",
        "ODOO_API_KEY": "<odoo-api-key>",
        "ODOO_TRANSPORT": "json2",
        "ODOO_MCP_POLICY_FILE": "<C:\\path\\to\\odoo_mcp_policy.json>",
        "ODOO_MCP_AUDIT_LOG": "<C:\\path\\to\\audit-staging.jsonl>",
        "ODOO_MCP_TOOLS_EXCLUDE": "execute_method"
      }
    }
  }
}
```

There is **no `run` subcommand.** An earlier revision of this file showed
`"args": ["run"]`; the CLI defines only flags, so argparse rejects the bare word
and the server exits 2 before it opens stdio. The symptom in Claude is a server
that fails to start with nothing useful on screen. Verified 2026-08-21:

```
__main__.py: error: unrecognized arguments: run
```

### Env var reference

| Variable | Value | Why |
|---|---|---|
| `ODOO_TRANSPORT` | `json2` | XML-RPC is deprecated (Odoo 22 removal). Do not reintroduce it. |
| `ODOO_MCP_POLICY_FILE` | absolute path | Field ACL. The MCP authenticates as an Odoo **admin**, so Odoo's own field groups do not constrain it — this file is the primary read-path control. |
| `ODOO_MCP_TOOLS_EXCLUDE` | `execute_method` | **Required.** See §4. |
| `ODOO_MCP_ENABLE_WRITES` | omit, or `1` | Omit for a read-only machine. Setting `1` enables `execute_approved_write` **and** `chatter_post`. |
| `ODOO_MCP_ELICIT_WRITES` | `1` wherever writes are on | Requires a human to confirm each write. Set it on every machine that sets `ODOO_MCP_ENABLE_WRITES`; without it the agent approves its own writes (§5, behavior 3). |
| `ODOO_MCP_AUDIT_LOG` | absolute path | Per-call audit trail. Ends in `.jsonl`, which is gitignored — keep it outside any repo. |
| `MCP_CHATTER_DIRECT` | **omit** | Setting `1` lets `chatter_post` skip its approval token. Do not set it. |
| `ODOO_MCP_ROTATION_DOC` | runbook path | Echoed by `check_api_key_expiry` so an expiry alert names its own remedy (§9). Not a credential. |

Do **not** point a server at a live git working copy (`uv run --directory ...`).
A checkout can be moved or switched between branches by unrelated work, silently
changing the code a server executes. Use the pinned install.

---

## 4. Why `execute_method` must be excluded

`execute_method` classifies any method named `get_*` or `_get_*` as `read_only`
(`diagnostics.py`), and read-only classification **skips the side-effect
allowlist check entirely**. An Odoo model method named `get_...` that in fact
mutates data would therefore execute with no allowlist review.

Upstream v1.3.0 still behaves this way. We do **not** patch it — we remove the
tool at deploy time. That is why `ODOO_MCP_TOOLS_EXCLUDE` is mandatory, and why
Behavior 2 (§5) makes the filter fail closed: a silently-skipped filter would
put `execute_method` back with no warning.

---

## 5. The five Burke write-safety behaviors

**Behavior 1 — `chatter_post` requires `ODOO_MCP_ENABLE_WRITES`.**
Upstream gates `execute_approved_write` on this flag but not `chatter_post`, which
reaches `message_post` directly. On the default `comment` subtype that notifies
followers by email, and `partner_ids` / `attachment_ids` pass straight through —
so a deployment intended as read-only could email an external partner with
attachments. The gate is at function entry, ahead of both the preview/token
branch and the `MCP_CHATTER_DIRECT` branch, so a refused call never opens a
connection and preview never issues a token the server would refuse to honour.

**Behavior 2 — the tool filter fails closed.**
`apply_tool_filter()` reaches into a private FastMCP attribute
(`mcp._tool_manager._tools`). Upstream returns silently if that is not a dict, so
a future SDK rename would make `ODOO_MCP_TOOLS_EXCLUDE` stop working with no
signal — restoring `execute_method`. This build raises at startup instead.

**Behavior 3 — the human confirmation gate fails closed.**
`ODOO_MCP_ELICIT_WRITES=1` asks a human to approve each write before it
executes. Upstream approved automatically when the client could not be asked —
no elicitation capability, URL-mode-only elicitation, or an error raised by the
elicit call. On such a client "confirm every write" silently became "write
freely", with the operator still believing a gate was in place.

That matters more than it looks, because **every other gate on the write path
is one the calling agent satisfies by itself**: the approval token, the
server-side validation record, the payload match, and `confirm=true` are all
supplied by the agent in the same turn. The elicitation prompt is the only
point where a person stands in the path. This build refuses the write and says
why, and the refusal is audited as `blocked` rather than `declined` so the log
distinguishes "nobody was asked" from "someone said no".

**Any client that does not declare form-mode elicitation is refused as
unaskable.** The check originally tested for url-mode *specifically*, which let
the commonest shape through: an elicitation object with neither `form` nor `url`
set. That is what `claude-code 2.1.234` sends — it advertises the capability,
cannot prompt, and declines on its own. So the refusal was audited as `declined`
and read as though the operator had said no, which sends whoever is debugging it
looking for a person who changed their mind. It is now `blocked`, with an error
naming the missing capability and the remedy.

Every `elicit` line also carries `client_elicitation=` — `form`, `url-only`,
`declared-none`, `declared-empty` or `uninspectable` — plus the client name from
the initialize handshake. That field is what located this bug, and it is the
first thing to read when a refusal is disputed.

**Residual, genuinely not closed.** A client whose capabilities cannot be
introspected at all still falls through to `ctx.elicit`, because there the elicit
call is the only authority available. And a client that declares form mode and
then declines without prompting stays indistinguishable from a human who
declined. The server can record what a client claimed it could show; it cannot
prove a human saw it.

The practical consequence: **an unattended run cannot write, and neither can a
client that cannot prompt.** A scheduled Cowork job has no one at the keyboard,
so with the gate on it fails visibly instead of proceeding unwatched. As of
2026-08-20 that also covers Claude Code, which declares no form mode — so on a
machine with `ODOO_MCP_ELICIT_WRITES=1`, **writes from Claude Code are refused
outright.** That is the gate working, not a defect. Doing gated writes from that
client needs either a client that can prompt, or a deliberate, logged decision to
unset the gate on that instance and accept agent-only approval.

**Behavior 4 — the confirmation shows what the write replaces.**
Upstream's prompt echoed the proposed values only. That reads like a diff but
is half of one: it cannot show that a field is already at the target value,
and an `unlink` prompt identified records as bare integers (`[30530]`), which
is not something a human can approve responsibly.

`validate_write` now reads the affected records once and holds the snapshot
server-side, and the prompt renders:

- record ids **with display names**, so `unlink` names what it deletes;
- per-field `before -> after`;
- fields already at the target value, marked `(unchanged - already set)`;
- fields the field ACL denies, marked `<hidden by field policy>` — a
  confirmation dialog must not become a way to read masked margin or cost;
- a `WARNING` line naming the reason when the snapshot could not be read.

The snapshot is deliberately **not** part of the approval token payload — if it
were, the token would change whenever Odoo data changed and a validated
approval would stop matching itself mid-flight. The read is best-effort: a
failed snapshot degrades the prompt and states why, rather than taking the
write path down when Odoo hiccups.

**Behavior 5 — the attachment-upload race guard works on Windows.**
`_read_attachment_source_file` closes the TOCTOU window between the
upload-root containment check and the read by opening with `O_NOFOLLOW`.
**`os.O_NOFOLLOW` does not exist on Windows**, where `getattr(os,
"O_NOFOLLOW", 0)` degrades to `0` — so on the only platform Burke deploys on,
the open silently followed whatever the final path component pointed at, and
the guard was absent.

Worse, its test passed on Windows for the wrong reason: it simulated the
attack by creating a symlink, which fails on a machine without Developer Mode,
so the test reported green having never performed the attack. On a machine
with Developer Mode enabled it failed — which is how this surfaced.

This build adds a portable identity check: after opening, the descriptor's
`(st_dev, st_ino)` must match `os.lstat()` of the same path, which does not
follow a final symlink. A swapped entry, a symlink, or a filesystem that
reports no usable file id all refuse the read. The symlink test now skips
rather than passing where it cannot create a symlink, and the mechanism has
direct tests that run on every platform.

Scope: reachable only when writes are enabled **and**
`ODOO_MCP_ATTACHMENT_UPLOAD_ROOTS` is set. Neither is true on a read-only
machine. Parity with POSIX, not beyond it — a swapped parent directory and a
hard link inside the upload root are out of scope on both platforms.

All five are covered by tests: `tests/test_chatter_write_gate.py`, the
registry-shape cases in `tests/test_plugins.py`,
`tests/test_write_confirmation.py`, and `tests/test_attachment_upload.py`.

### Where behaviors 3 and 4 apply

Only on a machine with writes enabled. A read-only deployment has no write path
to gate, which is why the read-only rollout does not depend on either of them.

---

## 6. Per-PC acceptance checklist

Run on each machine after setup. No live Odoo write is performed.

- [ ] `uv tool list` — confirm no shadowing `odoo-mcp-multi`, or plan to use §2 option B
- [ ] `odoo-mcp --version` → **`odoo-mcp 1.3.0+burke.10`** (a bare `1.3.0` is the wrong build)
- [ ] `odoo-mcp --health` exits 0 and its JSON shows `"package_version": "1.3.0+burke.10"`
- [ ] In Claude, call `health_check` and confirm:
  - [ ] `package_version` is `1.3.0+burke.10`
  - [ ] `field_acl.active` is `true` — if `false`, `ODOO_MCP_POLICY_FILE` is wrong and **all masking is off**
  - [ ] `side_effect_policy.error` is `null`
  - [ ] `tools_filtered` contains `execute_method`
  - [ ] `write_execution_enabled` matches what this machine is supposed to be
  - [ ] `elicit_writes_enabled` is `true` on any machine where
        `write_execution_enabled` is `true` — those two must never disagree
  - [ ] `chatter_direct_enabled` is `false`
- [ ] **Writes-enabled machines only** — confirm the human gate is real. Preview
      and validate a harmless one-field write on **staging**, then execute it and
      confirm that:
  - [ ] a confirmation prompt actually appears
  - [ ] it names the record by display name, not just by id
  - [ ] it shows the current value on the left of the `->`
  - [ ] declining it returns "declined by the human reviewer" and changes nothing
  A write that executes with no prompt means `ODOO_MCP_ELICIT_WRITES` is unset
  or the client cannot elicit — stop and fix it before touching production.
- [ ] Confirm masking end to end: read `sale.order.line` asking for
      `["name","price_unit","margin","purchase_price"]`. Expect `margin` and
      `purchase_price` to come back under `redacted_fields`, not as values.
- [ ] Confirm the audit log path is being written and is **outside** any git repo
- [ ] Confirm `MCP_CHATTER_DIRECT` is not set
- [ ] Call `check_api_key_expiry` and confirm `instance_kind` matches the label on
      the connection, `database` is the database you expect, and `status` is not
      `expired`. Note `visibility`: `own_user_only` means this report does **not**
      cover anyone else's keys (§9).

If `field_acl.active` is `false`, stop and fix it before letting anyone use the
machine. Every other control assumes the ACL is on.

---

## 7. Known limitation — not closed by this build

The field ACL removes denied fields from *results* and blocks *aggregation* on
them, but does **not** block *domain filtering*. Someone can filter
`sale.order.line` by `margin > X` and infer ranges from which rows match.

Closing this properly needs a restricted Odoo user rather than admin
credentials, or not exposing raw search to the team. Read-only tool configs and
skill defaults are conveniences, not security boundaries — Odoo per-user ACLs
are the enforcement layer.

---

## 8. A failed read is never served as "no data"

Upstream `OdooClient.search_read` and `read_records` both ended in:

```python
except Exception as e:
    print(f"Error in search_read: {str(e)}", file=sys.stderr)
    return []
```

Every Odoo-side failure on the two most-used read paths became an empty list.
The message went to stderr, which in a Claude Desktop extension nobody ever
sees. The caller could not distinguish **"nothing matched"** from **"your query
was invalid"**, **"your key expired"**, or **"the server returned 500"**.

Reproduced against Burke production on 2026-08-13, read-only:

| Call | Result |
|---|---|
| `res.partner`, `fields=["id","name"]` | records returned |
| `res.partner`, `fields=["id","name","totally_bogus_field_xyz"]` | `success: true`, `count: 0`, `error: null` |

`res.groups.full_name` no longer exists in Odoo 19, so an ordinary request
answered "there are no such records" about records that were sitting there.

**Why this outranks most of the write-path work for a read-only deployment.**
An error is recoverable — the reader retries. A confident empty answer is not:
it gets believed. Anyone reaching Odoo by describing what they want in English
will guess field names, and every miss would read as a fact about the business.
This is also the mechanism behind the symptom
[credential-lifecycle.md](credential-lifecycle.md) documents — an expired key
surfacing as an empty result rather than an error.

Both methods now re-raise. Every call site already wrapped them in a structured
error envelope, so the error reaches the user as `success: false` with the Odoo
message. `read_record` in particular stops reporting "Record not found" for a
record that exists.

The stderr line is kept: an operator tailing logs still gets it, and it is now
accompanied by a real error rather than replacing one.

Covered by `tests/test_read_error_surfacing.py`, which also pins the other
direction — a genuinely empty search still returns `success: true, count: 0`,
and a genuinely missing id still returns "Record not found". A fix that traded
a false negative for a false alarm would be no better than the bug.

**Still swallowed, deliberately:** `get_installed_modules` returns `[]` on
failure (metadata for `get_odoo_profile`; a profile call should degrade rather
than fail outright). Every other error path in `odoo_client.py` already returns
`{"error": ...}` and always did.

---

## 9. API key expiry monitoring

Odoo never warns before an API key expires, and an expired key surfaces
downstream as an **empty result**, not an error. `check_api_key_expiry` is the
Burke addition that makes that state legible: read-only, a fixed six-field
projection of `res.users.apikeys`, and no key material read or returned. Full
behavior in [credential-lifecycle.md](credential-lifecycle.md).

Two things to know when using it:

- **It reports what *this credential* can see.** Odoo restricts non-system users
  to their own key records, so `visibility: own_user_only` means other users'
  keys are not covered. A clean report from one machine is not an estate-wide
  all-clear.
- **A tool nobody calls prevents nothing.** The server has no timer. Until a
  scheduled job calls this daily and surfaces a non-`ok` status, the fallback is
  a calendar reminder two weeks before the known expiry — that reminder stays
  mandatory, not optional.

---

## 10. One credential slot per server, not two

`ODOO_PASSWORD` is **optional when `ODOO_API_KEY` is set.** Upstream required
both to be present before it would build an instance from environment
variables, which forced every API-key deployment to store the same 40-character
secret twice, under two names, in every config file. Six credential slots on one
machine were four more than the deployment needed.

The change is permissive and backward compatible: a config carrying both keeps
working unchanged, so a machine can move to this build first and drop the
duplicate afterwards, with no window where Odoo is unreachable. The two slots
also fall back to each other in both directions — an Odoo API key authenticates
over XML-RPC wherever a password does, so collapsing the slot does not depend on
the transport.

A partly-set environment now names the variables that are missing instead of
reporting "no Odoo configuration found", which sent the reader hunting for a
config file that was never the problem.

**Per-user keys are the same string on prod and staging.** Staging is
regenerated from a neutralized prod snapshot, and a key belongs to a `res.users`
record rather than to an instance. So a machine with both connections holds one
secret in two places by necessity — that is the floor, not redundancy to remove.
It also means staging is a valid canary: it exercises the identical credential
prod uses. Manage keys in prod only, and remember a config labelled `staging`
that carries prod's database name reaches production and authenticates fine —
`check_api_key_expiry`'s `instance_kind` and `database` fields are what catch
that.

---

## 11. Upgrading to a newer upstream

```bash
git fetch upstream --tags
git checkout main && git merge --ff-only upstream/main   # or merge the chosen tag
git checkout -b burke/hardening-<NEW_VER> main
git cherry-pick <behavior-1> <behavior-2>
```

A clean cherry-pick is **not** proof the behaviors still work — upstream may have
refactored the code the patch lands on. Re-prove all five behaviors by removing
each source change, watching the corresponding tests fail, restoring it, and
watching them pass. Then bump the version suffix to `<NEW_VER>+burke.1` and fully
restart Claude so the MCP relaunches on the new code.

Behaviors 3 and 4 both sit on MCP elicitation, which is a moving part of the
protocol. If upstream reworks `_resolve_write_confirmation` or the SDK changes
how client capabilities are advertised, re-run the §6 writes-enabled check by
hand — a green test suite proves the refusal logic, not that a real Claude
client still renders the prompt.

---

## 12. The team `.mcpb` bundle — read-only, one-click

**The bundle is built in `burke-mcp-deploy`, not here.** That repo is private
and owns deployment: the manifests, the field-ACL policy that ships in them,
the per-connection instructions, the installer pin, and the org-wide upload
procedure. This section covers only what belongs to the *server* — what a
correct bundle must contain and how to prove one is correct before anyone
installs it.

### Never ship the upstream bundle

`scripts/build_mcpb.py` in this repo, and the `.mcpb` on the upstream releases
page, resolve `uvx odoo-mcp==<version>` from **PyPI**. Burke's `+burke.N` build
was never published there, so that bundle can only ever install vanilla
upstream — with none of §5, and, worse for a read-only audience, none of §8.
Its `user_config` also exposes exactly four fields (url, db, username,
password) and cannot set `ODOO_MCP_POLICY_FILE` or `ODOO_MCP_TOOLS_EXCLUDE`, so
an install from it runs with **field masking off and `execute_method`
present**.

A Burke bundle vendors the wheel built from a pinned checkout instead. That
pins harder than a tag, needs no git on the target PC, and cannot be shadowed
by `odoo-mcp-multi` (§1), because `uvx --from <wheel>` resolves the console
script inside that wheel only.

### What a correct read-only bundle looks like

| | |
|---|---|
| Prompts for | Odoo login + API key. Nothing else — a database name typed by hand is how §10 goes wrong. |
| Vendored | the wheel, `odoo_mcp_policy.json`, the instructions file — all addressed via `${__dirname}`, never an absolute machine path |
| Excluded tools | `execute_method` (mandatory, §4) plus the rest of the write surface |
| Absent | `ODOO_MCP_ENABLE_WRITES`, `ODOO_MCP_ELICIT_WRITES`, `MCP_CHATTER_DIRECT` |

Two things that are easy to get wrong, both of which cost a failed rollout on
2026-08-24:

- **Do not declare `compatibility.runtimes.python`.** uv provisions its own
  Python, so a machine with no system interpreter runs the bundle fine.
  Declaring a runtime makes Claude Desktop demand a *system* Python and show an
  unmet requirement, which stops a non-technical installer cold. The upstream
  template carries this line; do not copy it.
- **`ODOO_MCP_AUDIT_LOG` does not audit reads.** `record_write_event` fires on
  the write path only — preview, validate, execute, chatter. On a read-only
  bundle it names a file that stays empty forever, implying a trail that does
  not exist. Leave it out and say so.

### Verify a bundle before anyone installs it

```bash
uv run python scripts/verify_burke_mcpb.py <bundle>.mcpb <scratch-dir>
```

This extracts the bundle to a path containing a space (the real extensions
directory has one), launches the exact command its manifest declares, and
drives a real MCP handshake over stdio with fake Odoo credentials — nothing
touches Odoo. It asserts the Burke version, `field_acl.active`, the filtered
tool list, and that no write tool appears in `tools/list`. Verified against the
`burke-mcp-deploy` bundle on 2026-08-24:

```
tools exposed: 37
write tools exposed: none
package_version 1.3.0+burke.10   field_acl.active true
tools_filtered  chatter_post, execute_approved_write, execute_method,
                preview_write, validate_write
write_execution_enabled false   chatter_direct_enabled false
RESULT: PASS
```

In `health_check` output, `tools_filtered` sits under **`plugins`**, not at the
top level, and the §6 posture fields sit under **`runtime`**. Worth knowing
before concluding a field is missing.

### Residual, not closed by any bundle

- **`uv` must be on `PATH` for GUI apps.** The manifest format has no field to
  declare it, so it will never appear in the extension's Requirements list.
  `winget install --id=astral-sh.uv`, then fully restart Claude Desktop.
- **§7 still stands.** The ACL strips denied fields from *results*, not from
  *domains* — `margin > X` as a filter still discriminates. The MCP
  authenticates as an Odoo **admin**, so the tool config is a convenience, not
  a boundary. Real containment is a restricted Odoo user per person, which is
  what `SERVICE-USERS.md` in `burke-mcp-deploy` specifies. Widening the
  audience makes that more worth doing, not less.
- **One key per person.** Per-user keys are the same string on prod and staging
  (§10), and `check_api_key_expiry` reports only the key it is using
  (`visibility: own_user_only`).
