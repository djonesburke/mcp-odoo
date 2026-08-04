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
| Package version | `1.3.0+burke.1` |
| Upstream base | `erpipe-org/mcp-odoo` tag `v1.3.0` |
| Fork | `djonesburke/mcp-odoo`, branch `burke/hardening-1.3.0` |
| Burke delta | two write-safety behaviors (§5) + field-ACL policy + this doc |

The `+burke.1` local-version suffix is the point of the version stamp: if
`health_check` or `--version` reports a bare `1.3.0`, the machine is running
**vanilla upstream from PyPI, not this build.** That distinction is the whole
reason the suffix exists — check it first when something behaves unexpectedly.

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

Expect `1.3.0+burke.1`. A bare `1.3.0` means PyPI upstream; anything `0.x` means
you hit `odoo-mcp-multi`.

### Option B — explicit module invocation (immune to the name collision)

```bash
uvx --from git+https://github.com/djonesburke/mcp-odoo@burke/hardening-1.3.0 python -m odoo_mcp --version
```

Pin to a **tag** rather than a branch once one is cut, so the four PCs cannot
drift apart between installs.

---

## 3. Claude Desktop configuration

`%APPDATA%\Claude\claude_desktop_config.json`. Replace every `<...>`.

```json
{
  "mcpServers": {
    "odoo-staging": {
      "command": "odoo-mcp",
      "args": ["run"],
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

### Env var reference

| Variable | Value | Why |
|---|---|---|
| `ODOO_TRANSPORT` | `json2` | XML-RPC is deprecated (Odoo 22 removal). Do not reintroduce it. |
| `ODOO_MCP_POLICY_FILE` | absolute path | Field ACL. The MCP authenticates as an Odoo **admin**, so Odoo's own field groups do not constrain it — this file is the primary read-path control. |
| `ODOO_MCP_TOOLS_EXCLUDE` | `execute_method` | **Required.** See §4. |
| `ODOO_MCP_ENABLE_WRITES` | omit, or `1` | Omit for a read-only machine. Setting `1` enables `execute_approved_write` **and** `chatter_post`. |
| `ODOO_MCP_AUDIT_LOG` | absolute path | Per-call audit trail. Ends in `.jsonl`, which is gitignored — keep it outside any repo. |
| `MCP_CHATTER_DIRECT` | **omit** | Setting `1` lets `chatter_post` skip its approval token. Do not set it. |

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

## 5. The two Burke write-safety behaviors

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

Both are covered by tests: `tests/test_chatter_write_gate.py` and the
registry-shape cases in `tests/test_plugins.py`.

---

## 6. Per-PC acceptance checklist

Run on each machine after setup. No live Odoo write is performed.

- [ ] `uv tool list` — confirm no shadowing `odoo-mcp-multi`, or plan to use §2 option B
- [ ] `odoo-mcp --version` → **`1.3.0+burke.1`** (a bare `1.3.0` is the wrong build)
- [ ] `odoo-mcp --health` exits 0
- [ ] In Claude, call `health_check` and confirm:
  - [ ] `field_acl.active` is `true` — if `false`, `ODOO_MCP_POLICY_FILE` is wrong and **all masking is off**
  - [ ] `side_effect_policy.error` is `null`
  - [ ] `tools_filtered` contains `execute_method`
  - [ ] `write_execution_enabled` matches what this machine is supposed to be
- [ ] Confirm masking end to end: read `sale.order.line` asking for
      `["name","price_unit","margin","purchase_price"]`. Expect `margin` and
      `purchase_price` to come back under `redacted_fields`, not as values.
- [ ] Confirm the audit log path is being written and is **outside** any git repo
- [ ] Confirm `MCP_CHATTER_DIRECT` is not set

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

## 8. Upgrading to a newer upstream

```bash
git fetch upstream --tags
git checkout main && git merge --ff-only upstream/main   # or merge the chosen tag
git checkout -b burke/hardening-<NEW_VER> main
git cherry-pick <behavior-1> <behavior-2>
```

A clean cherry-pick is **not** proof the behaviors still work — upstream may have
refactored the code the patch lands on. Re-prove both behaviors by removing each
source change, watching the corresponding tests fail, restoring it, and watching
them pass. Then bump the version suffix to `<NEW_VER>+burke.1` and fully restart
Claude so the MCP relaunches on the new code.
