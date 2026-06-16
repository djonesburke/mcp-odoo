# Burke Truck & Equipment — Odoo MCP Operations Runbook

Internal runbook for the BTE fork of `mcp-odoo` (`djonesburke/mcp-odoo`, branch
`burke-patches`). Audience: whoever operates or troubleshoots the MCP server.

> Current state: pinned to upstream **v1.0.0** (39 tools). Transport **json2**.
> Target instance: `staging.burketruck.com`. Auth user: `djones@burketruck.com`.

---

## 1. Transport: json2 only

We standardize on the **JSON-2 External API** (`ODOO_TRANSPORT=json2`), not
XML-RPC. Odoo is removing XML-RPC in 20.0, so json2 is the forward-compatible
path. Do not reintroduce the XML-RPC transport.

json2 requests use `urllib` under the hood. That matters for Cloudflare (below).

---

## 2. Cloudflare — the error 1010 fix (DO NOT re-patch the client)

**Symptom:** json2/HTTP calls return `HTTP 403`, `Server: cloudflare`, body
`error code: 1010`.

**Cause:** Cloudflare **Browser Integrity Check (BIC)** rejects the
`Python-urllib/*` User-Agent signature on the proxied host before the request
reaches Odoo. (Super Bot Fight Mode also blocks "definitely automated" traffic.)

**Proper fix (already in place):** the zone `burketruck.com` WAF custom rule
**"Odoo API - Apps Script"** skips, for the Odoo API paths on
`burketruck.com` / `www` / `staging`:
`http_ratelimit`, `http_request_firewall_managed`, `http_request_sbfm`, and
**Browser Integrity Check** (`products: ["bic"]`).

This is the supported fix. We do **not** spoof the User-Agent in code — that
workaround (old commit `d127b28`) was reverted because it only covered json2,
not the whole surface, and masked a Cloudflare misconfiguration.

**Verify from any host that can reach the origin:**
```bash
# Should return 404 (Odoo answering), NOT 403/1010
curl -s -o /dev/null -w "%{http_code}\n" -A "Python-urllib/3.12" \
  https://staging.burketruck.com/json/2/
```

---

## 3. Field-level ACL (read-path data masking)

The MCP authenticates as an **admin** Odoo user, so Odoo's own field groups do
not constrain it. The field ACL is therefore the **primary** control that keeps
sensitive data out of AI responses.

- Policy file: `odoo_mcp_policy.json` (repo root, version-controlled).
- Wired in via env var: `ODOO_MCP_POLICY_FILE` → absolute path to that file.
- What it masks today: sale margin & cost (`sale.order`, `sale.order.line`,
  product `standard_price`), partner financials & bank numbers (`res.partner`,
  `res.partner.bank`), and employee PII + compensation (`hr.employee`,
  `hr.version`).
- Responses report what was hidden via a `redacted_fields` array — redaction is
  visible, not silent.
- **Fail-closed:** a malformed policy file raises at startup rather than running
  unprotected. Always validate after editing.

**Extend / edit:** add fields to a model's `deny` list (blacklist) or switch a
model to `allow` (exclusive whitelist). Then validate:
```powershell
$env:ODOO_MCP_POLICY_FILE = "E:\Documents\Claude\Projects\mcp-odoo\odoo_mcp_policy.json"
& "E:\Documents\Claude\Projects\mcp-odoo\.venv\Scripts\python.exe" -c "import sys; sys.path.insert(0,'src'); import odoo_mcp.field_policy as f; p=f.get_field_policy(); print('active:', p.active(), p.instances())"
```

**Known limitation:** the ACL hides fields in *results* and blocks *aggregation*
on denied fields, but does **not** block *domain filtering*. A user could filter
`sale.order.line` by `margin > X` and infer ranges from which rows match. Closing
that fully requires a limited Odoo user or not exposing raw search to the team.

---

## 4. Write access (off by default)

Writes are gated and **disabled** unless explicitly enabled:

- `ODOO_MCP_ENABLE_WRITES=1` turns on `execute_approved_write`.
- Writes are **two-phase**: `preview_write` issues a canonical payload + approval
  token; `execute_approved_write` requires the matching token **and**
  `confirm=true`. Tokens are TTL'd and batch-size capped.
- Side-effect methods (e.g. `action_confirm`) require an **exact allowlist** in
  `allowed_side_effect_methods` (env or the policy file). Empty = none allowed.
- The MCP points at `staging` today, so write access applies to staging. If the
  URL is ever repointed at production, the same flag enables writes there.

---

## 5. Health & verification

```
# via the MCP: health_check  -> confirm:
#   tool_count: 39, field_acl.active: true, write_execution_enabled: <intended>
#   side_effect_policy.file points at odoo_mcp_policy.json, error: null
```

Functional ACL check (should list denied fields under `redacted_fields`):
search `sale.order.line` for `["name","price_unit","margin","purchase_price"]`.

---

## 6. Upgrading the server

Pinned to a tag, never `main`:
```bash
git fetch upstream --tags
git merge --no-edit vX.Y.Z      # the chosen release tag
.venv/Scripts/python -m pytest -q   # expect all pass on a clean env
```
After merge, fully restart the Claude app so the MCP relaunches on new code.

> Note: a real `ODOO_API_KEY` in the shell env will leak into `test_config.py`;
> run that test with the var cleared if it "fails" locally — it's environmental.
