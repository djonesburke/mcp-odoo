# Change request — API key lifecycle, before the MCP rolls out to Matt & Amber

- **Date**: 2026-08-11
- **Raised by**: Dalton, via the Burke ops dispatcher (`burke-odoo-optimization`)
- **Status**: change request — **not a specification, and nothing here is approved to build yet.** Two blocking questions in §6.
- **Why it is filed here**: implementation lands in this repo. The ops workspace analyses and hands off; it does not write MCP server code.
- **Note on intake**: this repo had **no change-request path** when this was written — no `context/`, no dispatcher, and the `context/mcp-change-request.md` referenced by a 2026-08-08 session was never created. This file establishes one by convention only. **If a real intake mechanism is wanted, decide it deliberately rather than inheriting this filename.**

---

## 1. The ask, and the counter-recommendation

Dalton's question: *"Should we build an easy means of users updating their API keys, so that part is done when we roll out the MCP to Matt & Amber?"*

**Recommendation: yes, build something — but an easy key-updater should be the LAST of four items, not the first.** On its own it treats the symptom and scales the underlying problem.

**Why.** One machine currently holds **five distinct 40-character secrets across eight storage slots**, all plaintext at rest, and until a fingerprint inventory was run on 2026-08-11 nobody could say which one was live. Four of the five are dead material from earlier rotations. Roll that shape out to three users and it becomes **~24 slots across three machines**, with the same "which copy is real?" question — and Dalton is the only person able to answer it.

**A faster paste tool does not reduce the number of places a secret lives. It makes the sprawl efficient.**

And it does not address what has actually failed. Both key incidents at Burke were **silent expiry**, not slow rotation. Odoo does not warn before a key dies; the 2026-08 rotation happened *because* two keys aged out unnoticed.

## 2. Build order

### (1) Expiry monitor — highest value, lowest cost
Read-only against `res.users.apikeys` (that model stores hashes, never key material), alerting at **T-14 days** before `expiration_date`. This is the single change that would have prevented both incidents. It uses an access pattern already trusted and needs no new capability.

Live example of the need: the only key on prod today expires **2026-08-21 00:00:00 UTC**, and nothing anywhere would have said so.

### (2) Collapse the slots to one per machine — do this BEFORE rollout
Current eight, on one machine:

| # | Location | Slot | Disposition |
|---|---|---|---|
| 1–2 | `HKCU\Environment` | `ODOO_PROD_APIKEY`, `ODOO_PROD_API_KEY` | **Delete** — no consumer found; orphaned-but-valid is the worst state for a credential |
| 3–4 | `~\.claude.json` | `odoo-prod.env.ODOO_API_KEY`, `.ODOO_PASSWORD` | Collapse — `ODOO_PASSWORD` duplicates the key |
| 5–6 | `~\.claude.json` | `odoo-staging.env.ODOO_API_KEY`, `.ODOO_PASSWORD` | Collapse — staging shares prod's credential by design |
| 7–8 | `~\.config\odoo-mcp\profiles.json` | `profiles.prod.api_key`, `profiles.staging.api_key` | **Both confirmed dead** (401 on 2026-08-10). Needed only if Claude Desktop's `odoo-mcp-multi` server stays in use |

**Target: one slot per machine.** At one slot, rotation barely needs tooling — which is the point.

### (3) Make failure legible
A non-technical user will not diagnose a 401. An expired or wrong key must produce something like *"Odoo API key expired 2026-08-21 — see the rotation runbook"*, not an empty result.

⚠️ **This matters more here than in a normal codebase.** An empty result from this server currently means any of: wrong field name, restricted field, archived record, a computed-field domain, a genuinely empty set, or a bad credential. **Eleven silent-failure modes are documented** in `burke-odoo-optimization/context/odoo-environment.md`. Adding a twelfth that reads identically to the other eleven is the failure mode to avoid.

### (4) Then a guided `Set-OdooKey`
Updates the one slot, verifies it authenticates, and reports a **fingerprint** (SHA-256 prefix) so two slots can be compared without displaying either. It must **replace** `scripts/Setup-OdooMcp.ps1`, not sit beside it.

⚠️ **`Setup-OdooMcp.ps1` is actively misleading today** and this is documented in the rotation runbook: it writes `odoo-prod`/`odoo-staging` entries into `claude_desktop_config.json`, while the live Claude Code servers read `~\.claude.json`. **Re-running it writes the new key where nothing reads it, leaves the live config on the old key, and reports success.** `docs/odoo-mcp-setup.md` still recommends re-running it — that guidance is stale. **Shipping a second tool alongside a broken one produces a third.**

## 3. Design constraint: keep keys per-user

Do **not** consolidate onto a shared service user for convenience.

- **Odoo API keys are per-user**, so a key on Matt's user carries **Matt's** rights, not admin. That bound is free and correct.
- Attribution depends on it. Because every current MCP call authenticates as uid 6, `write_uid` reads "Dalton Jones" for **both** a human in the UI and any agent — which on 2026-08-11 made the question *"was this five-product write yours?"* **unanswerable from the data.** A shared service user makes that permanently worse.

A dedicated **read-only** service user for unattended/scheduled reads is a separate, reasonable idea (named `burke-mcp-deploy` in TOPOLOGY, unimplemented). It is **not** a substitute for per-user keys, and it is an architecture change — not a rotation step.

## 4. Evidence base

All established 2026-08-10/11 against live Burke Odoo, read-only unless noted.

- **Five distinct secrets across eight slots on one machine**, four of them dead. Verified by SHA-256 fingerprint, no value displayed.
- **Exactly one `res.users.apikeys` record exists on prod** — id 12, `scope: false` (unscoped ⇒ full user rights), created 2026-07-22, expiring 2026-08-21. **Therefore at most one stored string can authenticate; the rest are dead by definition.**
- **`profiles.json`'s two values are provably dead** — 401 on both, which broke `scripts/odoo_readonly.py` in the ops workspace.
- **Keys expire silently.** Odoo emits no warning. Both Burke incidents were expiry, not compromise.
- **A masking bug printed a credential in cleartext to the startup banner** on 2026-08-04, fixed same-session in commit `e7bc9ec`. ⚠️ **Which secret it printed is NOT established** — the runbook attributes it to slot 1, a registry orphan, which would mean a **dead** key leaked. Two sources conflict and it was deliberately left unresolved rather than guessed, because settling it requires reading key material.
- **A second cleartext exposure occurred 2026-08-11**, into a session transcript, caused by a PowerShell helper named `H` colliding with the `Get-History` alias so raw values were echoed in error text. **Relevant to this request:** any tooling that handles a key must be written so a *failure path* cannot print it. That is a design requirement, not an incident note.
- **`Setup-OdooMcp.ps1` writes to a file nothing reads and reports success** (runbook §7).
- **Windows Credential Manager is unverified** as a ninth slot; `Setup-OdooMcp.ps1` handles a `SecureString` internally but was never confirmed to persist one.
- **Only uid 6 held any API key on prod as of 2026-08-04**, so other Burke PCs are either unprovisioned or sharing Dalton's credential. **Establish which before assuming any inventory is complete.**

## 5. Related findings in this repo's lane, not separate problems

Both surfaced during the same work and both bear on a rollout:

- **The side-effect policy file is SHARED between prod and staging.** `allowed_side_effect_methods` is `[]` in `odoo_mcp_policy.json`, annotated *"Change only via PR"*, and **both `odoo-prod` and `odoo-staging` point `ODOO_MCP_POLICY_FILE` at that same file.** So **there is no such thing as a staging-only method allowlist** — enabling a method to unblock a staging test would enable it on **production**, for every session. On 2026-08-11 this blocked a legitimate staging test of `stock.picking.action_assign`, and the worker correctly refused to edit the file.
- **`standard_price` is writable but NOT readable** through this server (`fields_get` → `access: restricted`; a `search_read` silently strips rows to bare `{"id"}`). **Write-without-read is the worst pairing**: it permits a change and forbids its verification. It left an applied production correction unverifiable and has now blocked three separate pieces of work. Same policy affects `margin` and `purchase_price`.

Neither is in scope below, but **a rollout decision made without them is incomplete.**

## 6. ⛔ Two blocking questions — do not start building before these are answered

1. **Which surfaces do Matt and Amber actually need — Claude Code, Claude Desktop, or Chat only?** Different surfaces read different slots (`~\.claude.json` vs `profiles.json`). **If they are Chat-only they may need no local key at all**, and items (2) and (4) largely evaporate. This determines whether there is anything to build.
2. **Should their MCP be able to write to production?** `write_execution_enabled` is currently **`true` on both instances.** Provisioning Matt as-is hands him a tool that can write to prod under a policy file he does not control and cannot safely change. **Decide this before rollout, not after.**

## 7. Out of scope

- Building a dedicated service user (architecture, not rotation).
- Rotating any key. **Claude does not generate, enter, or read back a credential** — that boundary holds regardless of how a request is framed, and it is stated in the runbook's §2.
- Changing `write_execution_enabled` or the side-effect policy. Those are decisions, recorded above, not tasks.
- Anything on machines other than Dalton's until §4's last bullet is settled.

## 8. Sequencing

**Fix the expiry blindness → collapse the slots → then roll out.** Rolling out first means doing the cleanup three times instead of once.

**See also**: `burke-os/runbooks/odoo-api-key-rotation.md` (the authority on rotation; never executed, so treat its first run as testing the document) · `burke-odoo-optimization/context/odoo-environment.md` (the eleven silent-failure hazards) · `burke-odoo-optimization/dispatcher/QUEUE.md` items `S15`, `S23`, `S27`, `S30`.
