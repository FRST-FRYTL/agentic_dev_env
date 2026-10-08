# Hooks

Barebone guardrails and memory hooks. Python stdlib only, ~20 ms each, no model calls.
Every rule has a **domain** (what it protects) and a **class** (how hard).

| Class | Decision | On hook error | Override |
|---|---|---|---|
| P0 Lock | deny | deny | only the user, outside the session |
| P1 Block | deny | allow (fail open) | `gitleaks:allow` marker / `secret_allowlist.txt` |
| P2 Confirm | ask (→ P1 when autonomous) | allow | the user's answer |
| P3 Advise | context note | allow | ignore it |
| P4 Audit | log only | allow | — |

Domains: **SEC** secrets · **DST** destructive · **OUT** outward · **GRD** guardrails · **KNW** knowledge.

| Script | Event | Rules |
|---|---|---|
| `user_prompt_submit.py` | UserPromptSubmit | S1 secret in prompt (SEC/P1) |
| `pre_tool_use.py` | PreToolUse | S2 bash guard (DST/OUT P1–P2, SEC P1) · S3 secret + guard paths for file tools, Grep and shell write targets (P0, fails closed) · S4 commit scan incl. `add && commit`, `-a`, pathspecs (SEC/P1) · project rules |
| `post_tool_use.py` | PostToolUse | S6 output redaction (SEC/P1) · W2 wiki page checks (KNW/P3) · commit nudge when HEAD moves (KNW/P3) |
| `stop.py` | Stop | W3 fallback wiki nudge once per session, from git changes since session start; unindexed-page reminder (KNW/P3) |
| `session_start.py` | SessionStart | W1 status injection (KNW/P3) · git snapshot for change tracking · tool hints · allowlist change detection |
| `config_change.py` | ConfigChange | S5 settings audit (GRD/P4) |
| `_policy.py` | — | classes, secret patterns, session state, audit log, evolution events |

**Autonomous sessions** (`bypassPermissions`, `dontAsk`, `auto`, or `AGENT_AUTONOMOUS=1`) turn
every P2 confirm into a P1 block. For long unattended runs, also start Claude with the strict
sandbox profile: `claude --settings .claude/sandbox-autonomous.json` (needs bubblewrap; on Ubuntu
24.04+ a one-time AppArmor profile, see the Claude Code sandboxing docs).

**Switches** (set in `.claude/settings.local.json` → `env`):
`SECURITY_HOOKS=0` turns off SEC/DST/OUT P1–P4 · `ENG_WIKI_HOOKS=0` turns off KNW ·
`CLAUDE_HOOK_GUARD=1` silences KNW for headless jobs · `DEV_ENV_EVOLUTION=0` stops evolution
events for this project. **Nothing turns off P0.**

**Project rules**: `.claude/project-rules.json` may add Bash rules of class P1–P3 (tighten only):
`{"rules": [{"id": "deploy", "domain": "OUT", "class": "P2", "pattern": "\\bmake deploy\\b", "reason": "Deploys to prod"}]}`

**Guard files** (P0 for writes): `.claude/hooks/**`, `.claude/settings*.json` (project and `~/.claude/`),
`.claude/sandbox*.json`, `.mcp.json`, `.pre-commit-config.yaml`; running `apply_user_settings.py` counts as a write.

**Evolution events** are written only when evolution mode is on *and* the project is registered
in the evolution repo's `projects.md` (`evolve setup`).

**Logs**: `${XDG_STATE_HOME:-~/.local/state}/dev-env-hooks/audit.jsonl` (values redacted).

**Tests**: `uv run --with pytest pytest .claude/hooks/tests -q`

Hooks are tripwires, not a security boundary: `bash -c`, `python -c` or encoding gets around
regex guards. The deny rules in `settings.json`, the gitleaks pre-commit hook, and the sandbox
profile are the other layers.
