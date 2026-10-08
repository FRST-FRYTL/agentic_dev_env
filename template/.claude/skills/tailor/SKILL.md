---
name: tailor
description: Use right after the first spec and architecture of a new project (op init - scaffold the app, fill CLAUDE.md commands, add project hook rules), or when a task has recurred about three times or Claude repeated a mistake (op skill - generate a small project-specific skill). Keeps the repo fitted to this application instead of generic.
argument-hint: "init | skill <need> | rules"
---

# tailor — fit the repo to this application

The template ships a small generic core. Everything project-specific — scaffold, commands, extra
skills, extra hook rules — is generated here, when a real need exists, and kept small. Generated
context that nobody needs makes agents worse, not better.

## init — scaffold after the first spec
1. Read the spec, `eng-wiki/concepts/architecture.md`, decisions, and stack pages.
2. Confirm the stack (ask if unclear; default suggestion: Python + uv). Scaffold the minimum that
   runs: for Python/uv → `uv init --package <name>` (or the layout the architecture names),
   dev deps `pytest` and `ruff`, one smoke test, `uv sync`, `uv run pytest -q` green. Keep the
   template's own files out of the project's linters and tests (Python: `[tool.ruff]
   extend-exclude = [".claude"]`, pytest `testpaths = ["tests"]`).
   For other stacks use their standard init tool, same rule: smallest runnable skeleton + 1 test.
3. Fill CLAUDE.md between `<!-- tailor:commands:start -->` and `<!-- tailor:commands:end -->`:
   install, test, lint, run, the spec's verify command. Keep the hook-test line. Add only rules
   Claude would otherwise get wrong (non-default conventions, gotchas). For each line ask:
   would removing it cause a mistake? If not, leave it out.
4. Project hook rules (`.claude/project-rules.json`, optional): commands this project must
   confirm or block, e.g. a deploy or a migration (`domain` OUT/DST/SEC/KNW, `class` P1–P3,
   `pattern` regex). The file can only tighten; P0 is reserved for the template.
5. Secret scan for your own commits: if this is a git repo and `uvx` exists, suggest
   `uvx pre-commit install` (the config is a guard file: you may run it, not edit it).
6. Record the stack/scaffold decision (ADR via the `wiki` skill, op record), update status,
   commit if the user wants commits.

## skill — generate a project skill only when it has earned it
Trigger: the same multi-step task done ~3 times, or Claude made the same mistake twice.
1. Fetch the current skill docs first (WebFetch `https://code.claude.com/docs/en/skills.md`):
   frontmatter fields change between Claude Code versions.
2. Write `.claude/skills/<name>/SKILL.md`: `description` says **when** to use it (trigger
   conditions), not a summary of its steps. Body under ~120 lines, explains *why* rather than
   stacking MUSTs, deterministic steps as scripts next to it.
3. Write `.claude/skills/<name>/evals.md`: 2–3 realistic prompts with the expected behaviour.
   Run one prompt with and one without the skill (subagents) when feasible; keep the skill only
   if it changes the outcome.
4. If the skill looks useful beyond this project, report it to evolution mode:
   `python3 .claude/hooks/_policy.py event skill_generated name=<name> generic=yes`
   (no-op when evolution mode is off).
5. Log it (`eng-wiki/log.md`) and mention it in CLAUDE.md only if Claude would miss it otherwise.

## rules — review project hook rules
Read the audit log (`~/.local/state/dev-env-hooks/audit.jsonl`, this project's lines): repeated
blocks of the same rule suggest a false positive (tell the user; the allowlist and hooks are guard
files they edit themselves); risky commands that passed suggest a missing project rule.
