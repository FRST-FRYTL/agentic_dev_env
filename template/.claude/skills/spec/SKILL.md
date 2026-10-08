---
name: spec
description: Use when starting a project or feature, when the user describes something to build, or when a requirement is vague or disputed. Produces specs/<feature>.md with testable requirements, explicit scope, and a runnable verify step. Skip for changes that fit in one sentence.
argument-hint: "[feature or idea]"
---

# spec — turn intent into a checkable contract

A spec is what the build is checked against. It is worth writing when the work is bigger than one
sentence, and only as long as it needs to be: requirements, scope, and a way to prove it works.
Long specs cost more to review than the code they describe, so aim for under ~120 lines.

## 1. Gather context (read, don't ask)
- `eng-wiki/status.md`, `eng-wiki/index.md` (open only pages whose "read when" matches), existing
  `specs/`, and the user's notes or `$ARGUMENTS`.
- If a spec for this feature exists, update it instead of writing a new one.

## 2. Interview — one question at a time
Ask only what you cannot infer. Prefer multiple choice with a recommended option
(AskUserQuestion when available). Usually 3–7 questions cover it:
goal and user · in/out of scope · inputs and outputs · constraints (stack, performance, security,
data) · what "done" looks like and how to check it.

**No one to ask** (headless run, autonomous loop, or the user said "just decide"): do not stall.
Make the smallest reasonable assumption for each gap and list it under *Assumptions* so a human
can overturn it later.

## 3. Write `specs/<kebab-slug>.md`

```markdown
---
id: specs/<slug>
status: draft | agreed | done
created: YYYY-MM-DD
updated: YYYY-MM-DD
---
# <Feature>

## Goal
One paragraph: who needs what, and why.

## Requirements
- R1 <observable behaviour, testable>
- R2 …

## Out of scope
- …

## Assumptions
- A1 <assumption made without the user; overturn here>   (omit section if none)

## Open questions
- Q1 …   (omit if none)

## Verify
Exact commands that prove R1…Rn, copy-pasteable from a fresh shell: `uv run pytest -q` plus one
end-to-end command and its expected output. If a check needs a fixture (a local server, sample
files), the command starts it, or the check lives inside a test.

## Tasks
- [ ] T1 … (small, ordered; each ends in something runnable)
```

Rules: every requirement is observable from outside; every requirement is covered by Verify;
tasks reference requirements (`T2 (R1, R3)`). Status: `draft` while open questions remain,
`agreed` once the user (or the stated assumptions) settle them, `done` when Verify passes.

## 4. Self-check before handing over
- Could a stranger build it from this without asking? Could they tell when it is done?
- Anything here that is a *how* (module layout, library choice)? Move it to the `architect` skill.
- Is anything specified that nobody asked for? Cut it.

## 5. Record
- Append to `eng-wiki/log.md`: `## [date] spec | <feature>` + one line with the spec path.
- Update `eng-wiki/status.md` → Focus / Next.
- Next step: `architect` (unless the design is obvious), then `stack-docs`, then `tailor` for a
  new project.
