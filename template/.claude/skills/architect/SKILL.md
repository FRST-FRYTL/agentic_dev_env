---
name: architect
description: Use after a spec is agreed and before building, or when a change crosses module boundaries, adds a dependency, or reverses an earlier decision. Decides the structure, records each non-obvious choice as an ADR in eng-wiki/decisions/, and writes CONTRACTS.md when parts must stay stable for parallel work.
argument-hint: "[spec path]"
---

# architect — decide the how, once, in writing

The spec says *what*. This skill decides *how* and writes it down so later sessions don't
re-derive or silently reverse it. Record a decision only when someone could reasonably have
chosen differently; obvious choices need no ADR.

## 1. Read
The spec (`$ARGUMENTS` or the newest in `specs/`), `eng-wiki/index.md`, existing
`eng-wiki/decisions/`, and `eng-wiki/stack/` pages for libraries already chosen.

## 2. List the decisions this spec forces
Typical: module/package layout · data model and storage · key libraries · interfaces between
parts · error handling and failure modes · how verification is automated. For each, decide
whether it is non-obvious (→ ADR) or obvious (→ one line in the architecture page).

## 3. Write ADRs — `eng-wiki/decisions/NNNN-<slug>.md`
Next free number, zero-padded to 4. Keep each under ~40 lines.

```markdown
---
id: decisions/NNNN-<slug>
type: decision
status: proposed | accepted | superseded
created: YYYY-MM-DD
updated: YYYY-MM-DD
confidence: high | medium | low
sources: [specs/<slug>.md]
supersedes: []          # ids of decisions this replaces
---
# NNNN <Decision as a sentence>

## Context
Why a decision is needed (link the spec requirement: R2).

## Options
1. **<A>** — pro / con
2. **<B>** — pro / con

## Decision
<A>, because …

## Consequences
What gets easier, what gets harder, what would make us revisit.
```

Status `accepted` when the user agreed or the choice is low-risk; otherwise `proposed` and say so
in the hand-over. Reversing a decision: new ADR with `supersedes:`, set the old one to
`status: superseded` and add `superseded_by:` there. Never delete or rewrite an accepted ADR.

## 4. Architecture page — `eng-wiki/concepts/architecture.md`
One page per project, updated, not duplicated: a Mermaid diagram of modules and data flow, one
line per module (responsibility, owner file), and links to the ADRs. Full page frontmatter (see
the `wiki` skill) with `id: concepts/architecture`, `type: concept`.

## 5. CONTRACTS.md (only when needed)
Write a root `CONTRACTS.md` when two or more parts will be built in parallel or by different
agents: exact function/class signatures, data shapes, invariants, and error behaviour. A contract
changes only through a new ADR.

## 6. Hand off
- Add every library the design relies on to `eng-wiki/stack/sources.md` (`- name@version: url`;
  version `latest` if not pinned yet) for the `stack-docs` skill.
- Link the ADRs and architecture page from the spec (a short *Design* line under Goal).
- `eng-wiki/index.md`: one line per new page with `read when:`. `eng-wiki/log.md`: one
  `decision` entry per ADR. `eng-wiki/status.md`: update Next.
