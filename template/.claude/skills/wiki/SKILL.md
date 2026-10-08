---
name: wiki
description: Use after any engineering decision or insight, when a session that changed things is ending, when asked "what did we decide/learn about X", when adding a doc or URL to project knowledge, or to health-check eng-wiki/. Operations - record, status, query, ingest, lint.
argument-hint: "record|status|query|ingest|lint [details]"
---

# wiki — keep eng-wiki/ the project's memory

`eng-wiki/` is a small, LLM-maintained wiki (Karpathy's "LLM wiki" pattern): sources stay where
they are (code, specs, URLs), the wiki compiles what was decided and learned so nobody re-derives
it. It only works if it stays small, current, and has exactly one page per fact.

## Layout
```
eng-wiki/
  index.md      catalog: one line per page with "read when: …"   (read first)
  log.md        append-only chronicle: "## [YYYY-MM-DD] <type> | <title>"
  status.md     handover: Focus · Done · Next · Blockers (injected at session start)
  decisions/    NNNN-slug.md ADRs (written by architect or record)
  learnings/    slug.md: gotchas, findings, benchmark results   (create on first use)
  concepts/     slug.md: durable explanations, architecture     (create on first use)
  stack/        sources.md + <lib>.md (written by stack-docs)
```

## Page frontmatter (every page except index/log)
```yaml
---
id: <folder>/<slug>                    # path without .md
type: decision | learning | concept | stack | status
status: active | superseded            # decisions: proposed | accepted | superseded
created: YYYY-MM-DD
updated: YYYY-MM-DD
confidence: high | medium | low        # high = tested here; low = single external claim
sources: [specs/x.md, src/y.py, commit:abc1234, https://…]
supersedes: []                         # optional
---
```

## Operations (route from `$ARGUMENTS`; infer if empty: a choice was made → record, a question → query)

### record — after a decision or insight
1. Decision (a choice with alternatives) → ADR via the template in the `architect` skill.
   Insight (gotcha, constraint, result that changed our mind) → `learnings/<slug>.md`:
   frontmatter + *What happened* · *Why* · *Rule* (what to do from now on), under ~30 lines.
2. Search `index.md` first. If a page already covers it, **update that page** instead.
   If the new fact overrides an old one: new page `supersedes: [old-id]`, old page
   `status: superseded` + `superseded_by:`. Never delete.
3. Add the index line: `- [Title](path) — read when: <task conditions>`.
4. Append to `log.md`: `## [date] decision|insight | <title>` + one line.
5. Focus changed? Update `status.md`.

### status — at the end of a session that changed things
Rewrite `status.md` (keep it under ~40 lines, it is injected every session):
Focus (one sentence) · Done (this session, newest first, max ~8 lines) · Next (ordered) ·
Blockers. Move older "Done" lines to `log.md` if they aren't there yet. Bump `updated`.

### query — "what did we decide / learn about X"
Read `index.md`, open matching pages, follow their links. Answer with page citations
(`eng-wiki/decisions/0003-…`). Flag `low` confidence or `updated` older than 90 days. If the
answer took real synthesis, file it as a `concepts/` page and log a `query` entry.

### ingest — add a source (doc, URL, spec) to the knowledge
Read it once; create or update the few `concepts/` pages it affects; cite it in `sources:`;
update index + log (`ingest`). Library docs go through the `stack-docs` skill instead.

### lint — health check
Run `python3 .claude/skills/wiki/scripts/wiki_lint.py` (deterministic: frontmatter, index
coverage, broken links, supersede consistency, stale pages). Then check by reading what a script
can't: contradictions between pages, duplicated facts, status.md drift from reality. Fix the safe
items, list the rest for the user, log a `lint` entry.

## Rules
- One fact, one page; link instead of copying. Specs and code are sources, not wiki content.
- Never write secret values, client data, or personal data into the wiki.
- Don't invent confidence or sources. Unverified → `confidence: low` and say so.
- The wiki is for this project's engineering. Ideas for improving the dev environment itself go
  to the `evolve` skill (`evolve note`).
