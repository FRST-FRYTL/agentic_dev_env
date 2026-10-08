# Evolution repo skeleton

Create these files on `evolve setup`.

## README.md
```markdown
# dev-env-evolution

Signals and improvement candidates for the agentic_dev_env template, collected from every project
on this machine. Written by hooks (events/) and the `evolve` skill (candidates/). Generic content
only: no client names, project code, paths, data, or secrets.
```

## index.md
```markdown
# Candidates

| id | kind | target | status | evidence |
|---|---|---|---|---|
```

## projects.md
```markdown
# Registered projects

| slug | registered | evolution |
|---|---|---|
```

## platform/README.md
```markdown
# Platform knowledge

Facts about the machines and runtimes projects run on (drivers, memory limits, serving stacks),
shared across projects. One topic per file, same frontmatter as eng-wiki pages.
```

## events/.gitkeep, candidates/.gitkeep (empty)

## Candidate template — candidates/<YYYY-MM-DD>-<slug>.md
```markdown
---
id: <YYYY-MM-DD>-<slug>
kind: friction | improvement | new-skill | hook-false-positive | missing-rule | hook-bug
target: hook/<rule-id> | skill/<name> | wiki-schema | claude-md | copier | template
status: open | accepted | rejected | promoted
created: YYYY-MM-DD
updated: YYYY-MM-DD
projects: [<slug>, …]
evidence: [events/<slug>/<YYYY-MM>.jsonl, …]
---
# <One-sentence improvement>

## Situation
What happened (generic terms).

## Proposal
What to change in the template.

## Decision
(filled on triage: accepted/rejected + reason; promoted → template commit)
```
