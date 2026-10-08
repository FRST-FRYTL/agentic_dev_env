---
name: stack-docs
description: Use when a library or framework is added or upgraded, when eng-wiki/stack/sources.md lists libraries without pages, or when Claude got a library API wrong. Pulls version-matched docs into eng-wiki/stack/<lib>.md and keeps a one-line-per-library index in CLAUDE.md.
argument-hint: "[lib ...] [--force]"
---

# stack-docs — version-pinned docs for the stack, indexed where Claude always looks

Models know libraries from training data that may be a version behind. A short, version-matched
page per library, plus an index line in CLAUDE.md, fixes most API mistakes. The index matters:
an always-loaded pointer is used far more reliably than knowledge Claude has to remember to fetch.

## 1. Resolve the list
- Libraries: `$ARGUMENTS`, else every entry in `eng-wiki/stack/sources.md`.
- Versions: from the lockfile/manifest (`uv.lock`, `pyproject.toml`, `package.json`, …). Update
  the manifest line if the version differs (`- httpx@0.28.1: https://…`).
- Skip a library whose page `fetched:` date is under 24 h old and whose version matches, unless
  `--force`.
- Source preference: the project's `llms.txt` / `llms-full.txt` → official docs pages for the
  pinned version → the repo README. Add a found URL to the manifest.

## 2. Fetch in parallel
Start one subagent per library (Agent tool, a small fast model such as Haiku is enough), all in
one message. Brief each with: library, version, source URL(s), what this project uses it for (from
the spec/architecture), and the page format below. Each returns the page content; you write the
files. Without subagents, fetch sequentially with WebFetch.

## 3. Page format — `eng-wiki/stack/<lib>.md` (under ~200 lines)
```markdown
---
id: stack/<lib>
type: stack
status: active
version: <x.y.z>
source: <url>
fetched: YYYY-MM-DD
created: YYYY-MM-DD
updated: YYYY-MM-DD
confidence: high
sources: [<url>]
---
# <lib> <version>

## What we use it for
## Core API we use        (signatures + 1-line examples, only what the project touches)
## Gotchas / changed in this version
## Links                  (deeper pages for later)
```
Facts only from the fetched docs; mark anything inferred. No marketing, no tutorials.

## 4. Index
- CLAUDE.md, between `<!-- stack-docs:start -->` and `<!-- stack-docs:end -->`, one line per
  library: `- <lib> <version>: eng-wiki/stack/<lib>.md — read when: <task conditions>`.
  Replace the placeholder line. Never touch content outside the markers.
- `eng-wiki/index.md` → *Stack* section, same line format.
- `eng-wiki/log.md`: `## [date] stack | <libs>`.

## 5. When a version changes
Re-fetch, update `version`/`fetched`/`updated`, and add the breaking changes that matter to this
project under *Gotchas*. If code must change, say so to the user.
