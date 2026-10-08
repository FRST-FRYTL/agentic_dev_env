#!/usr/bin/env python3
"""Deterministic eng-wiki checks. Usage: python3 wiki_lint.py [eng-wiki dir]. Exit 1 on errors."""
from __future__ import annotations

import datetime as dt
import re
import sys
from pathlib import Path

REQUIRED = ("id", "type", "status")
LINK = re.compile(r"\]\(([^)#\s]+\.md)(?:#[^)]*)?\)")
STALE_DAYS = 90


def frontmatter(text: str) -> dict[str, str] | None:
    if not text.startswith("---"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    fm = {}
    for line in parts[1].splitlines():
        if ":" in line and not line.startswith((" ", "-")):
            k, v = line.split(":", 1)
            fm[k.strip()] = v.split("#")[0].strip()
    return fm


def main(root: Path) -> int:
    errors, warnings = [], []
    index = (root / "index.md").read_text() if (root / "index.md").exists() else ""
    pages = {p.relative_to(root).as_posix(): p for p in root.rglob("*.md")}
    ids: dict[str, str] = {}
    superseded_ids = set()
    for rel, p in sorted(pages.items()):
        text = p.read_text(errors="replace")
        for target in LINK.findall(text):
            if not target.startswith(("http:", "https:")) and not (p.parent / target).resolve().exists():
                errors.append(f"{rel}: broken link → {target}")
        if rel in ("index.md", "log.md") or rel.startswith("stack/sources"):
            continue
        fm = frontmatter(text)
        if fm is None:
            errors.append(f"{rel}: missing frontmatter")
            continue
        for k in REQUIRED:
            if not fm.get(k):
                errors.append(f"{rel}: frontmatter lacks '{k}'")
        if fm.get("id"):
            if fm["id"] in ids:
                errors.append(f"{rel}: duplicate id {fm['id']} (also {ids[fm['id']]})")
            ids[fm["id"]] = rel
        if fm.get("status") == "superseded":
            superseded_ids.add(fm.get("id", ""))
            if not fm.get("superseded_by"):
                errors.append(f"{rel}: superseded but no superseded_by")
        if rel != "status.md" and rel not in index:
            errors.append(f"{rel}: not listed in index.md")
        upd = fm.get("updated", "")
        try:
            age = (dt.date.today() - dt.date.fromisoformat(upd)).days
            if age > STALE_DAYS and fm.get("status") in ("active", "accepted"):
                warnings.append(f"{rel}: not updated for {age} days, re-confirm or supersede")
        except ValueError:
            warnings.append(f"{rel}: 'updated' is not an ISO date")
    for line in index.splitlines():
        if line.startswith("- [") and "read when" not in line:
            warnings.append(f"index.md: entry without 'read when': {line[:70]}")
    log = (root / "log.md").read_text() if (root / "log.md").exists() else ""
    bad = [l for l in log.splitlines() if l.startswith("## ") and not re.match(r"## \[\d{4}-\d{2}-\d{2}\] \w+ \| ", l)]
    warnings += [f"log.md: malformed heading: {l[:60]}" for l in bad]
    for e in errors:
        print(f"ERROR {e}")
    for w in warnings:
        print(f"WARN  {w}")
    print(f"{len(pages)} pages · {len(errors)} errors · {len(warnings)} warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "eng-wiki")))
