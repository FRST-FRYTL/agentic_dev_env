#!/usr/bin/env python3
"""Summarise evolution events into clusters. Usage: evo_review.py <evolution repo>"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path


def main(home: Path) -> int:
    clusters: dict[tuple, dict] = defaultdict(lambda: {"count": 0, "projects": set(), "first": "", "last": ""})
    for f in sorted((home / "events").rglob("*.jsonl")):
        for line in f.read_text(errors="replace").splitlines():
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = (e.get("kind", "?"), e.get("rule") or e.get("hook") or e.get("name") or e.get("file") or "")
            c = clusters[key]
            c["count"] += 1
            c["projects"].add(e.get("project", "?"))
            ts = e.get("ts", "")
            c["first"] = min(c["first"] or ts, ts)
            c["last"] = max(c["last"], ts)
    print("## Event clusters (candidate when count >= 2 or projects >= 2)\n")
    print("| kind | subject | events | projects | first | last | candidate? |")
    print("|---|---|---|---|---|---|---|")
    for (kind, subject), c in sorted(clusters.items(), key=lambda kv: -kv[1]["count"]):
        ok = "yes" if c["count"] >= 2 or len(c["projects"]) >= 2 else "no"
        print(f"| {kind} | {subject} | {c['count']} | {', '.join(sorted(c['projects']))} | {c['first'][:10]} | {c['last'][:10]} | {ok} |")
    print("\n## Candidates\n")
    for f in sorted((home / "candidates").glob("*.md")):
        head = f.read_text(errors="replace").split("---")
        fm = head[1] if len(head) > 2 else ""
        status = re.search(r"^status:\s*(\S+)", fm, re.M)
        kind = re.search(r"^kind:\s*(\S+)", fm, re.M)
        print(f"- {f.stem} · {kind.group(1) if kind else '?'} · {status.group(1) if status else '?'}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1]).expanduser()))
