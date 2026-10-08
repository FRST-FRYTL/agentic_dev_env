#!/usr/bin/env python3
"""SessionStart (startup|clear|compact): W1 · KNW/P3 · inject eng-wiki/status.md.

Also: one-line tool hints, evolution-mode status, and allowlist change detection.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _policy as P  # noqa: E402

MAX_STATUS_CHARS = 3000


def git(root: Path, *args: str) -> str:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def staleness(root: Path, rel: str) -> str:
    last = git(root, "log", "-1", "--format=%H %ct", "--", rel)
    if not last:
        return "status.md is not committed yet"
    sha, ts = last.split()
    days = int((time.time() - int(ts)) // 86400)
    since = git(root, "rev-list", "--count", f"{sha}..HEAD") or "0"
    return f"status.md last committed {days} d ago; {since} commit(s) since"


def allowlist_check(data: dict) -> None:
    f = P.HOOKS_DIR / "secret_allowlist.txt"
    digest = hashlib.sha256(f.read_bytes()).hexdigest() if f.exists() else ""
    store = P.state_dir() / "projects"
    store.mkdir(exist_ok=True)
    rec = store / f"{P.project_slug(data)}.json"
    old = json.loads(rec.read_text()).get("allowlist") if rec.exists() else None
    if old is not None and old != digest:
        P.evolution_event("allowlist_changed", {"file": "secret_allowlist.txt"}, data)
    rec.write_text(json.dumps({"allowlist": digest}))


def main() -> None:
    data = P.read_input()
    root = P.project_dir(data)
    lines: list[str] = []

    if P.domain_enabled("KNW", "P3"):
        status = root / "eng-wiki" / "status.md"
        if status.exists():
            text = status.read_text(errors="replace")
            if len(text) > MAX_STATUS_CHARS:
                text = text[:MAX_STATUS_CHARS] + "\n… (truncated: trim status.md with the wiki skill, op status)"
            lines += ["## eng-wiki/status.md (injected by hook W1)", text.strip(), "",
                      f"({staleness(root, 'eng-wiki/status.md')}. Catalog: eng-wiki/index.md — open pages only "
                      "when their 'read when' matches the task.)"]

    if not shutil.which("gitleaks"):
        lines.append("Note: gitleaks is not installed; the commit scan (S4) uses the built-in pattern set.")
    evo = P.evolution_home()
    if evo is not None:
        lines.append(f"Evolution mode is on: hook signals go to {evo}/events/{P.project_slug(data)}/.")

    try:
        allowlist_check(data)
    except (OSError, ValueError):
        pass

    if lines:
        P.emit({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "\n".join(lines)}})


if __name__ == "__main__":
    P.run(main, hook="session_start")
