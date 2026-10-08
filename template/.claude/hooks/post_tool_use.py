#!/usr/bin/env python3
"""PostToolUse: S6 output redaction · W2 wiki tracking + checks · commit nudge · P2 approvals.

All fail open; nothing here blocks. See _policy.py for classes and switches.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _policy as P  # noqa: E402

REDACT_TOOLS = {"Bash", "Read", "Grep"}
EDIT_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
MAX_SCAN_BYTES = 1_000_000
MAX_COMMIT_NUDGES = 3
WIKI = "eng-wiki"
WIKI_ROOT_FILES = {"index.md", "log.md", "status.md"}
COMMIT_DONE = re.compile(r"^\[[^\]]+ [0-9a-f]{7,}\]", re.MULTILINE)


def redact_output(data: dict) -> tuple[dict | None, list[str]]:
    resp = data.get("tool_response")
    if resp is None or len(json.dumps(resp)) > MAX_SCAN_BYTES:
        return None, []
    new, rules = P.deep_redact(resp)
    return (new, rules) if rules else (None, [])


def rel_to(root: Path, raw: str) -> Path | None:
    p = Path(raw)
    p = (p if p.is_absolute() else root / p).resolve()
    try:
        return p.relative_to(root)
    except ValueError:
        return None


def wiki_checks(root: Path, rel: Path, data: dict) -> list[str]:
    """Light W2 checks on an edited eng-wiki file. Returns warnings."""
    warn: list[str] = []
    path = root / rel
    name = rel.name
    sub = rel.parts[1] if len(rel.parts) > 2 else ""
    if name == "log.md" and len(rel.parts) == 2:
        ti = data.get("tool_input") or {}
        old, new = ti.get("old_string"), ti.get("new_string")
        if old and new is not None and not new.startswith(old):
            warn.append("eng-wiki/log.md is append-only: add new lines at the end, don't rewrite entries.")
        return warn
    if name in WIKI_ROOT_FILES or not name.endswith(".md") or not path.exists():
        return warn
    if sub == "stack" and name == "sources.md":
        return warn
    text = path.read_text(errors="replace")
    if not text.startswith("---"):
        warn.append(f"{rel} has no frontmatter (id, type, status, created, updated, confidence, sources).")
    else:
        head = text.split("---", 2)[1] if text.count("---") >= 2 else ""
        missing = [k for k in ("id:", "type:", "status:") if k not in head]
        if missing:
            warn.append(f"{rel} frontmatter lacks {', '.join(m.rstrip(':') for m in missing)}.")
    index = root / WIKI / "index.md"
    link = rel.relative_to(WIKI).as_posix()
    if index.exists() and link not in index.read_text(errors="replace"):
        warn.append(f"{rel} is not listed in eng-wiki/index.md (add it with a 'read when:' condition).")
    return warn


def main() -> None:
    data = P.read_input()
    tool = data.get("tool_name", "")
    ti = data.get("tool_input") or {}
    root = P.project_dir(data)
    out: dict = {}
    notes: list[str] = []

    # P2 approvals: a PostToolUse for a tool_use_id we asked about means the user said yes.
    tuid = data.get("tool_use_id")
    if tuid:
        with P.session_state(data) as st:
            rule = st.get("pending_asks", {}).pop(tuid, None)
        if rule:
            P.evolution_event("p2_approved", {"rule": rule, "tool": tool}, data)

    # S6 · SEC/P1 · redact secrets in output before Claude reads it.
    if tool in REDACT_TOOLS and P.domain_enabled("SEC", "P1"):
        new, rules = redact_output(data)
        if new is not None:
            out["updatedToolOutput"] = new
            notes.append(f"S6 redacted {len(rules)} secret(s) ({', '.join(sorted(set(rules)))}) from this output. "
                         "Refer to secrets by env var name; never copy values into files.")
            P.audit({"hook": "post_tool_use", "rule": "S6-redact", "domain": "SEC", "class": "P1",
                     "decision": "redact", "session": data.get("session_id"), "detail": ",".join(rules)})
            P.evolution_event("s6_redacted", {"rules": ",".join(sorted(set(rules))), "tool": tool}, data)

    knw = P.domain_enabled("KNW", "P3")

    # W2 · KNW/P3 · track what changed; check wiki edits.
    if tool in EDIT_TOOLS and knw:
        raw = ti.get("file_path") or ti.get("notebook_path") or ""
        rel = rel_to(root, raw) if raw else None
        if rel is not None:
            in_wiki = rel.parts[:1] == (WIKI,)
            with P.session_state(data) as st:
                st["wiki_touched" if in_wiki else "code_touched"] = True
            if in_wiki:
                warns = wiki_checks(root, rel, data)
                if warns:
                    notes.append("W2 wiki check: " + " ".join(warns))
                    P.evolution_event("wiki_check_failed", {"file": rel.as_posix(), "warnings": len(warns)}, data)

    # Commit nudge (D9) · KNW/P3 · free: rides on the commit's tool result, no extra turn.
    if tool == "Bash" and knw and re.search(r"\bgit\b.*\bcommit\b", ti.get("command", "")):
        resp = data.get("tool_response") or {}
        stdout = resp.get("stdout", "") if isinstance(resp, dict) else str(resp)
        if COMMIT_DONE.search(stdout):
            with P.session_state(data) as st:
                due = st.get("code_touched") and not st.get("wiki_touched") and st.get("commit_nudges", 0) < MAX_COMMIT_NUDGES
                if due:
                    st["commit_nudges"] = st.get("commit_nudges", 0) + 1
                    st["code_touched"] = False
            if due:
                notes.append("Commit done. If this work settled a decision or produced an insight, record it now "
                             "with the wiki skill (record), and update eng-wiki/status.md if the focus changed. "
                             "If there is nothing to record, say 'wiki: nothing to record' and continue.")

    if notes:
        out["additionalContext"] = "\n".join(notes)
    if out:
        P.emit({"hookSpecificOutput": {"hookEventName": "PostToolUse", **out}})


if __name__ == "__main__":
    P.run(main, hook="post_tool_use")
