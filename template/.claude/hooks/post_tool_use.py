#!/usr/bin/env python3
"""PostToolUse: S6 output redaction · W2 wiki page checks · commit nudge · P2 approvals.

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
MAX_SCAN_BYTES = 10_000_000
MAX_COMMIT_NUDGES = 3
WIKI = "eng-wiki"
WIKI_ROOT_FILES = {"index.md", "log.md", "status.md"}
DECLINE = "wiki: nothing to record"


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


def wiki_checks(root: Path, rel: Path) -> list[str]:
    """Light W2 checks on an edited eng-wiki file. Index coverage is checked at Stop, after the
    skill had a chance to add the index line."""
    warn: list[str] = []
    path = root / rel
    if rel.as_posix() == f"{WIKI}/log.md":
        old = P.git_out(root, "show", f"HEAD:{WIKI}/log.md")
        if old and path.exists() and not path.read_text(errors="replace").startswith(old.rstrip("\n")):
            warn.append("eng-wiki/log.md is append-only: committed entries changed. Restore them and add new "
                        "lines at the end.")
        return warn
    if rel.name in WIKI_ROOT_FILES or rel.suffix != ".md" or not path.exists() or rel.as_posix() == f"{WIKI}/stack/sources.md":
        return warn
    text = path.read_text(errors="replace")
    if not text.startswith("---") or text.count("---") < 2:
        return [f"{rel} has no frontmatter (id, type, status, created, updated, confidence, sources)."]
    head = text.split("---", 2)[1]
    missing = [k for k in ("id", "type", "status") if not re.search(rf"^{k}:\s*\S", head, re.M)]
    if missing:
        warn.append(f"{rel} frontmatter lacks {', '.join(missing)}.")
    expected = rel.relative_to(WIKI).with_suffix("").as_posix()
    m = re.search(r"^id:\s*(\S+)", head, re.M)
    if m and m.group(1) != expected:
        warn.append(f"{rel}: id should be '{expected}' (path without .md), not '{m.group(1)}'.")
    return warn


def commit_nudge(data: dict, root: Path) -> str | None:
    """After a successful commit (HEAD moved): nudge if code changed and the wiki did not."""
    head = P.git_out(root, "rev-parse", "HEAD").strip()
    with P.session_state(data) as st:
        last = st.get("last_head")
        if not head or head == last:
            return None
        st["last_head"] = head
        if last:
            code, wiki = P.classify(P.git_out(root, "diff", "--name-only", f"{last}..{head}").split())
        else:  # no snapshot (e.g. resumed session): fall back to the last commit
            code, wiki = P.classify(P.git_out(root, "show", "--name-only", "--format=", head).split())
        snap = st.get("snap")
        if snap:  # wiki edits made through Bash but not committed yet also count
            wiki = wiki or P.classify(P.newly_changed(root, snap))[1]
        if not code or wiki or st.get("wiki_touched") or st.get("commit_nudges", 0) >= MAX_COMMIT_NUDGES:
            return None
        st["commit_nudges"] = st.get("commit_nudges", 0) + 1
    return ("Commit done. If this work settled a decision or produced an insight, record it now with the wiki "
            "skill (record), and update eng-wiki/status.md if the focus changed. If there is nothing to record, "
            f"add the line '{DECLINE}' at the end of your answer and carry on.")


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
            rule = st.get("pending_asks", {}).pop(tuid, None) if st.get("pending_asks") else None
        if rule:
            P.evolution_event("p2_approved", {"rule": rule, "tool": tool, "cmd_head": P.cmd_head(ti.get("command", ""))}, data)

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

    # W2 · KNW/P3 · check wiki pages as they are written (Edit/Write tools).
    if tool in EDIT_TOOLS and knw:
        raw = ti.get("file_path") or ti.get("notebook_path") or ""
        rel = rel_to(root, raw) if raw else None
        if rel is not None:
            in_wiki = rel.parts[:1] == (WIKI,)
            if in_wiki:
                with P.session_state(data) as st:
                    st["wiki_touched"] = True
                warns = wiki_checks(root, rel)
                if warns:
                    notes.append("W2 wiki check: " + " ".join(warns))
                    P.evolution_event("wiki_check_failed", {"file": rel.as_posix(), "warnings": len(warns)}, data)

    # Commit nudge (D9) · KNW/P3 · rides on the commit's tool result, so it costs no extra turn.
    if tool == "Bash" and knw and re.search(r"\bgit\b.*\bcommit\b", ti.get("command", "")):
        note = commit_nudge(data, root)
        if note:
            notes.append(note)

    if notes:
        out["additionalContext"] = "\n".join(notes)
    if out:
        P.emit({"hookSpecificOutput": {"hookEventName": "PostToolUse", **out}})


if __name__ == "__main__":
    P.run(main, hook="post_tool_use")
