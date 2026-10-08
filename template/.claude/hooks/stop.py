#!/usr/bin/env python3
"""Stop: W3 · KNW/P3 · fallback wiki nudge, at most once per session.

Changes are read from git against the snapshot taken at session start, so files written through
Bash count too. Fires only if real code changed (>= MIN_LINES), the wiki did not, and no commit
nudge was given (the commit nudge is the primary, free one). Also reminds once about new wiki
pages missing from index.md. Never blocks; loop-guarded.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _policy as P  # noqa: E402

DECLINE = "wiki: nothing to record"
DECLINE_LINE = re.compile(rf"^\s*{re.escape(DECLINE)}\.?\s*$", re.I | re.M)
MIN_LINES = 15
WIKI_ROOT_FILES = {"eng-wiki/index.md", "eng-wiki/log.md", "eng-wiki/status.md", "eng-wiki/stack/sources.md"}


def unindexed(root: Path, wiki_paths: list[str]) -> list[str]:
    index = root / "eng-wiki" / "index.md"
    text = index.read_text(errors="replace") if index.exists() else ""
    return [p for p in wiki_paths if p.endswith(".md") and p not in WIKI_ROOT_FILES
            and (root / p).exists() and p.removeprefix("eng-wiki/") not in text]


def main() -> None:
    data = P.read_input()
    if data.get("agent_id") or not P.domain_enabled("KNW", "P3"):
        return
    root = P.project_dir(data)
    notes: list[str] = []
    with P.session_state(data) as st:
        if DECLINE_LINE.search(data.get("last_assistant_message") or "") and not st.get("decline_logged"):
            st["decline_logged"] = True
            P.evolution_event("wiki_nudge_declined", {}, data)
        if data.get("stop_hook_active"):
            return
        snap = st.get("snap")
        if snap is None:
            return  # no baseline (session started before the hooks existed); stay quiet
        code, wiki, lines = P.changed_since(root, snap)
        if (code and lines >= MIN_LINES and not wiki and not st.get("wiki_touched")
                and not st.get("stop_nudged") and not st.get("commit_nudges")):
            st["stop_nudged"] = True
            notes.append("W3: code changed this session but eng-wiki/ was not updated. If a decision, insight, or "
                         "change of focus happened, record it with the wiki skill (record / status). If not, repeat "
                         f"your previous final answer in full and add the line '{DECLINE}' at its end. Keep the answer itself.")
        status = root / "eng-wiki" / "status.md"
        if "eng-wiki/status.md" in wiki and status.exists() and not status.read_text(errors="replace").startswith("---") \
                and not st.get("status_fm_nudged"):
            st["status_fm_nudged"] = True
            notes.append("W3: eng-wiki/status.md lost its YAML frontmatter (id: status, type: status, status: active, "
                         "updated: <date>). Restore it.")
        missing = unindexed(root, wiki)
        if missing and not st.get("index_nudged"):
            st["index_nudged"] = True
            notes.append("W3: these wiki pages are not listed in eng-wiki/index.md: " + ", ".join(missing[:8])
                         + ". Add one line each with 'read when:'.")
    if notes:
        P.emit({"hookSpecificOutput": {"hookEventName": "Stop", "additionalContext": "\n".join(notes)}})


if __name__ == "__main__":
    P.run(main, hook="stop")
