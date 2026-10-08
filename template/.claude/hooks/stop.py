#!/usr/bin/env python3
"""Stop: W3 · KNW/P3 · fallback wiki nudge, once per session.

Fires only if code changed, the wiki did not, and no commit nudge was given (the commit nudge in
post_tool_use.py is the primary, free one). Never blocks; loop-guarded.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _policy as P  # noqa: E402

DECLINE = "wiki: nothing to record"


def main() -> None:
    data = P.read_input()
    if data.get("agent_id") or not P.domain_enabled("KNW", "P3"):
        return
    with P.session_state(data) as st:
        if DECLINE in (data.get("last_assistant_message") or "") and not st.get("decline_logged"):
            st["decline_logged"] = True
            P.evolution_event("wiki_nudge_declined", {}, data)
        if data.get("stop_hook_active"):
            return
        due = (st.get("code_touched") and not st.get("wiki_touched")
               and not st.get("stop_nudged") and not st.get("commit_nudges"))
        if due:
            st["stop_nudged"] = True
    if due:
        P.emit({"hookSpecificOutput": {"hookEventName": "Stop", "additionalContext": (
            "W3: files changed this session but eng-wiki/ was not updated. If a decision, insight, or "
            "change of focus happened, record it with the wiki skill (record / status). If not, reply "
            f"exactly '{DECLINE}'.")}})


if __name__ == "__main__":
    P.run(main, hook="stop")
