#!/usr/bin/env python3
"""UserPromptSubmit: S1 · SEC/P1 · block prompts that contain a secret.

A block keeps the prompt from reaching the model, but the text can still sit in the local
transcript and prompt history, so the message tells the user to rotate the key.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _policy as P  # noqa: E402


def main() -> None:
    data = P.read_input()
    if not P.domain_enabled("SEC", "P1"):
        return
    hits = P.find_secrets(data.get("prompt", ""))
    if not hits:
        return
    rules = sorted({rid for rid, _ in hits})
    P.audit({"hook": "user_prompt_submit", "rule": "S1-prompt-secret", "domain": "SEC", "class": "P1",
             "decision": "block", "session": data.get("session_id"), "detail": ",".join(rules)})
    P.evolution_event("p1_blocked", {"rule": "S1-prompt-secret", "class": "P1", "kinds": ",".join(rules)}, data)
    P.emit({
        "decision": "block",
        "reason": (f"S1 blocked this prompt: it contains what looks like a secret ({', '.join(rules)}). "
                   "It was not sent to the model. Treat the key as exposed and rotate it if it is real "
                   "(the text may remain in local transcripts). Refer to secrets by env var name instead. "
                   "False positive? Add 'gitleaks:allow' to the line or its fingerprint to "
                   ".claude/hooks/secret_allowlist.txt."),
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True},
    })


if __name__ == "__main__":
    P.run(main, hook="user_prompt_submit")
