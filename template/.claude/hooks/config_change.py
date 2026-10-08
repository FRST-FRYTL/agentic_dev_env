#!/usr/bin/env python3
"""ConfigChange: S5 · GRD/P4 · audit settings changes made during a session (log only)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _policy as P  # noqa: E402


def main() -> None:
    data = P.read_input()
    P.audit({"hook": "config_change", "rule": "S5-config-audit", "domain": "GRD", "class": "P4",
             "decision": "log", "session": data.get("session_id"),
             "detail": f"{data.get('source')} {data.get('file_path', '')}"})


if __name__ == "__main__":
    P.run(main, hook="config_change")
