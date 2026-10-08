#!/usr/bin/env python3
"""Turn evolution mode on in ~/.claude/settings.json. Run it yourself (it edits a guard file):

    ! python3 .claude/skills/evolve/scripts/apply_user_settings.py ~/Projects/dev-env-evolution
    ! python3 .claude/skills/evolve/scripts/apply_user_settings.py --off

Sets env.DEV_ENV_EVOLUTION_HOME and adds the path to permissions.additionalDirectories.
A backup is written next to the file first.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

SETTINGS = Path.home() / ".claude" / "settings.json"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    data = json.loads(SETTINGS.read_text()) if SETTINGS.exists() else {}
    if SETTINGS.exists():
        shutil.copy2(SETTINGS, SETTINGS.with_suffix(".json.bak"))
    env = data.setdefault("env", {})
    dirs = data.setdefault("permissions", {}).setdefault("additionalDirectories", [])
    if argv[0] == "--off":
        old = env.pop("DEV_ENV_EVOLUTION_HOME", None)
        if old in dirs:
            dirs.remove(old)
        print("evolution mode off")
    else:
        path = str(Path(argv[0]).expanduser().resolve())
        if not Path(path).is_dir():
            print(f"not a directory: {path}")
            return 1
        env["DEV_ENV_EVOLUTION_HOME"] = path
        if path not in dirs:
            dirs.append(path)
        print(f"evolution mode on: {path} (takes effect in new sessions)")
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps(data, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
