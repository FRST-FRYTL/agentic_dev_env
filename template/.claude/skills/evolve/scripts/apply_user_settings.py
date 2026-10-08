#!/usr/bin/env python3
"""Turn evolution mode on or off in ~/.claude/settings.json. Run it yourself (it edits a guard file):

    ! python3 .claude/skills/evolve/scripts/apply_user_settings.py ~/Projects/dev-env-evolution
    ! python3 .claude/skills/evolve/scripts/apply_user_settings.py --off

Sets env.DEV_ENV_EVOLUTION_HOME and adds the path to permissions.additionalDirectories.
The first run keeps the original as settings.json.orig; every run also writes a timestamped backup.
"""
from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

SETTINGS = Path.home() / ".claude" / "settings.json"


def fail(msg: str) -> int:
    print(f"error: {msg} (nothing changed)")
    return 1


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__)
        return 2
    off = argv[0] == "--off"
    path = "" if off else str(Path(argv[0]).expanduser().resolve())
    if not off and not Path(path).is_dir():
        return fail(f"not a directory: {path}")
    try:
        data = json.loads(SETTINGS.read_text()) if SETTINGS.exists() else {}
    except json.JSONDecodeError as exc:
        return fail(f"{SETTINGS} is not valid JSON ({exc})")
    if not isinstance(data, dict):
        return fail(f"{SETTINGS} is not a JSON object")
    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    dirs = perms.get("additionalDirectories") if isinstance(perms.get("additionalDirectories"), list) else []
    if off:
        old = env.pop("DEV_ENV_EVOLUTION_HOME", None)
        if old in dirs:
            dirs.remove(old)
    else:
        env["DEV_ENV_EVOLUTION_HOME"] = path
        if path not in dirs:
            dirs.append(path)
    data["env"], perms["additionalDirectories"], data["permissions"] = env, dirs, perms
    if SETTINGS.exists():
        orig = SETTINGS.with_suffix(".json.orig")
        if not orig.exists():
            shutil.copy2(SETTINGS, orig)
        shutil.copy2(SETTINGS, SETTINGS.with_suffix(f".json.bak-{time.strftime('%Y%m%d-%H%M%S')}"))
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps(data, indent=2) + "\n")
    print("evolution mode off" if off else f"evolution mode on: {path} (takes effect in new sessions)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
