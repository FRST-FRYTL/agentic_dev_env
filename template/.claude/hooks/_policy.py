"""Shared policy for the dev-env hooks.

Every rule declares a domain (what it protects) and a class (how hard). The class, not the
script, decides the outcome, the failure mode, and whether a kill switch applies.

Domains: SEC secrets · DST destructive ops · OUT outward actions · GRD guardrails · KNW knowledge
Classes: P0 lock · P1 block · P2 confirm · P3 advise · P4 audit

P2 escalates to P1 in autonomous sessions (bypass/dontAsk/auto mode or AGENT_AUTONOMOUS=1),
because nobody is there to answer a confirmation. No switch disables P0.

Stdlib only. Imported by the event scripts in this directory; also usable as a CLI:
    python3 .claude/hooks/_policy.py event <kind> [key=value ...]   # emit an evolution event
    python3 .claude/hooks/_policy.py scan <file>                    # secret scan, exit 1 on hit
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

AUTONOMOUS_MODES = {"bypassPermissions", "dontAsk", "auto"}
CLASS_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
HOOKS_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------- environment and switches

def env_on(name: str, default: str = "1") -> bool:
    return os.environ.get(name, default) not in ("0", "false", "False", "")


def domain_enabled(domain: str, cls: str) -> bool:
    """Kill switches. P0 is never switched off."""
    if cls == "P0":
        return True
    if domain == "KNW":
        return env_on("ENG_WIKI_HOOKS") and os.environ.get("CLAUDE_HOOK_GUARD") != "1"
    return env_on("SECURITY_HOOKS")


def is_autonomous(data: dict) -> bool:
    return data.get("permission_mode") in AUTONOMOUS_MODES or os.environ.get("AGENT_AUTONOMOUS") == "1"


def project_dir(data: dict) -> Path:
    # cwd from the hook input follows worktrees; CLAUDE_PROJECT_DIR stays at the main checkout.
    return Path(data.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()


def project_slug(data: dict) -> str:
    root = os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or os.getcwd()
    return re.sub(r"[^A-Za-z0-9._-]+", "-", Path(root).name).strip("-") or "project"


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    d = Path(base) / "dev-env-hooks"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------- I/O

def read_input() -> dict:
    raw = sys.stdin.read()
    return json.loads(raw) if raw.strip() else {}


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def run(main, *, hook: str) -> None:
    """Run a hook entry point; an unexpected error fails open and is recorded."""
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - a hook must never crash the session
        detail = f"{type(exc).__name__}: {exc}"
        with contextlib.suppress(Exception):
            audit({"hook": hook, "decision": "error", "detail": detail})
            evolution_event("hook_error", {"hook": hook, "error": type(exc).__name__}, {})
        print(f"{hook}: internal error ({type(exc).__name__}), failing open", file=sys.stderr)
        sys.exit(0)


# ---------------------------------------------------------------- secrets

# High-precision patterns adapted from gitleaks (config/gitleaks.toml). No generic entropy rule:
# it is too noisy for prompts and tool output.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    (rid, re.compile(rx)) for rid, rx in [
        ("anthropic-api-key", r"sk-ant-[a-z]+\d{2}-[A-Za-z0-9_\-]{40,}"),
        ("openai-api-key", r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{16,}T3BlbkFJ[A-Za-z0-9_\-]{16,}"),
        ("github-pat", r"\bghp_[A-Za-z0-9]{36}\b"),
        ("github-fine-grained-pat", r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        ("github-token", r"\bgh[ousr]_[A-Za-z0-9]{36}\b"),
        ("aws-access-key-id", r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"),
        ("private-key", r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----"),
        ("huggingface-token", r"\bhf_[A-Za-z]{34}\b"),
        ("google-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        ("slack-token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}"),
        ("gitlab-pat", r"\bglpat-[0-9A-Za-z_\-]{20}\b"),
        ("stripe-key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,99}\b"),
        ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ]
]
ALLOW_MARKERS = ("gitleaks:allow", "pragma: allowlist secret")
PLACEHOLDER = re.compile(r"EXAMPLE|x{8,}|X{8,}|0{12,}|<[^>]*>|\{\{.*\}\}|\.\.\.", re.IGNORECASE)


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def allowlisted() -> set[str]:
    f = HOOKS_DIR / "secret_allowlist.txt"
    if not f.exists():
        return set()
    return {ln.split("#")[0].strip() for ln in f.read_text().splitlines() if ln.split("#")[0].strip()}


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return (rule_id, value) for every secret in text, skipping marked lines,
    placeholders, and allowlisted fingerprints."""
    if not text:
        return []
    allow = allowlisted()
    hits: list[tuple[str, str]] = []
    for line in text.splitlines() or [text]:
        if any(m in line for m in ALLOW_MARKERS):
            continue
        for rid, rx in SECRET_PATTERNS:
            for m in rx.finditer(line):
                value = m.group(0)
                if PLACEHOLDER.search(value) or fingerprint(value) in allow:
                    continue
                hits.append((rid, value))
    return hits


def redact(text: str) -> tuple[str, list[str]]:
    rules: list[str] = []
    for rid, value in find_secrets(text):
        text = text.replace(value, f"[REDACTED:{rid}]")
        rules.append(rid)
    return text, rules


def deep_redact(obj):
    """Redact every string inside a JSON-like structure, keeping its shape."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, list):
        out, rules = [], []
        for item in obj:
            new, r = deep_redact(item)
            out.append(new)
            rules += r
        return out, rules
    if isinstance(obj, dict):
        out, rules = {}, []
        for k, v in obj.items():
            new, r = deep_redact(v)
            out[k] = new
            rules += r
        return out, rules
    return obj, []


def mask(text: str, limit: int = 200) -> str:
    """Make text safe to log: redact secrets, truncate."""
    clean, _ = redact(text or "")
    return clean if len(clean) <= limit else clean[:limit] + "…"


# ---------------------------------------------------------------- rules and decisions

@dataclass(frozen=True)
class Rule:
    id: str
    domain: str
    cls: str
    reason: str


def strongest(hits: list[Rule]) -> Rule | None:
    hits = [r for r in hits if domain_enabled(r.domain, r.cls)]
    return min(hits, key=lambda r: CLASS_RANK[r.cls]) if hits else None


def effective_class(rule: Rule, data: dict) -> str:
    return "P1" if rule.cls == "P2" and is_autonomous(data) else rule.cls


def pre_tool_decision(rule: Rule, data: dict, detail: str) -> None:
    """Emit the PreToolUse decision for the strongest matching rule."""
    cls = effective_class(rule, data)
    if cls in ("P0", "P1"):
        decision = "deny"
        lock = " This path is locked (P0); only the user can change it, outside the session." if cls == "P0" else ""
        reason = f"[{rule.id} · {rule.domain}/{cls}] {rule.reason}.{lock} If this is a false positive, tell the user; do not work around it."
    elif cls == "P2":
        decision = "ask"
        reason = f"[{rule.id} · {rule.domain}/P2] {rule.reason}. Confirm to proceed."
        with session_state(data) as st:
            st.setdefault("pending_asks", {})[data.get("tool_use_id", "")] = rule.id
    else:
        return
    audit({"hook": "pre_tool_use", "rule": rule.id, "domain": rule.domain, "class": cls,
           "decision": decision, "session": data.get("session_id"), "detail": mask(detail)})
    if decision == "deny":
        evolution_event("p1_blocked", {"rule": rule.id, "class": cls, "tool": data.get("tool_name")}, data)
    emit({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                 "permissionDecision": decision,
                                 "permissionDecisionReason": reason}})


def load_project_rules(root: Path) -> list[dict]:
    """Project rules (.claude/project-rules.json) can only add P1–P3 Bash rules: they tighten,
    never loosen, so the file is not a guard file and `tailor` may write it."""
    f = root / ".claude" / "project-rules.json"
    if not f.exists():
        return []
    try:
        rules = json.loads(f.read_text()).get("rules", [])
    except (json.JSONDecodeError, AttributeError):
        return []
    out = []
    for r in rules:
        if r.get("class") in ("P1", "P2", "P3") and r.get("domain") in ("SEC", "DST", "OUT", "KNW") and r.get("pattern"):
            try:
                out.append({**r, "rx": re.compile(r["pattern"])})
            except re.error:
                continue
    return out


# ---------------------------------------------------------------- state, audit, evolution

@contextlib.contextmanager
def session_state(data: dict):
    """Per-session JSON state, locked against parallel hook runs."""
    sid = re.sub(r"[^A-Za-z0-9_-]", "", str(data.get("session_id") or "nosession"))
    d = state_dir() / "sessions"
    d.mkdir(exist_ok=True)
    path = d / f"{sid}.json"
    with open(d / f"{sid}.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = json.loads(path.read_text()) if path.exists() else {}
        yield state
        path.write_text(json.dumps(state))


def audit(entry: dict) -> None:
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "project": os.environ.get("CLAUDE_PROJECT_DIR", ""), **entry}
    with open(state_dir() / "audit.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


def evolution_home() -> Path | None:
    home = os.environ.get("DEV_ENV_EVOLUTION_HOME")
    if not home or not env_on("DEV_ENV_EVOLUTION"):
        return None
    p = Path(os.path.expanduser(home))
    return p if p.is_dir() else None


def evolution_event(kind: str, fields: dict, data: dict) -> None:
    """Append one redacted signal to the evolution repo (evolution mode only)."""
    home = evolution_home()
    if home is None:
        return
    slug = project_slug(data)
    d = home / "events" / slug
    d.mkdir(parents=True, exist_ok=True)
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": kind, "project": slug,
             "session": data.get("session_id"), **{k: mask(str(v)) for k, v in fields.items()}}
    with open(d / f"{time.strftime('%Y-%m')}.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------- CLI

def _cli(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "event":
        fields = dict(a.split("=", 1) for a in argv[2:] if "=" in a)
        evolution_event(argv[1], fields, {"cwd": os.getcwd()})
        return 0
    if len(argv) == 2 and argv[0] == "scan":
        hits = find_secrets(Path(argv[1]).read_text(errors="replace"))
        for rid, value in hits:
            print(f"{rid}\t{fingerprint(value)}")
        return 1 if hits else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
