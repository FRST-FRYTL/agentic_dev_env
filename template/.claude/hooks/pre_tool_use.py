#!/usr/bin/env python3
"""PreToolUse: S2 bash guard · S3 path guard · S4 commit scan (+ project rules).

S3 (secret and guard paths) fails closed: if this script errors on a file tool, the call is
denied. S2/S4 fail open. See _policy.py for classes and switches.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _policy as P  # noqa: E402

FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}
WRITE_TOOLS = FILE_TOOLS - {"Read"}
HOME = Path.home()

# ---------------------------------------------------------------- S3 path rules

SECRET_BASENAMES = [".env", ".env.*", "*.pem", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*", "id_ecdsa*",
                    "id_dsa*", ".git-credentials", ".pypirc", ".netrc"]
SECRET_BASENAME_OK = [".env.example", ".env.sample", ".env.template", ".env.dist", "*.pub"]
SECRET_DIRS = [HOME / ".ssh", HOME / ".aws", HOME / ".gnupg", HOME / ".config" / "gh"]
SECRET_FILES = [HOME / ".docker" / "config.json"]

R_SECRET_PATH = P.Rule("S3-secret-path", "SEC", "P0", "Reading or writing credential files is locked")
R_GUARD_PATH = P.Rule("S3-guard-path", "GRD", "P0", "Hook scripts, Claude settings and the pre-commit config are guard files")


def is_secret_path(p: Path) -> bool:
    name = p.name
    if any(fnmatch.fnmatch(name, pat) for pat in SECRET_BASENAME_OK):
        return False
    if any(fnmatch.fnmatch(name, pat) for pat in SECRET_BASENAMES):
        return True
    return p in SECRET_FILES or any(p == d or d in p.parents for d in SECRET_DIRS)


def is_guard_path(p: Path) -> bool:
    parts = p.parts
    if ".claude" in parts:
        i = len(parts) - 1 - parts[::-1].index(".claude")
        rest = parts[i + 1:]
        if rest[:1] == ("hooks",):
            return True
        if len(rest) == 1 and fnmatch.fnmatch(rest[0], "settings*.json"):
            return True
    return p.name == ".pre-commit-config.yaml"


def check_path(tool: str, raw: str, root: Path) -> P.Rule | None:
    p = Path(os.path.expanduser(raw))
    p = (p if p.is_absolute() else root / p).resolve()
    if is_secret_path(p):
        return R_SECRET_PATH
    if tool in WRITE_TOOLS and is_guard_path(p):
        return R_GUARD_PATH
    return None


# ---------------------------------------------------------------- S2 bash rules

SEGMENT_SPLIT = re.compile(r"\|\||&&|;|\n|\|")
WRITE_HINT = re.compile(r"(^|\s)(>|>>|tee|sed\s+-i|rm|mv|cp|chmod|chown|truncate|ln|install|rsync|dd|"
                        r"git\s+(checkout|restore|rm|mv)|python3?|perl|ruby|node)(\s|$)")
GUARD_IN_CMD = re.compile(r"\.claude/(hooks\b|settings[^/\s]*\.json)|\.pre-commit-config\.yaml")
SECRET_READ_CMD = re.compile(r"(^|[\s;&|(])(cat|less|more|head|tail|bat|grep|rg|xxd|strings|base64|cp|scp|od)\s")
SECRET_FILE_IN_CMD = re.compile(r"(^|[\s/'\"=])(\.env(\.(?!example|sample|template|dist)\w+)*|id_(rsa|ed25519|ecdsa|dsa)|"
                                r"\.git-credentials|\.pypirc|\.netrc|[\w.-]+\.pem)(?=$|[\s'\";|&)])|~/\.(ssh|aws|gnupg)/|"
                                r"\.config/gh/")

BASH_RULES: list[tuple[P.Rule, re.Pattern]] = [
    (P.Rule("S2-pipe-to-shell", "OUT", "P1", "Piping a download into a shell runs unreviewed code"),
     re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?python")),
    (P.Rule("S2-force-push", "OUT", "P1", "Force-push rewrites shared history (use --force-with-lease if really needed)"),
     re.compile(r"\bgit\b.*\bpush\b.*(\s--force(?!-with-lease)\b|\s-f\b|\s\+\S)")),
    (P.Rule("S2-reset-hard", "DST", "P1", "git reset --hard discards uncommitted work"),
     re.compile(r"\bgit\b.*\breset\b.*--hard\b")),
    (P.Rule("S2-clean-force", "DST", "P1", "git clean -f deletes untracked files permanently"),
     re.compile(r"\bgit\b.*\bclean\b.*\s-[a-zA-Z]*f")),
    (P.Rule("S2-mkfs-dd", "DST", "P1", "Low-level disk writes"),
     re.compile(r"\bmkfs(\.\w+)?\b|\bdd\b.*\bof=/dev/")),
    (P.Rule("S2-chmod-777", "DST", "P1", "World-writable permissions"),
     re.compile(r"\bchmod\b.*\b0?777\b")),
    (P.Rule("S2-no-verify", "OUT", "P2", "Skipping git hooks also skips the secret scan"),
     re.compile(r"\bgit\b.*\b(commit|push)\b.*--no-verify\b|\bSKIP=\S*gitleaks")),
]
R_PUSH_MAIN = P.Rule("S2-push-main", "OUT", "P2", "Pushing directly to main/master")
R_RM_OUTSIDE = P.Rule("S2-rm-outside", "DST", "P1", "Recursive delete outside the project and temp directories")
R_SECRET_READ = P.Rule("S2-secret-read", "SEC", "P1", "Reading credential files through the shell")
R_GUARD_WRITE = P.Rule("S3-guard-shell", "GRD", "P0", "Changing guard files through the shell")


def segments(cmd: str) -> list[list[str]]:
    out = []
    for seg in SEGMENT_SPLIT.split(cmd):
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        while toks and re.match(r"^\w+=", toks[0]):  # strip leading VAR=value
            toks = toks[1:]
        while toks and toks[0] in ("sudo", "command", "exec", "nohup", "time"):
            toks = toks[1:]
        if toks:
            out.append(toks)
    return out


def rm_outside(toks: list[str], root: Path, cwd: Path) -> bool:
    if Path(toks[0]).name != "rm":
        return False
    flags = [t for t in toks[1:] if t.startswith("-")]
    if not any(f in ("-r", "-R", "--recursive") or (not f.startswith("--") and ("r" in f or "R" in f)) for f in flags):
        return False
    allowed = [root, Path("/tmp"), Path(os.environ.get("TMPDIR", "/tmp"))]
    for t in toks[1:]:
        if t.startswith("-"):
            continue
        target = Path(os.path.expandvars(os.path.expanduser(t)))
        target = (target if target.is_absolute() else cwd / target).resolve()
        if not any(target == a or a in target.parents for a in allowed) or target in (Path("/"), HOME):
            return True
    return False


def pushes_main(toks: list[str], cwd: Path) -> bool:
    if toks[:1] != ["git"] or "push" not in toks:
        return False
    args = [t for t in toks[toks.index("push") + 1:] if not t.startswith("-")]
    if any(re.search(r"(^|:)(main|master)$", a) for a in args[1:]):
        return True
    if len(args) <= 1:  # no refspec: pushes the current branch
        try:
            branch = subprocess.run(["git", "-C", str(cwd), "branch", "--show-current"],
                                    capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return False
        return branch in ("main", "master")
    return False


def check_bash(cmd: str, data: dict, root: Path, cwd: Path) -> list[P.Rule]:
    hits = [rule for rule, rx in BASH_RULES if rx.search(cmd)]
    if GUARD_IN_CMD.search(cmd) and WRITE_HINT.search(cmd):
        hits.append(R_GUARD_WRITE)
    if SECRET_FILE_IN_CMD.search(cmd) and SECRET_READ_CMD.search(" " + cmd):
        hits.append(R_SECRET_READ)
    for toks in segments(cmd):
        if rm_outside(toks, root, cwd):
            hits.append(R_RM_OUTSIDE)
        if pushes_main(toks, cwd):
            hits.append(R_PUSH_MAIN)
    for r in P.load_project_rules(root):
        if r.get("tool", "Bash") == "Bash" and r["rx"].search(cmd):
            hits.append(P.Rule(r.get("id", "project-rule"), r["domain"], r["class"], r.get("reason", "Project rule")))
    return hits


# ---------------------------------------------------------------- S4 commit scan

R_COMMIT_SECRET = P.Rule("S4-commit-secret", "SEC", "P1", "Staged changes contain a secret")


def is_commit(cmd: str) -> tuple[bool, bool]:
    for toks in segments(cmd):
        if toks[:1] == ["git"] and "commit" in toks:
            after = toks[toks.index("commit") + 1:]
            all_flag = any(t == "--all" or (re.match(r"^-[a-zA-Z]+$", t) and "a" in t) for t in after)
            return True, all_flag
    return False, False


def scan_commit(cwd: Path, all_flag: bool) -> str | None:
    """Return a short finding summary, or None when clean."""
    if shutil.which("gitleaks"):
        r = subprocess.run(["gitleaks", "git", "--pre-commit", "--staged", "--redact", "--no-banner",
                            "--exit-code", "1"], cwd=cwd, capture_output=True, text=True, timeout=25)
        if r.returncode == 1:
            return "gitleaks: " + P.mask(r.stdout + r.stderr, 300)
        if r.returncode == 0 and not all_flag:
            return None  # clean; otherwise (error or -a) fall through to the built-in scan
    diffs = [["git", "diff", "--cached", "-U0"]] + ([["git", "diff", "-U0"]] if all_flag else [])
    added = []
    for d in diffs:
        out = subprocess.run(d, cwd=cwd, capture_output=True, text=True, timeout=15).stdout
        added += [ln[1:] for ln in out.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    hits = P.find_secrets("\n".join(added))
    if hits:
        return "fallback scan: " + ", ".join(sorted({rid for rid, _ in hits}))
    return None


# ---------------------------------------------------------------- main

def main() -> None:
    data = P.read_input()
    tool = data.get("tool_name", "")
    ti = data.get("tool_input") or {}
    root = P.project_dir(data)
    cwd = Path(data.get("cwd") or root)

    if tool in FILE_TOOLS:
        raw = ti.get("file_path") or ti.get("notebook_path") or ""
        try:
            rule = check_path(tool, raw, root) if raw else None
        except Exception as exc:  # noqa: BLE001 - S3 fails closed
            rule = P.Rule("S3-error", "GRD", "P0", f"Path guard failed ({type(exc).__name__}); failing closed")
        if rule:
            P.pre_tool_decision(rule, data, f"{tool} {raw}")
        return

    if tool == "Bash":
        cmd = ti.get("command", "")
        hits = check_bash(cmd, data, root, cwd)
        committing, all_flag = is_commit(cmd)
        if committing and P.domain_enabled("SEC", "P1"):
            finding = scan_commit(cwd, all_flag)
            if finding:
                hits.append(P.Rule(R_COMMIT_SECRET.id, "SEC", "P1",
                                   f"{R_COMMIT_SECRET.reason} ({finding}); unstage it, use an env var, rotate if real"))
        rule = P.strongest(hits)
        if rule:
            P.pre_tool_decision(rule, data, cmd)


if __name__ == "__main__":
    P.run(main, hook="pre_tool_use")
