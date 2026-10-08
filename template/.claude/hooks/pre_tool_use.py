#!/usr/bin/env python3
"""PreToolUse: S2 bash guard · S3 path guard · S4 commit scan (+ project rules).

S3 (secret and guard paths) fails closed: if this script errors on a file tool, the call is
denied. S2/S4 fail open. See _policy.py for classes and switches.
"""
from __future__ import annotations

import fnmatch
import json
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
R_GUARD_PATH = P.Rule("S3-guard-path", "GRD", "P0", "Hook scripts, Claude settings, sandbox profiles, .mcp.json and the pre-commit config are guard files")


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
        if len(rest) == 1 and (fnmatch.fnmatch(rest[0], "settings*.json") or fnmatch.fnmatch(rest[0], "sandbox*.json")):
            return True
    return p.name in (".pre-commit-config.yaml", ".mcp.json")


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
GUARD_RX = re.compile(r"(^|/)\.claude/hooks(/\S*)?$|(^|/)\.claude/(settings|sandbox)[^/\s]*\.json$|"
                      r"(^|/)\.pre-commit-config\.yaml$|(^|/)\.mcp\.json$")
GUARD_ANYWHERE = re.compile(r"\.claude/(hooks|settings[^/\s]*\.json|sandbox[^/\s]*\.json)|\.pre-commit-config\.yaml|\.mcp\.json")
REDIRECT_TARGET = re.compile(r">>?\s*['\"]?([^\s'\";|&]+)")
SETTINGS_WRITER = re.compile(r"apply_user_settings\.py")
TARGET_ALL = {"rm", "rmdir", "truncate", "chmod", "chown", "touch", "tee", "sponge", "shred", "unlink"}
TARGET_LAST = {"cp", "mv", "ln", "install", "rsync"}
INLINE_CODE = {"python", "python3", "perl", "ruby", "node", "bash", "sh", "zsh"}
SECRET_READ_CMD = re.compile(r"(^|[\s;&|(])(cat|less|more|head|tail|bat|grep|rg|xxd|strings|base64|cp|scp|od|awk|cut|"
                             r"tac|nl|diff|sort|uniq|sed|jq|paste|column|vi|vim|nano|view)\s")
SECRET_FILE_IN_CMD = re.compile(r"(^|[\s/'\"=])(\.env(\.(?!example|sample|template|dist)[\w*?]+)*[*?]*|id_(rsa|ed25519|ecdsa|dsa)|"
                                r"\.git-credentials|\.pypirc|\.netrc|[\w.*-]+\.pem)(?=$|[\s'\";|&)])|~/\.(ssh|aws|gnupg)/|"
                                r"\.config/gh/")

BASH_RULES: list[tuple[P.Rule, re.Pattern]] = [
    (P.Rule("S2-pipe-to-shell", "OUT", "P1", "Running downloaded code unreviewed"),
     re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|"
                r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?python[\d.]*\b(?!\s+-c\b|\s+-m\s+json\.tool\b)|"
                r"\b(ba|z)?sh\s+<\(\s*(curl|wget)\b|\bsource\s+<\(\s*(curl|wget)\b")),
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
R_RM_OUTSIDE = P.Rule("S2-rm-outside", "DST", "P1", "Recursive delete of the project root, a temp root, or anything outside them")
R_SECRET_READ = P.Rule("S2-secret-read", "SEC", "P1", "Reading credential files through the shell")
R_GUARD_WRITE = P.Rule("S3-guard-shell", "GRD", "P0", "Changing guard files through the shell")


def is_guard_token(tok: str) -> bool:
    return bool(GUARD_RX.search(tok.rstrip("/")))


def writes_guard(cmd: str) -> bool:
    """True when a guard file is the *target* of a write, not merely mentioned."""
    if SETTINGS_WRITER.search(cmd):
        return True
    if any(is_guard_token(t) for t in REDIRECT_TARGET.findall(cmd)):
        return True
    for toks in segments(cmd):
        name = Path(toks[0]).name
        args = [t for t in toks[1:] if not t.startswith("-")]
        if name in TARGET_ALL and any(is_guard_token(a) for a in args):
            return True
        if name in TARGET_LAST and args and is_guard_token(args[-1]):
            return True
        if name == "sed" and any(t.startswith("-i") or t == "--in-place" for t in toks) and any(is_guard_token(a) for a in args):
            return True
        if name == "git" and len(toks) > 1 and toks[1] in ("checkout", "restore", "rm", "mv") and any(is_guard_token(a) for a in args[1:]):
            return True
        if name in INLINE_CODE and any(t in ("-c", "-e") for t in toks):
            code = " ".join(toks[toks.index("-c" if "-c" in toks else "-e") + 1:])
            if GUARD_ANYWHERE.search(code) and re.search(r"open\(|write|unlink|remove|rename|replace|truncate|>", code):
                return True
    return False


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
        if target in allowed or target in (Path("/"), HOME) or not any(a in target.parents for a in allowed):
            return True  # the roots themselves (project, /tmp) are not deletable either
    return False


def pushes_main(toks: list[str], cwd: Path) -> bool:
    if toks[:1] != ["git"] or "push" not in toks:
        return False
    args = [t for t in toks[toks.index("push") + 1:] if not t.startswith("-")]
    if any(re.search(r"(^|:)(refs/heads/)?(main|master)$", a) for a in args[1:]):
        return True
    if len(args) <= 1:  # no refspec: pushes the current branch
        try:
            branch = subprocess.run(["git", "-C", str(cwd), "branch", "--show-current"],
                                    capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return False
        return branch in ("main", "master")
    return False


HEREDOC_START = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")
SHELLS = re.compile(r"(^|[\s;&|(])(ba|z|da)?sh|python[\d.]*|perl|ruby|node|ssh|exec|eval")
MESSAGE_ARG = re.compile(r"(\s(?:-m|--message)(?:=|\s+))(\"(?:[^\"\\\\]|\\\\.)*\"|'[^']*')")


def strip_data(cmd: str) -> str:
    """Remove text that is data, not commands: heredoc bodies (unless fed to an interpreter) and
    commit messages. Keeps the heredoc's first line, so redirect targets still count."""
    lines, out, i = cmd.split("\n"), [], 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        m = HEREDOC_START.search(line)
        i += 1
        if m and not SHELLS.search(line[:m.start()].split("|")[-1].strip().split(" ")[0] if line[:m.start()].strip() else ""):
            while i < len(lines) and lines[i].strip() != m.group(1):
                i += 1
            i += 1
    return MESSAGE_ARG.sub(lambda m: m.group(1) + '"…"', "\n".join(out))


def check_bash(cmd: str, data: dict, root: Path, cwd: Path) -> list[P.Rule]:
    cmd = strip_data(cmd)
    hits = [rule for rule, rx in BASH_RULES if rx.search(cmd)]
    if writes_guard(cmd):
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

R_COMMIT_SECRET = P.Rule("S4-commit-secret", "SEC", "P1", "Changes about to be committed contain a secret")
VALUE_FLAGS = {"-m", "--message", "-F", "--file", "-C", "-c", "--reuse-message", "--reedit-message", "--author",
               "--date", "-t", "--template", "--fixup", "--squash", "--cleanup", "--trailer"}


def commit_scope(cmd: str) -> str | None:
    """None if the command doesn't commit; 'staged' if only the index is committed; 'broad' if
    the command stages or commits working-tree changes too (-a, pathspec, add && commit)."""
    segs = segments(cmd)
    for i, toks in enumerate(segs):
        if toks[:1] == ["git"] and "commit" in toks:
            after = toks[toks.index("commit") + 1:]
            broad = any(t in ("--all", "--include", "--only", "-i", "-o") or
                        (re.match(r"^-[a-zA-Z]+$", t) and "a" in t) for t in after)
            skip = False
            for t in after:  # a pathspec commits the working-tree version of those files
                if skip:
                    skip = False
                    continue
                if t in VALUE_FLAGS:
                    skip = True
                elif not t.startswith("-"):
                    broad = True
            if any(s[:1] == ["git"] and len(s) > 1 and s[1] in ("add", "rm", "mv", "stage") for s in segs[:i]):
                broad = True
            return "broad" if broad else "staged"
    return None


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=15).stdout


def scan_commit(cwd: Path, scope: str) -> str | None:
    """Return a short finding summary, or None when clean."""
    if shutil.which("gitleaks"):
        r = subprocess.run(["gitleaks", "git", "--pre-commit", "--staged", "--redact", "--no-banner",
                            "--exit-code", "1"], cwd=cwd, capture_output=True, text=True, timeout=25)
        if r.returncode == 1:
            return "gitleaks: " + P.mask(r.stdout + r.stderr, 300)
        if r.returncode == 0 and scope == "staged":
            return None  # clean; otherwise (error or broad scope) fall through to the built-in scan
    texts = [_git(cwd, "diff", "--cached", "-U0")]
    if scope == "broad":
        texts.append(_git(cwd, "diff", "-U0"))
    added = [ln[1:] for t in texts for ln in t.splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    if scope == "broad":  # untracked files that `git add` could pick up
        for rel in _git(cwd, "ls-files", "--others", "--exclude-standard").splitlines()[:500]:
            f = cwd / rel
            if f.is_file() and f.stat().st_size < 1_000_000:
                added.append(f.read_text(errors="replace"))
    hits = P.find_secrets("\n".join(added))
    if hits:
        return "built-in scan: " + ", ".join(sorted({rid for rid, _ in hits}))
    return None


# ---------------------------------------------------------------- main

R_GREP_SECRET = P.Rule("S3-secret-path", "SEC", "P0", "Searching inside credential files is locked")


def main() -> None:
    raw_in = sys.stdin.read()
    try:
        data = json.loads(raw_in) if raw_in.strip() else {}
    except json.JSONDecodeError:
        return  # not a tool call we can judge; fail open
    try:
        decide(data)
    except Exception as exc:  # noqa: BLE001
        # P0 fails closed: a file tool, or a command that mentions a guard or secret path.
        tool = data.get("tool_name", "")
        cmd = (data.get("tool_input") or {}).get("command", "")
        if tool in FILE_TOOLS or GUARD_ANYWHERE.search(cmd) or SECRET_FILE_IN_CMD.search(cmd):
            P.emit(P.deny_output(f"[S3-error · GRD/P0] Guard failed ({type(exc).__name__}); failing closed. Tell the user."))
            return
        raise


def decide(data: dict) -> None:
    tool = data.get("tool_name", "")
    ti = data.get("tool_input") or {}
    root = P.project_dir(data)
    cwd = Path(data.get("cwd") or root)

    if tool in FILE_TOOLS:
        raw = ti.get("file_path") or ti.get("notebook_path") or ""
        rule = check_path(tool, raw, root) if raw else None
        if rule:
            P.pre_tool_decision(rule, data, f"{tool} {raw}")
        return

    if tool == "Grep":
        raw = ti.get("path") or ""
        if raw and check_path("Read", raw, root) == R_SECRET_PATH:
            P.pre_tool_decision(R_GREP_SECRET, data, f"Grep {raw}")
        return

    if tool == "Bash":
        cmd = ti.get("command", "")
        hits = check_bash(cmd, data, root, cwd)
        scope = commit_scope(cmd)
        if scope and P.domain_enabled("SEC", "P1"):
            finding = scan_commit(cwd, scope)
            if finding:
                hits.append(P.Rule(R_COMMIT_SECRET.id, "SEC", "P1",
                                   f"{R_COMMIT_SECRET.reason} ({finding}); remove it, use an env var, rotate if real"))
        rule = P.strongest(hits)
        if rule:
            P.pre_tool_decision(rule, data, cmd)


if __name__ == "__main__":
    P.run(main, hook="pre_tool_use")
