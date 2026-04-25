#!/usr/bin/env python3
"""
SessionStart auto-pull hook for Claude Code.

Runs git fetch + fast-forward / rebase pull across every direct sub-repo of
the workspace root. Stashes dirty working trees before pulling and restores
them after. Never creates branches. Emits a Claude Code SessionStart hook
JSON payload on stdout so the user sees a banner at session start and the
agent receives the full report as additional context.

Codex CLI is intentionally not supported: as of codex v0.125.0, hook output
(systemMessage / additionalContext) is not surfaced to the user in either
`codex exec` or the TUI.

Behaviour:
  * Block flag /tmp/block-session-pull: print blocked message to stderr,
    exit 2 (agent refuses to start the session).
  * Per-repo flock prevents two parallel sessions from racing on the same
    repo. If the lock cannot be acquired in 10s, the repo is reported as
    "locked" and skipped this round.
  * Stash entries are tagged with a unique message so concurrent stashes
    do not clobber each other; pop is by message, not by stack position.
  * Conflicts that cannot be auto-resolved (rebase, stash pop) are surfaced
    verbatim in the report; the repo is left in a recoverable state.

Inputs:
  Reads a JSON object from stdin (Claude Code hook input). Uses the "cwd"
  field as the workspace root. Falls back to $PWD if cwd is missing.

Output:
  A single JSON object on stdout with two channels:
    * systemMessage: a one-line summary shown directly to the user as a
      session-start banner (so the report is visible before the user types).
    * hookSpecificOutput.additionalContext: the full multi-line report
      injected into the agent's context.
  Errors and the block message on stderr.
  Exit 0 normally, exit 2 when blocked.
"""

import concurrent.futures
import datetime
import fcntl
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

BLOCK_FILE = "/tmp/block-session-pull"
LOCK_TIMEOUT_SECONDS = 10
FETCH_TIMEOUT_SECONDS = 60
GIT_OP_TIMEOUT_SECONDS = 60
MAX_WORKERS = 8


@dataclass
class RepoResult:
    name: str
    category: str = "clean"
    detail: str = ""
    notes: List[str] = field(default_factory=list)


def run_git(repo: Path, *args: str, timeout: int = GIT_OP_TIMEOUT_SECONDS) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _clean_git_err(text: str, max_chars: int = 200) -> str:
    """Compact a git error message for inline display in the status report.

    Drops `hint:` lines, collapses whitespace runs (including newlines) into
    single spaces, trims, and truncates with an ellipsis.
    """
    if not text:
        return ""
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("hint:")]
    flat = " ".join(ln.strip() for ln in lines if ln.strip())
    if len(flat) > max_chars:
        flat = flat[: max_chars - 1].rstrip() + "…"
    return flat


def detect_special_state(repo: Path) -> str:
    git_dir = repo / ".git"
    if git_dir.is_file():
        return ""
    if (git_dir / "rebase-merge").exists() or (git_dir / "rebase-apply").exists():
        return "mid-rebase"
    if (git_dir / "MERGE_HEAD").exists():
        return "mid-merge"
    if (git_dir / "CHERRY_PICK_HEAD").exists():
        return "mid-cherry-pick"
    if (git_dir / "BISECT_LOG").exists():
        return "mid-bisect"
    return ""


def read_state(repo: Path) -> dict:
    state = {"branch": None, "upstream": None, "ahead": 0, "behind": 0,
             "dirty": 0, "special": "", "detached": False}
    state["special"] = detect_special_state(repo)

    r = run_git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
    if r.returncode != 0:
        state["detached"] = True
        return state
    state["branch"] = r.stdout.strip()

    r = run_git(repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if r.returncode != 0:
        return state
    state["upstream"] = r.stdout.strip()

    r = run_git(repo, "rev-list", "--left-right", "--count", "HEAD...@{u}")
    if r.returncode == 0 and r.stdout.strip():
        parts = r.stdout.strip().split()
        if len(parts) == 2:
            state["ahead"] = int(parts[0])
            state["behind"] = int(parts[1])

    r = run_git(repo, "status", "--porcelain")
    if r.returncode == 0:
        state["dirty"] = sum(1 for line in r.stdout.splitlines() if line.strip())

    return state


def find_stash_ref_by_message(repo: Path, message: str) -> str:
    r = run_git(repo, "stash", "list")
    if r.returncode != 0:
        return ""
    for line in r.stdout.splitlines():
        m = re.match(r"^(stash@\{\d+\}):", line)
        if m and message in line:
            return m.group(1)
    return ""


def list_conflict_files(repo: Path) -> List[str]:
    r = run_git(repo, "diff", "--name-only", "--diff-filter=U")
    if r.returncode != 0:
        return []
    return [f for f in r.stdout.splitlines() if f.strip()]


def acquire_lock(lock_path: Path):
    try:
        fd = open(lock_path, "w")
    except OSError:
        return None
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            time.sleep(0.2)
    fd.close()
    return None


def process_repo(repo: Path) -> RepoResult:
    name = repo.name
    result = RepoResult(name=name)

    git_internal = repo / ".git"
    if git_internal.is_file():
        result.category = "skipped"
        result.detail = "submodule (skipped)"
        return result

    lock_path = git_internal / "sessionstart-pull.lock"
    lock_fd = acquire_lock(lock_path)
    if lock_fd is None:
        result.category = "locked"
        result.detail = "another session held the lock; skipped this round"
        return result

    try:
        try:
            r = run_git(repo, "fetch", "--quiet", timeout=FETCH_TIMEOUT_SECONDS)
            if r.returncode != 0:
                result.category = "errors"
                result.detail = f"fetch failed: {_clean_git_err(r.stderr or r.stdout)}"
                return result
        except subprocess.TimeoutExpired:
            result.category = "errors"
            result.detail = f"fetch timed out (>{FETCH_TIMEOUT_SECONDS}s)"
            return result

        state = read_state(repo)

        if state["special"]:
            result.category = "needs-attention"
            result.detail = f"{state['special']} in progress; manual intervention required"
            return result
        if state["detached"]:
            result.category = "needs-attention"
            result.detail = "detached HEAD; manual intervention required"
            return result
        if not state["upstream"]:
            result.category = "no-upstream"
            return result

        ahead, behind, dirty = state["ahead"], state["behind"], state["dirty"]

        stash_msg = ""
        if dirty:
            stash_msg = f"sessionstart-autostash-{os.getpid()}-{int(time.time() * 1000)}"
            r = run_git(repo, "stash", "push", "-u", "-m", stash_msg)
            if r.returncode != 0:
                result.category = "needs-attention"
                result.detail = (
                    f"dirty tree, stash failed: "
                    f"{_clean_git_err(r.stderr or r.stdout)}; pull skipped"
                )
                return result
            if not find_stash_ref_by_message(repo, stash_msg):
                # Nothing was actually stashed (race or no-op); proceed without restore.
                stash_msg = ""

        pulled_action = ""
        rebase_failed = False
        if behind > 0 and ahead == 0:
            r = run_git(repo, "merge", "--ff-only", "@{u}")
            if r.returncode == 0:
                pulled_action = f"behind {behind} -> fast-forward"
            else:
                rebase_failed = True
                result.notes.append(
                    f"ff-only merge failed: {_clean_git_err(r.stderr or r.stdout)}"
                )
        elif behind > 0 and ahead > 0:
            r = run_git(repo, "pull", "--rebase")
            if r.returncode == 0:
                s = "" if ahead == 1 else "s"
                pulled_action = f"behind {behind} -> rebased over {ahead} local commit{s}"
            else:
                run_git(repo, "rebase", "--abort")
                rebase_failed = True
                result.notes.append(
                    f"rebase failed ({_clean_git_err(r.stderr or r.stdout, 160)}); rebase --abort applied"
                )

        stash_pop_conflict = False
        if stash_msg:
            ref = find_stash_ref_by_message(repo, stash_msg)
            if ref:
                r = run_git(repo, "stash", "pop", ref)
                if r.returncode != 0:
                    stash_pop_conflict = True
                    conflicts = list_conflict_files(repo)
                    files_str = ", ".join(conflicts) if conflicts else "(see git status)"
                    result.notes.append(
                        f"stash pop conflicts in: {files_str}; "
                        f"stash entry preserved ({stash_msg})"
                    )

        if rebase_failed or stash_pop_conflict:
            result.category = "needs-attention"
            parts = []
            if pulled_action:
                parts.append(pulled_action + " (then issue arose)")
            parts.extend(result.notes)
            result.detail = "; ".join(parts) if parts else "needs attention"
        elif pulled_action:
            tail = " (stashed -> applied -> restored cleanly)" if dirty else ""
            result.category = "pulled"
            result.detail = pulled_action + tail
        elif ahead > 0:
            result.category = "ahead-only"
            result.detail = f"+{ahead} unpushed"
        else:
            result.category = "clean"

        return result
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fd.close()


def discover_repos(workspace: Path) -> List[Path]:
    repos = []
    try:
        entries = sorted(workspace.iterdir())
    except OSError:
        return repos
    for entry in entries:
        if not entry.is_dir():
            continue
        if (entry / ".git").exists():
            repos.append(entry)
    return repos


def format_report(results: List[RepoResult]) -> str:
    by_cat = {}
    for r in results:
        by_cat.setdefault(r.category, []).append(r)

    interesting_cats = ("pulled", "ahead-only", "needs-attention", "locked", "errors")
    if not any(by_cat.get(c) for c in interesting_cats):
        return ""

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%MZ")
    lines = [f"Repo status (auto-pull at session start, {ts}):"]

    def section(label, items, render):
        if not items:
            return
        lines.append(f"  {label} ({len(items)}):")
        for r in items:
            lines.append(render(r))

    section("pulled", by_cat.get("pulled", []),
            lambda r: f"    {r.name:<22} {r.detail}")
    section("ahead-only", by_cat.get("ahead-only", []),
            lambda r: f"    {r.name:<22} {r.detail}")
    no_up = by_cat.get("no-upstream", [])
    if no_up:
        names = ", ".join(r.name for r in no_up)
        lines.append(f"  no-upstream ({len(no_up)}): {names}")
    section("needs-attention", by_cat.get("needs-attention", []),
            lambda r: f"    {r.name}: {r.detail}")
    section("locked", by_cat.get("locked", []),
            lambda r: f"    {r.name}: {r.detail}")
    section("errors", by_cat.get("errors", []),
            lambda r: f"    {r.name}: {r.detail}")

    return "\n".join(lines)


def build_summary(results: List[RepoResult]) -> str:
    """Build a one-line user-facing summary for the systemMessage channel."""
    counts = {}
    for r in results:
        counts[r.category] = counts.get(r.category, 0) + 1

    order = ("needs-attention", "errors", "locked", "pulled", "ahead-only")
    pieces = [f"{counts[cat]} {cat}" for cat in order if counts.get(cat)]

    if not pieces:
        return "All repos up to date."
    clean = counts.get("clean", 0)
    suffix = f" ({clean} clean)" if clean else ""
    return "Repo status: " + ", ".join(pieces) + suffix


def emit_block_message_and_exit() -> None:
    try:
        ctime = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(os.path.getctime(BLOCK_FILE)),
        )
    except OSError:
        ctime = "unknown"
    print(
        f"SESSION BLOCKED: {BLOCK_FILE} present (created {ctime}).\n"
        f"A human placed this file to prevent automated session-start "
        f"pulls and new agent sessions.\n\n"
        f"Before removing this block, you may wish to check the status "
        f"of all repos in this workspace and any agents you currently "
        f"have running, to ensure they are in a consistent state. Once "
        f"verified, remove the block to allow new sessions to start:\n"
        f"    rm {BLOCK_FILE}",
        file=sys.stderr,
    )
    sys.exit(2)


def resolve_workspace() -> Optional[Path]:
    if not sys.stdin.isatty():
        try:
            data = sys.stdin.read()
        except Exception:
            data = ""
        if data and data.strip():
            try:
                payload = json.loads(data)
                cwd = payload.get("cwd")
                if cwd:
                    return Path(cwd).resolve()
            except (json.JSONDecodeError, ValueError, AttributeError):
                pass
    fallback = os.environ.get("PWD") or os.getcwd()
    return Path(fallback).resolve() if fallback else None


def main() -> int:
    if os.path.exists(BLOCK_FILE):
        emit_block_message_and_exit()

    workspace = resolve_workspace()
    if workspace is None or not workspace.is_dir():
        return 0

    repos = discover_repos(workspace)
    if not repos:
        return 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        results = list(ex.map(process_repo, repos))

    output = {
        "systemMessage": build_summary(results),
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": format_report(results) or "All repos up to date.",
        },
    }
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # never block the session over a hook bug
        print(f"sessionstart-repo-status: internal error: {e!r}", file=sys.stderr)
        sys.exit(0)
