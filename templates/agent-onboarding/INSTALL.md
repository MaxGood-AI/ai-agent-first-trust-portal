# Agent Onboarding — SessionStart Auto-Pull (Claude Code)

This template installs an automated **SessionStart auto-pull** system for **Claude Code**. On every session start (`startup`, `resume`, `clear`, and `compact`), the hook:

1. Runs `git fetch` across every direct sub-repo of the workspace root.
2. Fast-forwards or rebases each sub-repo as needed (no branching is ever performed).
3. Stashes any dirty working tree before pulling and restores it afterward.
4. Shows the user a one-line status banner immediately at session start (via Claude Code's `systemMessage` channel), and injects the full multi-line report into the agent's context (via `hookSpecificOutput.additionalContext`) so the agent can flag unpushed commits, conflicts, or unresolved issues on its first turn.

A manual block flag (`/tmp/block-session-pull`) lets a human prevent any new agent session across the whole machine from starting until removed.

This is a **governance-grade development-lifecycle automation**: the script and configuration files belong under version control alongside your CLAUDE.md / AGENTS.md policy documents. The agent directory itself (`.claude/`) holds per-machine state and is *not* a governance artifact.

> **Why Claude Code only?** OpenAI Codex CLI was originally in scope for this template, but as of **codex v0.125.0** Codex does not surface hook output (`systemMessage` / `additionalContext`) to the user in either `codex exec` or the TUI — only a generic `hook: SessionStart` line is shown, with no way to display the status banner. We removed Codex from this template until that changes upstream. (Codex is still used inside the Claude Code workflow as the independent pre-commit RED-team reviewer — that's a separate hook unaffected by this template.)

## Why this matters for SOC 2

Every agent session is guaranteed to begin from current code, with a deterministic snapshot of repo state captured in the session transcript. This is automated evidence that "agents always work against current code" — a useful artifact for change-management and configuration-management controls. The script is path-independent and reproducible across every developer machine that uses the workspace.

## Prerequisites

- A git-tracked **governance repository** at your workspace root (the directory that contains all your sub-repos as direct children). See `templates/governance/GOVERNANCE-SETUP.md` for setup.
- **Claude Code** with hooks support (`SessionStart` event).
- **Python 3** available on the developer's `PATH` (the script uses stdlib only — no extra dependencies).
- Git ≥ 2.30 recommended (the script uses `stash push -u -m`, `merge --ff-only @{u}`, and `pull --rebase`).

## Layout produced by this install

```
<workspace-root>/
├── scripts/
│   └── sessionstart-repo-status.py        ← shared script (governance-tracked)
├── agent-config/                          ← canonical config (governance-tracked)
│   └── claude/
│       └── settings.json
└── .claude/                               ← per-machine, gitignored
    └── settings.json   → ../agent-config/claude/settings.json   (symlink)
```

The `scripts/` and `agent-config/` directories are tracked in git as part of your governance repo. The `.claude/` directory contains only the symlink (plus any per-machine local settings such as `.claude/settings.local.json`) and remains gitignored.

## Step 1: Copy the script

From the trust portal's `templates/agent-onboarding/` directory into your workspace root:

```bash
WORKSPACE=~/Development            # adjust to wherever your governance repo is
TRUST_PORTAL=~/Development/ai-agent-first-trust-portal   # adjust if needed

mkdir -p "$WORKSPACE/scripts" "$WORKSPACE/agent-config/claude"

cp "$TRUST_PORTAL/templates/agent-onboarding/scripts/sessionstart-repo-status.py" \
   "$WORKSPACE/scripts/"
chmod +x "$WORKSPACE/scripts/sessionstart-repo-status.py"
```

## Step 2: Wire up Claude Code

If you do **not** yet have `agent-config/claude/settings.json` in your workspace:

```bash
cp "$TRUST_PORTAL/templates/agent-onboarding/agent-config/claude/settings.json" \
   "$WORKSPACE/agent-config/claude/settings.json"
```

If you **already have** `agent-config/claude/settings.json` (for example, for a SessionEnd transcript hook), open it and merge in the `SessionStart` block from the template:

```json
"SessionStart": [
  { "matcher": "startup", "hooks": [{ "type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/scripts/sessionstart-repo-status.py\"", "timeout": 90000 }] },
  { "matcher": "resume",  "hooks": [{ "type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/scripts/sessionstart-repo-status.py\"", "timeout": 90000 }] },
  { "matcher": "clear",   "hooks": [{ "type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/scripts/sessionstart-repo-status.py\"", "timeout": 90000 }] },
  { "matcher": "compact", "hooks": [{ "type": "command", "command": "python3 \"$CLAUDE_PROJECT_DIR/scripts/sessionstart-repo-status.py\"", "timeout": 90000 }] }
]
```

`$CLAUDE_PROJECT_DIR` is set automatically by Claude Code at session start — do not hardcode an absolute path.

Then create the symlink so Claude actually reads the canonical file:

```bash
mkdir -p "$WORKSPACE/.claude"
# If a real settings.json already exists in .claude/, move it into agent-config/ first.
[ -f "$WORKSPACE/.claude/settings.json" ] && [ ! -L "$WORKSPACE/.claude/settings.json" ] && \
  mv "$WORKSPACE/.claude/settings.json" "$WORKSPACE/agent-config/claude/settings.json"

ln -sfn ../agent-config/claude/settings.json "$WORKSPACE/.claude/settings.json"
```

## Step 3: Update your `.gitignore`

In your workspace's `.gitignore`, the `scripts/` and `agent-config/` directories must be tracked, while `.claude/` must remain ignored. Add (or confirm) these lines:

```gitignore
# Track agent-orchestration scripts (governance-tracked)
!scripts/
!scripts/**

# Track canonical agent configuration (governance-tracked).
# .claude/ itself stays ignored — it holds the symlink to these canonical
# files plus per-machine state (settings.local.json, locks).
!agent-config/
!agent-config/**
```

## Step 4: Document the new behaviour

Add a bullet to your CLAUDE.md / AGENTS.md governance documents under your "Cross-Cutting Conventions" section so the agents themselves understand the system:

> **SessionStart auto-pull (Claude Code only)**: every Claude Code session started in this workspace runs `scripts/sessionstart-repo-status.py` before the agent's first turn. The script fetches every direct sub-repo, fast-forwards or rebases as needed, stashes and restores any dirty working tree (no branching is ever performed), shows the user a one-line status banner via `systemMessage`, and injects the full status report into the agent's context via `hookSpecificOutput.additionalContext`. Triggers on all SessionStart matchers (`startup`, `resume`, `clear`, `compact`). Conflicts that the script can't auto-resolve (rebase or stash-pop conflicts) are surfaced verbatim in the report for the agent to handle on its first turn. To pause all new agent sessions globally: `touch /tmp/block-session-pull`; resume with `rm /tmp/block-session-pull`. Before removing the block, check the status of all repos and any agents you have running to ensure things are in a consistent state. Codex CLI is intentionally not wired up: as of codex v0.125.0, hook output is not surfaced to the user in either `codex exec` or the TUI.

## Step 5: Verify

Smoke test the install before relying on it:

```bash
# Dry-run with a synthetic CWD payload (no SessionStart event needed)
cd "$WORKSPACE"
echo '{"cwd": "'"$WORKSPACE"'", "session_id": "smoke-test", "hook_event_name": "SessionStart"}' \
  | python3 scripts/sessionstart-repo-status.py | python3 -m json.tool
```

Expected output is a single JSON object with two keys:

- `systemMessage` — a one-line string (e.g. `"All repos up to date."` or `"Repo status: 2 pulled, 1 needs-attention (20 clean)"`). Claude Code shows this to the user as a banner at session start.
- `hookSpecificOutput.additionalContext` — either `"All repos up to date."` or a multi-line block listing pulled / ahead-only / no-upstream / needs-attention / locked / errors categories. Claude Code injects this into the agent's context.

Test the block flag:

```bash
touch /tmp/block-session-pull
echo '{"cwd": "'"$WORKSPACE"'"}' | python3 scripts/sessionstart-repo-status.py ; echo "exit=$?"
# Expect exit=2 and a clear "SESSION BLOCKED" message on stderr.
rm /tmp/block-session-pull
```

Note: as of the Claude Code hook reference current at the time of writing, `exit 2` is documented as ignored for the `SessionStart` event — the stderr message is still surfaced but the session is not actually blocked. Treat the block flag as a soft signal until that changes.

Then start a real Claude Code session and confirm the banner appears immediately at session start, before you type your first prompt.

## Step 6: Commit

```bash
cd "$WORKSPACE"
git add scripts/ agent-config/ .gitignore CLAUDE.md AGENTS.md
git commit
```

## Tunables

The script has three constants near the top:

| Constant | Default | When to change |
|---|---|---|
| `LOCK_TIMEOUT_SECONDS` | 10 | Increase if you frequently start parallel sessions in the same workspace and they collide on the same sub-repo. |
| `FETCH_TIMEOUT_SECONDS` | 60 | Increase for large repos with slow remotes. The Claude Code hook timeout (90s) caps total wall time; with parallel workers you have headroom. |
| `MAX_WORKERS` | 8 | Increase if you have more than ~30 sub-repos and your network can handle the parallelism. |

## Updating to a newer template version

The `VERSION` file in this template directory is bumped whenever the canonical script or template structure changes meaningfully. To update an existing install:

```bash
diff "$TRUST_PORTAL/templates/agent-onboarding/scripts/sessionstart-repo-status.py" \
     "$WORKSPACE/scripts/sessionstart-repo-status.py"
```

Apply the changes you want; commit them in your workspace's governance repo.

## Known trade-offs

- **`compact` mid-session pulls** can shift code under the agent's working assumptions. Accepted in exchange for currency. If you do not want this, drop the `compact` matcher from `agent-config/claude/settings.json`.
- **Sub-repo agents running in parallel** will see files change underneath them when the parent session pulls. Per-repo file locks prevent corruption of git state but not stale reads. In practice agents re-read files for each turn, so this is benign.
- **Rebase rewrites local commit SHAs.** Only ever applied to unpushed commits, but if you push the same branch to multiple remotes (forks), be aware that a SessionStart rebase against `@{u}` will diverge from the other remote.
- **Codex sessions in this workspace will not auto-pull.** The mechanism is intentionally Claude-Code-only as of codex v0.125.0 (see the note at the top of this document).
