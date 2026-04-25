# Agent Onboarding — SessionStart Auto-Pull

This template installs an automated **SessionStart auto-pull** system for AI coding agents (Claude Code and OpenAI Codex). On every session start (`startup`, `resume`, `clear`, and — for Claude — `compact`), the hook:

1. Runs `git fetch` across every direct sub-repo of the workspace root.
2. Fast-forwards or rebases each sub-repo as needed (no branching is ever performed).
3. Stashes any dirty working tree before pulling and restores it afterward.
4. Injects a concise status report into the agent's system context, surfacing any unpushed commits, conflicts, or unresolved issues for the agent's first turn.

A manual block flag (`/tmp/block-session-pull`) lets a human prevent any new agent session from starting until removed.

This is a **governance-grade development-lifecycle automation**: the script and configuration files belong under version control alongside your CLAUDE.md / AGENTS.md policy documents. The agent directories themselves (`.claude/`, `.codex/`) hold per-machine state and are *not* governance artifacts.

## Why this matters for SOC 2

Every agent session is guaranteed to begin from current code, with a deterministic snapshot of repo state captured in the session transcript. This is automated evidence that "agents always work against current code" — a useful artifact for change-management and configuration-management controls. The script is path-independent and reproducible across every developer machine that uses the workspace.

## Prerequisites

- A git-tracked **governance repository** at your workspace root (the directory that contains all your sub-repos as direct children). See `templates/governance/GOVERNANCE-SETUP.md` for setup.
- **Claude Code** with hooks support, and/or **OpenAI Codex CLI** with hooks support (`SessionStart` event).
- **Python 3** available on the developer's `PATH` (the script uses stdlib only — no extra dependencies).
- Git ≥ 2.30 recommended (the script uses `stash push -u -m`, `merge --ff-only @{u}`, and `pull --rebase`).

## Layout produced by this install

```
<workspace-root>/
├── scripts/
│   └── sessionstart-repo-status.py        ← shared script (governance-tracked)
├── agent-config/                          ← canonical config (governance-tracked)
│   ├── claude/
│   │   └── settings.json
│   └── codex/
│       └── config.toml
├── .claude/                               ← per-machine, gitignored
│   └── settings.json   → ../agent-config/claude/settings.json   (symlink)
└── .codex/                                ← per-machine, gitignored
    └── config.toml     → ../agent-config/codex/config.toml      (symlink)
```

The `scripts/` and `agent-config/` directories are tracked in git as part of your governance repo. The `.claude/` and `.codex/` directories contain only symlinks (and any per-machine local settings such as `.claude/settings.local.json`) and remain gitignored.

## Step 1: Copy the script and configs

From the trust portal's `templates/agent-onboarding/` directory into your workspace root:

```bash
WORKSPACE=~/Development            # adjust to wherever your governance repo is
TRUST_PORTAL=~/Development/ai-agent-first-trust-portal   # adjust if needed

mkdir -p "$WORKSPACE/scripts" "$WORKSPACE/agent-config/claude" "$WORKSPACE/agent-config/codex"

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

## Step 3: Wire up Codex

```bash
cp "$TRUST_PORTAL/templates/agent-onboarding/agent-config/codex/config.toml" \
   "$WORKSPACE/agent-config/codex/config.toml"

mkdir -p "$WORKSPACE/.codex"
ln -sfn ../agent-config/codex/config.toml "$WORKSPACE/.codex/config.toml"
```

If you already have a `.codex/config.toml` with other settings, merge the three `[[hooks.SessionStart]]` blocks from the template instead of replacing the file.

## Step 4: Update your `.gitignore`

In your workspace's `.gitignore`, the `scripts/` and `agent-config/` directories must be tracked, while `.claude/` and `.codex/` must remain ignored. Add (or confirm) these lines:

```gitignore
# Track agent-orchestration scripts (governance-tracked)
!scripts/
!scripts/**

# Track canonical agent configuration (governance-tracked).
# .claude/ and .codex/ themselves stay ignored — they hold symlinks to these
# canonical files plus per-machine state (settings.local.json, locks).
!agent-config/
!agent-config/**
```

## Step 5: Document the new behaviour

Add a bullet to your CLAUDE.md / AGENTS.md governance documents under your "Cross-Cutting Conventions" section so the agents themselves understand the system:

> **SessionStart auto-pull**: every Claude Code or Codex session started in this workspace runs `scripts/sessionstart-repo-status.py` before the agent's first turn. The script fetches every direct sub-repo, fast-forwards or rebases as needed, stashes and restores any dirty working tree (no branching is ever performed), and injects a concise status report into the agent's system context. Triggers on all SessionStart matchers (`startup`, `resume`, `clear`, `compact`). Conflicts that the script can't auto-resolve (rebase or stash-pop conflicts) are surfaced verbatim in the report for the agent to handle on its first turn. To pause all new agent sessions: `touch /tmp/block-session-pull`; resume with `rm /tmp/block-session-pull`. Before removing the block, check the status of all repos and any agents you have running to ensure things are in a consistent state.

## Step 6: Verify

Smoke test the install before relying on it:

```bash
# Dry-run with a synthetic CWD payload (no SessionStart event needed)
cd "$WORKSPACE"
echo '{"cwd": "'"$WORKSPACE"'", "session_id": "smoke-test", "hook_event_name": "SessionStart"}' \
  | python3 scripts/sessionstart-repo-status.py
```

Expected output:
- A `Repo status (auto-pull at session start, ...)` block listing pulled / ahead-only / no-upstream / needs-attention / locked / errors categories, OR
- No output at all if every sub-repo is already clean and in sync.

Test the block flag:

```bash
touch /tmp/block-session-pull
echo '{"cwd": "'"$WORKSPACE"'"}' | python3 scripts/sessionstart-repo-status.py ; echo "exit=$?"
# Expect exit=2 and a clear "SESSION BLOCKED" message on stderr.
rm /tmp/block-session-pull
```

Then start a real agent session and confirm the report appears in the system context (Claude Code: `/transcripts`).

## Step 7: Commit

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
| `FETCH_TIMEOUT_SECONDS` | 60 | Increase for large repos with slow remotes. The Claude/Codex hook timeout (90s) caps total wall time; with parallel workers you have headroom. |
| `MAX_WORKERS` | 8 | Increase if you have more than ~30 sub-repos and your network can handle the parallelism. |

## Updating to a newer template version

The `VERSION` file in this template directory is bumped whenever the canonical script or template structure changes meaningfully. To update an existing install:

```bash
diff "$TRUST_PORTAL/templates/agent-onboarding/scripts/sessionstart-repo-status.py" \
     "$WORKSPACE/scripts/sessionstart-repo-status.py"
```

Apply the changes you want; commit them in your workspace's governance repo.

## Known trade-offs

- **`compact` mid-session pulls** (Claude Code only) can shift code under the agent's working assumptions. Accepted in exchange for currency. If you do not want this, drop the `compact` matcher from `agent-config/claude/settings.json`.
- **Sub-repo agents running in parallel** will see files change underneath them when the parent session pulls. Per-repo file locks prevent corruption of git state but not stale reads. In practice agents re-read files for each turn, so this is benign.
- **Rebase rewrites local commit SHAs.** Only ever applied to unpushed commits, but if you push the same branch to multiple remotes (forks), be aware that a SessionStart rebase against `@{u}` will diverge from the other remote.
