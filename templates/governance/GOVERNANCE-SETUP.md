# Setting Up AI Agent Governance for SOC 2 Compliance

This guide walks you through setting up the CLAUDE.md and AGENTS.md governance documents for your organization. These files are formal SOC 2 policy documents that govern how AI coding agents (Claude Code, OpenAI Codex) behave in your development environment.

## Prerequisites

- **Trust Portal** deployed and running (see the main README)
- **Task board** (any work-tracking tool your agents can reach through an API) for tracking work items
- **Claude Code** installed on your development machine
- **Git** repositories for your platform's codebase

## What Are These Files?

| File | Read By | Purpose |
|------|---------|---------|
| **CLAUDE.md** | Claude Code | Governs Claude Code behavior specifically |
| **AGENTS.md** | All AI agents (Codex, Claude Code, etc.) | Governs all AI coding agents — includes the Codex Review Protocol |

Both files share most of their content. The key difference is that AGENTS.md includes the **Codex Review Protocol** section, which defines how independent code reviews are conducted by a second AI agent.

**These are not just documentation.** Every version of these files (tracked in git) is a formal policy version for SOC 2 audit purposes. Changes to these files are changes to compliance policy.

## Step 1: Create a Governance Repository

Choose a root directory that will hold all your organization's repos (the workspace root; any location works), set `WORKSPACE` to its path, and initialize it as a git repository. The commands below name every path from `$WORKSPACE`:

```bash
export WORKSPACE=/path/to/your/workspace
mkdir -p "$WORKSPACE"
cd "$WORKSPACE"
git init
```

Create a `.gitignore` that excludes all sub-repositories (your actual project repos):

```gitignore
# Exclude all directories (sub-repos)
*/

# Never track credentials
.env

# But track governance files
!.gitignore
!CLAUDE.md
!AGENTS.md
!README.md
```

This governance repo tracks only the root-level policy files. Your actual project repos are cloned inside this directory but excluded from the governance repo's tracking.

## Step 2: Clone Trust Portal

Clone the Trust Portal repo into your development directory:

```bash
cd "$WORKSPACE"
git clone <trust-portal-repo-url> trust-portal
```

## Step 3: Copy and Customize the Templates

Copy the template files to your development root:

```bash
cp "$WORKSPACE/trust-portal/templates/governance/CLAUDE.md.template" "$WORKSPACE/CLAUDE.md"
cp "$WORKSPACE/trust-portal/templates/governance/AGENTS.md.template" "$WORKSPACE/AGENTS.md"
```

Now edit both files and replace all placeholders:

### Required Placeholders

| Placeholder | What to fill in | Example |
|-------------|-----------------|---------|
| `{{ YEAR }}` | Current year | `2026` |
| `{{ LEGAL_ENTITY }}` | Your legal entity name | `Acme Corp Inc.` |
| `{{ PLATFORM_DESCRIPTION }}` | 2-3 sentence platform description | See template comments |
| `{{ DATABASE_CHANGE_POLICY }}` | Your DB change rules (or remove section) | See template comments |
| `{{ ARCHITECTURE_DIAGRAM }}` | ASCII diagram of your services | See template comments |
| `{{ LANGUAGE_CONVENTIONS }}` | Language-specific coding standards | See template comments |
| `{{ EXTERNAL_AUTOMATIONS }}` | External systems that touch your code/DB | See template comments |
| `{{ DOMAIN_TERMS }}` | Glossary of product-specific terms | See template comments |

### CUSTOMIZE Comment Blocks

Throughout the templates, `<!-- CUSTOMIZE: ... -->` comments provide guidance on what to write. **Remove the comment blocks** after filling in the content — they are instructions, not part of the final document.

### Keep Both Files In Sync

CLAUDE.md and AGENTS.md must contain identical content for all shared sections. The only difference is that AGENTS.md includes the **Codex Review Protocol** section. When you update one, update the other.

The **Discrepancy Rule** (included in both templates) instructs AI agents to flag any inconsistency between the two files.

## Step 4: Add Your Repositories to the Repository Map

Fill in the Repository Map table with every repo in your development environment. Group them logically:

```markdown
### Core Platform

| Repo | Tech | Purpose |
|------|------|---------|
| **my-backend** | Python/FastAPI, PostgreSQL | Backend API |
| **my-frontend** | React + TypeScript | Web application |
| **Trust Portal** | Python/Flask, PostgreSQL | SOC 2 trust portal. Port 5100. |

### Integrations

| Repo | Tech | Purpose |
|------|------|---------|
| **my-slack-bot** | Python/Flask | Slack integration |
```

## Step 5: Connect Your Task Board

1. Create an API credential for your task board
2. Add the board's credentials to a `.env` file in `$WORKSPACE`, for example:

```bash
TASK_BOARD_API_KEY=your-api-key
TASK_BOARD_ID=your-board-id
```

3. Install the agent integration for your task board (a skill, MCP server or CLI that reads these variables) and name it in the "Task Board Access" section of CLAUDE.md and AGENTS.md

The governance documents reference the task board for the work item workflow, and the Trust Portal evidence chain tracks approved plans on work items.

## Step 6: Set Up the Decision Log Hook

The decision log captures every Claude Code session as formal compliance evidence.

Every session transcript is uploaded to the trust portal by the SessionEnd hook that ships with the portal (`scripts/session-end-hook.sh`). It posts the transcript to `POST /api/decision-log/upload` and, when the portal is unreachable, keeps a copy under `decision-logs/.retry/` for a later upload.

1. Copy the hook into your governance repository:

```bash
mkdir -p "$WORKSPACE/.claude/hooks"
cp "$WORKSPACE/trust-portal/scripts/session-end-hook.sh" "$WORKSPACE/.claude/hooks/"
chmod +x "$WORKSPACE/.claude/hooks/session-end-hook.sh"
```

2. Give it the portal URL and an agent API key (issued in the portal under Admin > Team Members), for example in your shell profile:

```bash
export TRUST_PORTAL_API_URL=https://trust.example.com
export TRUST_PORTAL_API_KEY=<agent API key>
```

3. Configure Claude Code to run it at session end. Create or update `$WORKSPACE/.claude/settings.json` (hook timeouts are in seconds):

```json
{
    "hooks": {
        "SessionEnd": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "/path/to/your/workspace/.claude/hooks/session-end-hook.sh",
                        "timeout": 60
                    }
                ]
            }
        ]
    }
}
```

Replace `/path/to/your/workspace` with the absolute path in `$WORKSPACE` (`echo "$WORKSPACE"` prints it).

## Step 7: Commit and Verify

Commit the governance files to your governance repo:

```bash
cd "$WORKSPACE"
git add CLAUDE.md AGENTS.md .gitignore
git commit -m "Add AI agent governance documents for SOC 2 compliance"
```

Verify the setup by starting a Claude Code session in `$WORKSPACE` and asking it to:
1. Read the CLAUDE.md and confirm it understands the conventions
2. Check that the task-board integration can read a work item on your board
3. End the session and verify the session appears in the portal (`GET /api/decision-log/sessions`)

## Ongoing Maintenance

- **Policy changes** = git commits to CLAUDE.md or AGENTS.md. Each commit is a formal policy version.
- **Keep files in sync** — the Discrepancy Rule will catch drift, but proactively update both files together.
- **Review quarterly** — check that the governance documents still reflect your actual practices.
- **New repos** — add them to the Repository Map when created.
- **New team members** — point them to this setup guide. The governance files ensure every AI agent session follows the same compliance framework.
