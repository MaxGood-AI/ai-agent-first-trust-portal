# Setting Up AI Agent Governance for SOC 2 Compliance

This guide walks you through setting up the CLAUDE.md and AGENTS.md governance documents for your organization. These files are formal SOC 2 policy documents that govern how AI coding agents (Claude Code, OpenAI Codex) behave in your development environment.

## Prerequisites

- **Trust Portal** deployed and running (see the main README)
- **KanbanZone** account with a board for tracking work
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

Create a root directory that will hold all your organization's repos, and initialize it as a git repository:

```bash
mkdir ~/Development
cd ~/Development
git init
```

Create a `.gitignore` that excludes all sub-repositories (your actual project repos):

```gitignore
# Exclude all directories (sub-repos)
*/

# But track governance files
!.gitignore
!CLAUDE.md
!AGENTS.md
!README.md
!.env
```

This governance repo tracks only the root-level policy files. Your actual project repos are cloned inside this directory but excluded from the governance repo's tracking.

## Step 2: Clone Trust Portal

Clone the Trust Portal repo into your development directory:

```bash
cd ~/Development
git clone <trust-portal-repo-url> trust-portal
```

## Step 3: Copy and Customize the Templates

Copy the template files to your development root:

```bash
cp trust-portal/templates/governance/CLAUDE.md.template ~/Development/CLAUDE.md
cp trust-portal/templates/governance/AGENTS.md.template ~/Development/AGENTS.md
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

## Step 5: Set Up KanbanZone Integration

1. Get your KanbanZone API key from Settings > Organization Settings > Integrations
2. Create a `.env` file in `~/Development`:

```bash
KANBANZONE_API_KEY=your-api-key
KANBANZONE_BOARD_ID=your-board-public-id
```

3. Install the `kanban-zone` Claude Skill (follow the skill's setup instructions)

The governance documents reference KanbanZone for card workflow, and the Trust Portal evidence chain tracks approved plans on KanbanZone cards.

## Step 6: Set Up the Decision Log Hook

The decision log captures every Claude Code session as formal compliance evidence. Set up the SessionEnd hook:

1. Create the hooks directory:

```bash
mkdir -p ~/Development/.claude/hooks
```

2. Create the export script at `~/Development/.claude/hooks/export-session.sh`:

```bash
#!/bin/bash
set -e

# Read session metadata from stdin
read -r INPUT
SESSION_ID=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('session_id',''))")
TRANSCRIPT=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('transcript_path',''))")
CWD=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('cwd',''))")
REASON=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('reason',''))")

# Only capture sessions from the development directory
DEV_DIR="$HOME/Development"
if [[ "$CWD" != "$DEV_DIR"* ]]; then
    exit 0
fi

# Skip if no transcript
if [ -z "$TRANSCRIPT" ] || [ ! -f "$TRANSCRIPT" ]; then
    exit 0
fi

# Copy transcript to trust-portal decision-logs/
DEST_DIR="$DEV_DIR/trust-portal/decision-logs"
mkdir -p "$DEST_DIR"

TIMESTAMP=$(date -u +"%Y-%m-%dT%H%M%SZ")
cp "$TRANSCRIPT" "$DEST_DIR/${TIMESTAMP}_${SESSION_ID}.jsonl"

# Write metadata sidecar
cat > "$DEST_DIR/${TIMESTAMP}_${SESSION_ID}.meta.json" << METAEOF
{
    "session_id": "$SESSION_ID",
    "cwd": "$CWD",
    "reason": "$REASON",
    "captured_at": "$TIMESTAMP"
}
METAEOF
```

3. Make it executable:

```bash
chmod +x ~/Development/.claude/hooks/export-session.sh
```

4. Configure Claude Code to use the hook. Create or update `~/Development/.claude/settings.json`:

```json
{
    "hooks": {
        "SessionEnd": [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": "/path/to/your/Development/.claude/hooks/export-session.sh",
                        "timeout": 5000
                    }
                ]
            }
        ]
    }
}
```

Replace `/path/to/your/Development` with the actual absolute path.

## Step 7: Commit and Verify

Commit the governance files to your governance repo:

```bash
cd ~/Development
git add CLAUDE.md AGENTS.md .gitignore
git commit -m "Add AI agent governance documents for SOC 2 compliance"
```

Verify the setup by starting a Claude Code session in `~/Development` and asking it to:
1. Read the CLAUDE.md and confirm it understands the conventions
2. Check that the KanbanZone skill can access your board
3. End the session and verify a transcript appears in `trust-portal/decision-logs/`

## Ongoing Maintenance

- **Policy changes** = git commits to CLAUDE.md or AGENTS.md. Each commit is a formal policy version.
- **Keep files in sync** — the Discrepancy Rule will catch drift, but proactively update both files together.
- **Review quarterly** — check that the governance documents still reflect your actual practices.
- **New repos** — add them to the Repository Map when created.
- **New team members** — point them to this setup guide. The governance files ensure every AI agent session follows the same compliance framework.
