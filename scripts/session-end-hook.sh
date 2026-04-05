#!/bin/bash
# SessionEnd hook — uploads AI agent session transcripts to the trust portal.
#
# Install: configure in ~/.claude/settings.json under hooks.SessionEnd
#
# Required env vars (set in shell or sourced from .env):
#   TRUST_PORTAL_API_URL — trust portal base URL (e.g., https://trust.maxgood.work)
#   TRUST_PORTAL_API_KEY — API key for the submitting team member
#
# Claude Code passes session data via stdin as JSON with fields:
#   session_id, cwd, transcript_path, exit_reason
#
# Behavior:
#   1. Check if cwd starts with the configured dev directory (default ~/Development)
#   2. POST transcript JSONL to /api/decision-log/upload
#   3. On failure: copy to local staging directory for retry

set -euo pipefail

# Configurable base directory — only sessions under this path are captured
DEV_DIR="${TRUST_PORTAL_DEV_DIR:-${HOME}/Development}"
STAGING_DIR="${TRUST_PORTAL_STAGING_DIR:-${DEV_DIR}/decision-logs}"
RETRY_DIR="${STAGING_DIR}/.retry"

# Read hook input from stdin
INPUT=$(cat)

# Extract fields using Python (available on macOS)
SESSION_ID=$(echo "$INPUT" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('session_id', ''))" 2>/dev/null || echo "")
CWD=$(echo "$INPUT" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('cwd', ''))" 2>/dev/null || echo "")
TRANSCRIPT_PATH=$(echo "$INPUT" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('transcript_path', ''))" 2>/dev/null || echo "")
EXIT_REASON=$(echo "$INPUT" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('exit_reason', ''))" 2>/dev/null || echo "")

# Scope check: only process sessions under the dev directory
if [[ -z "$CWD" || "$CWD" != "${DEV_DIR}"* ]]; then
    exit 0
fi

# Verify transcript file exists
if [[ -z "$TRANSCRIPT_PATH" || ! -f "$TRANSCRIPT_PATH" ]]; then
    exit 0
fi

# Load config from environment, falling back to .env file
if [[ -z "${TRUST_PORTAL_API_URL:-}" || -z "${TRUST_PORTAL_API_KEY:-}" ]]; then
    ENV_FILE="${DEV_DIR}/.env"
    if [[ -f "$ENV_FILE" ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                TRUST_PORTAL_API_URL) TRUST_PORTAL_API_URL="$value" ;;
                TRUST_PORTAL_API_KEY) TRUST_PORTAL_API_KEY="$value" ;;
            esac
        done < <(grep -E '^TRUST_PORTAL_API_(URL|KEY)=' "$ENV_FILE" 2>/dev/null || true)
    fi
fi

TRUST_PORTAL_API_URL="${TRUST_PORTAL_API_URL:-}"
TRUST_PORTAL_API_KEY="${TRUST_PORTAL_API_KEY:-}"

# If no API config, fall back to local staging only
if [[ -z "$TRUST_PORTAL_API_URL" || -z "$TRUST_PORTAL_API_KEY" ]]; then
    mkdir -p "$STAGING_DIR"
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H%M%SZ")
    cp "$TRANSCRIPT_PATH" "${STAGING_DIR}/${TIMESTAMP}_${SESSION_ID}.jsonl"
    exit 0
fi

# Attempt upload
UPLOAD_URL="${TRUST_PORTAL_API_URL}/api/decision-log/upload?session_id=${SESSION_ID}&exit_reason=${EXIT_REASON}"

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "X-API-Key: ${TRUST_PORTAL_API_KEY}" \
    -H "Content-Type: application/jsonl" \
    --data-binary "@${TRANSCRIPT_PATH}" \
    --max-time 30 \
    "${UPLOAD_URL}" 2>/dev/null || echo "000")

if [[ "$HTTP_STATUS" == "200" ]]; then
    # Success — keep a local copy for backup
    mkdir -p "$STAGING_DIR"
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H%M%SZ")
    DEST="${STAGING_DIR}/${TIMESTAMP}_${SESSION_ID}"
    cp "$TRANSCRIPT_PATH" "${DEST}.jsonl"
    python3 -c "
import json, sys
meta = {'session_id': sys.argv[1], 'cwd': sys.argv[2], 'reason': sys.argv[3],
        'exported_at': sys.argv[4], 'uploaded': True}
with open(sys.argv[5], 'w') as f:
    json.dump(meta, f, indent=2)
" "$SESSION_ID" "$CWD" "$EXIT_REASON" "$TIMESTAMP" "${DEST}.meta.json" 2>/dev/null || true
else
    # Failure — stage for retry
    mkdir -p "$RETRY_DIR"
    TIMESTAMP=$(date -u +"%Y-%m-%dT%H%M%SZ")
    DEST="${RETRY_DIR}/${TIMESTAMP}_${SESSION_ID}"
    cp "$TRANSCRIPT_PATH" "${DEST}.jsonl"
    python3 -c "
import json, sys
meta = {'session_id': sys.argv[1], 'cwd': sys.argv[2], 'reason': sys.argv[3],
        'exported_at': sys.argv[4], 'uploaded': False, 'http_status': sys.argv[5]}
with open(sys.argv[6], 'w') as f:
    json.dump(meta, f, indent=2)
" "$SESSION_ID" "$CWD" "$EXIT_REASON" "$TIMESTAMP" "$HTTP_STATUS" "${DEST}.meta.json" 2>/dev/null || true
fi
