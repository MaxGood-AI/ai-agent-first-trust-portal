#!/usr/bin/env bash
# Create the portal's first compliance admin and save its API key to a file.
#
#   bash deploy/aws/bootstrap-admin.sh --stack <stack-name> --name "<full name>" --email <email> \
#       --key-file <path outside any git repository> [--region <region>]
#
# Calls POST /api/setup, which works only while no admin exists. The bootstrap
# token goes only in the "Authorization: Bearer" header; the body is
# {"name", "email"}. The token is read from the runtime secret through a pipe
# into a shell variable and handed to curl as a config on stdin by the printf
# builtin, so it never appears in a process listing, in shell history or on
# disk. The portal returns the API key once: this script writes it to
# --key-file (mode 600) and writes <key-file>.header holding the
# "X-API-Key: ..." line for curl -H @<file>, and prints only those paths.
#
# Exit status: 0 created; 1 rejected or unreachable; 2 usage.
set -euo pipefail
umask 077

STACK=""
NAME=""
EMAIL=""
KEY_FILE=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"

usage() {
    echo "usage: $0 --stack <stack-name> --name <full name> --email <email> --key-file <path> [--region <region>]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --stack) STACK="${2:-}"; shift 2 ;;
        --name) NAME="${2:-}"; shift 2 ;;
        --email) EMAIL="${2:-}"; shift 2 ;;
        --key-file) KEY_FILE="${2:-}"; shift 2 ;;
        --region) REGION="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$STACK" ] && [ -n "$NAME" ] && [ -n "$EMAIL" ] && [ -n "$KEY_FILE" ] && [ -n "$REGION" ] || usage
[ -e "$KEY_FILE" ] && { echo "$KEY_FILE already exists; refusing to overwrite it" >&2; exit 2; }
KEY_DIR=$(dirname "$KEY_FILE")
mkdir -p "$KEY_DIR"
if command -v git > /dev/null && git -C "$KEY_DIR" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    echo "$KEY_DIR is inside a git repository; choose a key file outside every repository" >&2
    exit 2
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK" \
    --query 'Stacks[0].Outputs' --output json > "$WORK/outputs.json"
URL=$(jq -r '.[] | select(.OutputKey == "PublicUrl") | .OutputValue' "$WORK/outputs.json")
SECRET=$(jq -r '.[] | select(.OutputKey == "PortalSecretArn") | .OutputValue' "$WORK/outputs.json")
SETUP_URL="${URL%/}/api/setup"

TOKEN=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$SECRET" \
    --query SecretString --output text | jq -r '.BOOTSTRAP_TOKEN // empty')
[ -n "$TOKEN" ] || { echo "the runtime secret has no BOOTSTRAP_TOKEN" >&2; exit 1; }
[[ "$TOKEN" =~ ^[A-Za-z0-9_-]+$ ]] || { echo "BOOTSTRAP_TOKEN has unexpected characters" >&2; exit 1; }

jq -n --arg name "$NAME" --arg email "$EMAIL" '{name: $name, email: $email}' > "$WORK/body.json"

code=$(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl --config - -sS \
    -o "$WORK/response.json" -w '%{http_code}' --max-time 30 \
    -H 'Content-Type: application/json' --data "@$WORK/body.json" "$SETUP_URL" || true)
unset TOKEN

detail() {
    jq -c 'del(.api_key?)' "$WORK/response.json" 2>/dev/null || head -c 300 "$WORK/response.json" 2>/dev/null || true
}

case "$code" in
    201)
        API_KEY=$(jq -r '.api_key // empty' "$WORK/response.json")
        if [ -z "$API_KEY" ]; then
            echo "201 from $SETUP_URL without an api_key" >&2
            exit 1
        fi
        printf '%s\n' "$API_KEY" > "$KEY_FILE"
        printf 'X-API-Key: %s\n' "$API_KEY" > "$KEY_FILE.header"
        unset API_KEY
        echo "Admin created: member_id $(jq -r '.member_id' "$WORK/response.json")"
        echo "API key saved to $KEY_FILE"
        echo "Request header line saved to $KEY_FILE.header"
        ;;
    401)
        echo "401: the portal rejected the bootstrap token. The running containers read the secret at start;" >&2
        echo "redeploy the current image if BOOTSTRAP_TOKEN changed since the last deployment, then retry." >&2
        exit 1
        ;;
    400)
        echo "400: the portal needs both a name and an email: $(detail)" >&2
        exit 1
        ;;
    404)
        echo "404: setup is closed because an admin already exists. Use an existing admin's API key." >&2
        exit 1
        ;;
    429)
        echo "429: too many failed setup attempts; wait before retrying." >&2
        exit 1
        ;;
    000)
        echo "Could not reach $SETUP_URL" >&2
        exit 1
        ;;
    *)
        echo "Unexpected $code from $SETUP_URL: $(detail)" >&2
        exit 1
        ;;
esac
