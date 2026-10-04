#!/usr/bin/env bash
# Show or create the DNS records that validate the portal's Lightsail certificate.
#
#   bash deploy/aws/certificate-dns.sh --certificate-name <name> [--hosted-zone-id <zone-id>] [--region <region>]
#
# Without --hosted-zone-id it prints the CNAME records to create at your DNS
# provider. With it, it upserts them into that Route 53 hosted zone and waits
# for Route 53 to apply the change. Lightsail issues the certificate once the
# records resolve, usually within minutes; then set AttachCustomDomain=true.
# The certificate exists as soon as the stack's Certificate resource is
# created, so this can run while the rest of the stack is still being built.
set -euo pipefail
umask 077

CERTIFICATE=""
ZONE=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"

usage() {
    echo "usage: $0 --certificate-name <name> [--hosted-zone-id <zone-id>] [--region <region>]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --certificate-name) CERTIFICATE="${2:-}"; shift 2 ;;
        --hosted-zone-id) ZONE="${2:-}"; shift 2 ;;
        --region) REGION="${2:-}"; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$CERTIFICATE" ] && [ -n "$REGION" ] || usage

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

for attempt in $(seq 1 30); do
    aws lightsail get-certificates --region "$REGION" --certificate-name "$CERTIFICATE" \
        --include-certificate-details \
        --query 'certificates[0].certificateDetail.domainValidationRecords[].resourceRecord' \
        --output json > "$WORK/records.json"
    if [ "$(jq 'length' "$WORK/records.json")" -gt 0 ] && ! jq -e 'any(.[]; .value == null)' "$WORK/records.json" > /dev/null; then
        break
    fi
    [ "$attempt" -eq 30 ] && { echo "No validation records for $CERTIFICATE yet; run again shortly." >&2; exit 1; }
    sleep 10
done

if [ -z "$ZONE" ]; then
    echo "Create these records at your DNS provider:"
    jq -r '.[] | "\(.type)\t\(.name)\t\(.value)"' "$WORK/records.json"
    exit 0
fi

jq '{Comment: "Lightsail certificate validation", Changes: [.[] | {Action: "UPSERT",
      ResourceRecordSet: {Name: .name, Type: .type, TTL: 300, ResourceRecords: [{Value: .value}]}}]}' \
    "$WORK/records.json" > "$WORK/change-batch.json"
CHANGE=$(aws route53 change-resource-record-sets --hosted-zone-id "$ZONE" \
    --change-batch "file://$WORK/change-batch.json" --query 'ChangeInfo.Id' --output text)
echo "Route 53 change $CHANGE submitted; waiting for INSYNC"
aws route53 wait resource-record-sets-changed --id "$CHANGE"
aws lightsail get-certificates --region "$REGION" --certificate-name "$CERTIFICATE" \
    --query 'certificates[0].certificateDetail.[domainName, status]' --output text
