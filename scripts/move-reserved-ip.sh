#!/usr/bin/env bash
# Moves oauth-tee.femled.ai's reserved address to a broker replica that already
# serves as the active primary. DNS is unchanged. Refuses unless the target
# answers on its own external address as an active primary on the expected
# image. Whoever holds the address now (a dead primary, typically) loses it.
#
#   bash scripts/move-reserved-ip.sh --to <vm> --to-zone <zone> --expect-digest sha256:...
set -euo pipefail

PROJECT="${GCP_PROJECT_ID:-prod-femled-couple-router}"
REGION="${RESERVED_ADDRESS_REGION:-us-west1}"
ADDRESS_NAME="${RESERVED_ADDRESS_NAME:-auth-broker-tee-oauth-ip}"
HOST=oauth-tee.femled.ai
TO=""
TO_ZONE=""
EXPECT_DIGEST=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --to) TO="$2"; shift 2 ;;
    --to-zone) TO_ZONE="$2"; shift 2 ;;
    --expect-digest) EXPECT_DIGEST="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
if [[ -z "$TO" || -z "$TO_ZONE" || ! "$EXPECT_DIGEST" =~ ^sha256:[a-f0-9]{64}$ ]]; then
  echo "usage: $0 --to <vm> --to-zone <zone> --expect-digest sha256:<64 hex>" >&2
  exit 2
fi

WANT="active primary ${EXPECT_DIGEST}"
serving_state() {
  curl -sS -m 10 ${1:+--resolve "${HOST}:443:$1"} "https://${HOST}/.well-known/femled-tee-governance.json" 2>/dev/null \
    | jq -r '"\(.payload.status) \(.payload.replica.role // "none") \(.payload.imageDigest)"' 2>/dev/null || true
}

IP=$(gcloud compute addresses describe "$ADDRESS_NAME" --region "$REGION" --project "$PROJECT" --format='value(address)')
TO_IP=$(gcloud compute instances describe "$TO" --zone "$TO_ZONE" --project "$PROJECT" \
  --format='value(networkInterfaces[0].accessConfigs[0].natIP)')
if [[ "$TO_IP" == "$IP" ]]; then
  echo "${TO} already holds ${IP}"
  exit 0
fi
state=$(serving_state "$TO_IP")
echo "${TO} (${TO_IP:-no external address}): ${state:-unreachable}"
if [[ "$state" != "$WANT" ]]; then
  echo "${TO} is not '${WANT}'; not moving the address" >&2
  exit 1
fi

holder=$(gcloud compute addresses describe "$ADDRESS_NAME" --region "$REGION" --project "$PROJECT" --format='value(users[0])')
TO_AC=$(gcloud compute instances describe "$TO" --zone "$TO_ZONE" --project "$PROJECT" \
  --format='value(networkInterfaces[0].accessConfigs[0].name)')

date -u +"move start %H:%M:%SZ"
if [[ -n "$TO_AC" ]]; then
  gcloud compute instances delete-access-config "$TO" --zone "$TO_ZONE" --project "$PROJECT" \
    --access-config-name "$TO_AC" --quiet
fi
if [[ -n "$holder" ]]; then
  holder_name="${holder##*/}"
  holder_zone=$(sed -E 's#.*/zones/([^/]+)/.*#\1#' <<<"$holder")
  holder_ac=$(gcloud compute instances describe "$holder_name" --zone "$holder_zone" --project "$PROJECT" \
    --format='value(networkInterfaces[0].accessConfigs[0].name)')
  gcloud compute instances delete-access-config "$holder_name" --zone "$holder_zone" --project "$PROJECT" \
    --access-config-name "$holder_ac" --quiet
fi
gcloud compute instances add-access-config "$TO" --zone "$TO_ZONE" --project "$PROJECT" \
  --access-config-name "${TO_AC:-external-nat}" --address "$IP" --quiet
date -u +"move end %H:%M:%SZ"
# The previous holder keeps an ephemeral address: a retired predecessor must
# stay reachable to finalize, and a restarted replica needs egress.
if [[ -n "$holder" ]]; then
  gcloud compute instances add-access-config "$holder_name" --zone "$holder_zone" --project "$PROJECT" \
    --access-config-name "${holder_ac:-external-nat}" --quiet || true
  echo "previous holder ${holder_name}: $(gcloud compute instances describe "$holder_name" --zone "$holder_zone" \
    --project "$PROJECT" --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
fi

for _ in $(seq 1 30); do
  state=$(serving_state "")
  echo "$(date -u +%H:%M:%S) ${HOST}: ${state:-unreachable}"
  [[ "$state" == "$WANT" ]] && exit 0
  sleep 5
done
echo "${HOST} did not serve ${TO} within 150 s" >&2
exit 1
