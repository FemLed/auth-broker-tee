#!/bin/sh
set -eu

echo "=== Auth Broker TEE Repair Worker ==="
echo "Job: ${TEE_REPAIR_JOB_ID:-unknown}"
echo "Proposal: ${TEE_REPAIR_PROPOSAL_DIGEST:-unknown}"
echo "Repo: ${GITHUB_REPO_OWNER:-FemLed}/${GITHUB_REPO_NAME:-auth-broker-tee}"

for required in \
  TEE_REPAIR_JOB_ID \
  TEE_REPAIR_PROPOSAL_DIGEST \
  TEE_REPAIR_PROMPT \
  TEE_REPAIR_PROMPT_DIGEST \
  TEE_REPAIR_CALLBACK_URL \
  TEE_REPAIR_CALLBACK_TOKEN
do
  eval "value=\${$required:-}"
  if [ -z "$value" ]; then
    echo "Missing required repair-worker environment variable: ${required}" >&2
    exit 1
  fi
done

exec python3 /usr/local/bin/repair-worker-run.py
