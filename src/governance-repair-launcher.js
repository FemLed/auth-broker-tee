import { existsSync } from "node:fs";
import { canonicalStringify } from "./canonical-json.js";
import { getProjectId, getWifAccessToken } from "./gcp-auth.js";
import {
  getPendingRepairJobsForLaunch,
  markRepairJobRunning,
} from "./governance-repair-jobs.js";

const REPAIR_JOB_NAME = "auth-broker-tee-repair-worker";
const REPAIR_JOB_REGION = "us-west1";
const REPAIR_CALLBACK_URL = "https://oauth-tee.femled.ai/governance/repair-artifact";
const REPAIR_REPO_OWNER = "FemLed";
const REPAIR_REPO_NAME = "auth-broker-tee";
const TEE_ATTESTATION_TOKEN_PATH = "/run/container_launcher/attestation_verifier_claims_token";

export async function launchPendingRepairJobs() {
  if (!existsSync(TEE_ATTESTATION_TOKEN_PATH)) return [];
  const launched = [];
  for (const job of getPendingRepairJobsForLaunch()) {
    await launchRepairJob(job);
    launched.push(markRepairJobRunning(job.jobId));
  }
  return launched;
}

export function buildRepairJobOverrides(job) {
  return {
    containerOverrides: [{
      env: [
        { name: "TEE_REPAIR_JOB_ID", value: job.jobId },
        { name: "TEE_REPAIR_PROPOSAL_DIGEST", value: job.proposalDigest },
        { name: "TEE_REPAIR_PROMPT", value: canonicalStringify(job.promptEnvelope) },
        { name: "TEE_REPAIR_PROMPT_DIGEST", value: job.promptDigest },
        { name: "TEE_REPAIR_CALLBACK_URL", value: REPAIR_CALLBACK_URL },
        { name: "TEE_REPAIR_CALLBACK_TOKEN", value: job.callbackToken },
        { name: "GITHUB_REPO_OWNER", value: REPAIR_REPO_OWNER },
        { name: "GITHUB_REPO_NAME", value: REPAIR_REPO_NAME },
      ],
    }],
    timeout: "5400s",
  };
}

async function launchRepairJob(job) {
  const accessToken = await getWifAccessToken();
  const url = `https://run.googleapis.com/v2/projects/${getProjectId()}/locations/${REPAIR_JOB_REGION}/jobs/${REPAIR_JOB_NAME}:run`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      overrides: buildRepairJobOverrides(job),
    }),
  });
  if (!response.ok) {
    throw new Error(`repair worker launch failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}
