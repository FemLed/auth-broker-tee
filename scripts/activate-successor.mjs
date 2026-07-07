#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const DEFAULT_TEE_URL = "https://oauth-tee.femled.ai";
const DEFAULT_IMAGE_REPOSITORY = "us-west1-docker.pkg.dev/prod-femled-couple-router/auth-broker/auth-broker-tee";
const GOVERNANCE_OIDC_AUDIENCE = "https://oauth-tee.femled.ai/governance";
const GOVERNANCE_CRITICAL_SOURCE_FILES = [
  "Dockerfile",
  "package.json",
  "package-lock.json",
  ".github/workflows/build-and-attest.yml",
  "src/attestation.js",
  "src/capsule-store.js",
  "src/confidential-space-attestation.js",
  "src/first-principles-adjudication.js",
  "src/first-principles-review.js",
  "src/gcp-auth.js",
  "src/governance-boundary.js",
  "src/governance-certificates.js",
  "src/governance-crypto.js",
  "src/governance-image-inspection.js",
  "src/governance-model-policy-supervisor.js",
  "src/governance-repair-contract.js",
  "src/governance-repair-jobs.js",
  "src/governance-repair-launcher.js",
  "src/governance-routes.js",
  "src/governance-self-improvement.js",
  "src/governance-state.js",
  "src/governance-successor-decision.js",
  "src/http-helpers.js",
  "src/kms-governance-key.js",
  "src/route-registry.js",
  "src/server.js",
  "src/state-capsule.js",
  "src/vertex-gemini.js",
  "verifier/main.go",
  "test/first-principles.test.js",
  "test/governance.test.js",
];

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log(usage());
    return;
  }
  const workDir = options.workDir || fs.mkdtempSync("/tmp/tee-successor-");
  fs.mkdirSync(workDir, { recursive: true });

  const candidateImageReference = `${options.imageRepository}@${options.imageDigest}`;
  const { manifest, manifestDigest, config } = await fetchOciEvidence({
    imageRepository: options.imageRepository,
    imageDigest: options.imageDigest,
  });
  const sourceBundle = buildSourceBundle({
    complianceSummaryPath: options.complianceSummary,
    workflowRunId: options.workflowRunId,
    imageDigest: options.imageDigest,
  });

  const preapprovalRequest = {
    candidateImageDigest: options.imageDigest,
    candidateImageReference,
    manifest,
    manifestDigest,
    config,
    sourceBundle,
  };
  writeJson(path.join(workDir, "preapprove-request.json"), preapprovalRequest);
  const preapprovalRequestDigest = sha256Digest(canonicalStringify(preapprovalRequest));
  const challenge = await fetchJson(`${options.teeUrl}/governance/challenge`, {
    method: "POST",
    headers: await governanceAuthHeaders(options),
    body: {
      purpose: "governance.preapprove",
      requestDigest: preapprovalRequestDigest,
    },
  });
  writeJson(path.join(workDir, "preapprove-challenge-response.json"), challenge);
  preapprovalRequest.governanceChallenge = challenge.challenge;
  const preapproval = await fetchJson(`${options.teeUrl}/governance/preapprove`, {
    method: "POST",
    headers: await governanceAuthHeaders(options),
    body: preapprovalRequest,
  });
  writeJson(path.join(workDir, "preapprove-response.json"), preapproval);
  if (preapproval.decision !== "APPROVE") {
    throw new Error(`preapproval did not approve: ${JSON.stringify(preapproval.aiDecision || preapproval)}`);
  }

  const predecessorGovernance = await fetchJson(`${options.teeUrl}/.well-known/femled-tee-governance.json`);
  writeJson(path.join(workDir, "predecessor-governance.json"), predecessorGovernance);

  const candidateGovernance = await fetchJson(`${options.teeUrl}/.well-known/femled-tee-governance.json`, {
    resolveIp: options.candidateIp,
  });
  writeJson(path.join(workDir, "candidate-governance.json"), candidateGovernance);
  const activationOffer = await fetchJson(`${options.teeUrl}/governance/activation-offer`, {
    method: "POST",
    headers: await governanceAuthHeaders(options),
    body: {
      preapprovalEnvelope: preapproval.preapproval,
      candidateGovernancePublicKeyPem: candidateGovernance.payload.governancePublicKeyPem,
      candidateActivationPublicKeyPem: candidateGovernance.payload.activationPublicKeyPem,
      candidateImageDigest: preapproval.candidate.candidateImageDigest,
    },
  });
  writeJson(path.join(workDir, "activation-offer-response.json"), activationOffer);

  const candidateAttestationToken = await fetchText(`${options.teeUrl}/attestation?nonce=${encodeURIComponent(activationOffer.activationNonce)}`, {
    resolveIp: options.candidateIp,
  });
  fs.writeFileSync(path.join(workDir, "candidate-attestation.jwt"), candidateAttestationToken);

  const activationComplete = await fetchJson(`${options.teeUrl}/governance/activation-complete`, {
    method: "POST",
    headers: await governanceAuthHeaders(options),
    body: {
      preapprovalEnvelope: preapproval.preapproval,
      candidate: preapproval.candidate,
      candidateAttestationToken,
      candidateGovernancePublicKeyPem: candidateGovernance.payload.governancePublicKeyPem,
      candidateGovernanceKeyId: candidateGovernance.payload.governanceKeyId,
      candidateActivationPublicKeyPem: candidateGovernance.payload.activationPublicKeyPem,
      activationNonce: activationOffer.activationNonce,
    },
  });
  writeJson(path.join(workDir, "activation-complete-response.json"), activationComplete);

  const activationApply = await fetchJson(`${options.teeUrl}/governance/activation-apply`, {
    method: "POST",
    resolveIp: options.candidateIp,
    headers: await governanceAuthHeaders(options),
    body: {
      successorCertificate: activationComplete.successorCertificate,
      encryptedState: activationComplete.encryptedState,
      activationNonce: activationOffer.activationNonce,
    },
  });
  writeJson(path.join(workDir, "activation-apply-response.json"), activationApply);

  const activationFinalize = await fetchJson(`${options.teeUrl}/governance/activation-finalize`, {
    method: "POST",
    headers: await governanceAuthHeaders(options),
    body: {
      activationProof: activationApply.activationProof,
    },
  });
  writeJson(path.join(workDir, "activation-finalize-response.json"), activationFinalize);

  console.log(JSON.stringify({
    schema: "femled.tee.activation_successor.report.v1",
    workDir,
    imageDigest: options.imageDigest,
    candidateIp: options.candidateIp,
    successorPayloadDigest: activationComplete.successorCertificate.payloadDigest,
    activationProofDigest: activationApply.activationProof.payloadDigest,
    finalizeStatus: activationFinalize.status,
    predecessorLineageDigest: predecessorGovernance.payload.lineageDigest,
    successorExpectedEpoch: Number(predecessorGovernance.payload.epoch || 0) + 1,
    postActivationIamReconciliation: {
      when: "after production traffic points at the active successor governance manifest",
      command: [
        "node scripts/reconcile-active-tee-iam.mjs",
        `--expected-image-digest ${options.imageDigest}`,
        `--pinned-predecessor-lineage-digest ${predecessorGovernance.payload.lineageDigest}`,
        `--min-governance-epoch ${Number(predecessorGovernance.payload.epoch || 0) + 1}`,
        `--candidate-image-digest ${options.imageDigest}`,
        "--write-default-tfvars-json",
      ].join(" \\\n  "),
      nextStep: "review the generated Terraform variables, then run terraform plan/apply from terraform/",
    },
  }, null, 2));
}

export function parseArgs(argv) {
  const options = {
    teeUrl: DEFAULT_TEE_URL,
    imageRepository: DEFAULT_IMAGE_REPOSITORY,
    workDir: "",
    workflowRunId: "",
    complianceSummary: "",
    governanceOidcToken: process.env.AUTH_BROKER_GOVERNANCE_OIDC_TOKEN || "",
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--tee-url") options.teeUrl = stripTrailingSlash(argv[++i]);
    else if (arg === "--candidate-ip") options.candidateIp = argv[++i];
    else if (arg === "--image-digest") options.imageDigest = argv[++i];
    else if (arg === "--image-repository") options.imageRepository = argv[++i];
    else if (arg === "--workflow-run-id") options.workflowRunId = argv[++i];
    else if (arg === "--compliance-summary") options.complianceSummary = argv[++i];
    else if (arg === "--governance-oidc-token") options.governanceOidcToken = argv[++i];
    else if (arg === "--work-dir") options.workDir = argv[++i];
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (!options.help) {
    if (!options.candidateIp) throw new Error("--candidate-ip is required");
    if (!isSha256Digest(options.imageDigest)) throw new Error("--image-digest must be a sha256 digest");
    if (!options.complianceSummary && !options.workflowRunId) {
      throw new Error("--compliance-summary or --workflow-run-id is required");
    }
  }
  return options;
}

async function governanceAuthHeaders(options) {
  const token = await getGovernanceOidcToken(options);
  return { Authorization: `Bearer ${token}` };
}

async function getGovernanceOidcToken(options) {
  if (options.governanceOidcToken) return options.governanceOidcToken;
  if (process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN && process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    return requestGitHubActionsOidcToken();
  }
  throw new Error(
    "governance OIDC token is required; run inside GitHub Actions with id-token: write or pass --governance-oidc-token / AUTH_BROKER_GOVERNANCE_OIDC_TOKEN"
  );
}

async function requestGitHubActionsOidcToken() {
  const url = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL);
  url.searchParams.set("audience", GOVERNANCE_OIDC_AUDIENCE);
  const response = await fetch(url, {
    headers: {
      Authorization: `bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`,
    },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    throw new Error(`GitHub Actions OIDC token request failed: ${response.status}`);
  }
  const payload = await response.json();
  if (!payload.value) {
    throw new Error("GitHub Actions OIDC token response did not include a token value");
  }
  return payload.value;
}

async function fetchOciEvidence({ imageRepository, imageDigest }) {
  const token = run("gcloud", ["auth", "print-access-token"]).trim();
  const [registry, ...repoParts] = imageRepository.split("/");
  const repository = repoParts.join("/");
  const base = `https://${registry}/v2/${repository}`;
  const manifestText = await fetchText(`${base}/manifests/${imageDigest}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
    },
  });
  const manifestDigest = sha256Digest(manifestText);
  if (manifestDigest !== imageDigest) {
    throw new Error(`manifest digest mismatch: expected ${imageDigest}, got ${manifestDigest}`);
  }
  const manifest = JSON.parse(manifestText);
  const configDigest = manifest.config?.digest;
  if (!configDigest) throw new Error("manifest missing config digest");
  const configText = await fetchText(`${base}/blobs/${configDigest}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const fetchedConfigDigest = sha256Digest(configText);
  if (fetchedConfigDigest !== configDigest) {
    throw new Error(`config digest mismatch: expected ${configDigest}, got ${fetchedConfigDigest}`);
  }
  return { manifest, manifestDigest, config: JSON.parse(configText) };
}

function buildSourceBundle({ complianceSummaryPath, workflowRunId, imageDigest }) {
  const complianceSummary = loadComplianceSummary({ complianceSummaryPath, workflowRunId });
  const headSha = run("git", ["rev-parse", "HEAD"]).trim();
  const files = {};
  for (const file of GOVERNANCE_CRITICAL_SOURCE_FILES) {
    if (fs.existsSync(file)) files[file] = fs.readFileSync(file, "utf8");
  }
  return {
    requireCompleteGovernanceCriticalSource: true,
    complianceRulesDigest: complianceSummary.compliance_rules_digest || null,
    complianceSummaryDigest: sha256Digest(canonicalStringify(complianceSummary)),
    complianceSummary,
    workflowRunId,
    headSha,
    buildPredicateDigest: sha256Digest(canonicalStringify({
      workflowRunId,
      imageDigest,
      complianceRulesDigest: complianceSummary.compliance_rules_digest || null,
    })),
    provenanceDigest: sha256Digest(canonicalStringify({
      workflowRunId,
      headSha,
    })),
    sourceImageBindingDigest: sha256Digest(canonicalStringify({
      sourceRevision: headSha,
      imageDigest,
    })),
    files,
  };
}

function loadComplianceSummary({ complianceSummaryPath, workflowRunId }) {
  if (complianceSummaryPath) return JSON.parse(fs.readFileSync(complianceSummaryPath, "utf8"));
  const dir = fs.mkdtempSync("/tmp/tee-compliance-summary-");
  run("gh", ["run", "download", workflowRunId, "--name", "compliance-summary", "--dir", dir]);
  return JSON.parse(fs.readFileSync(path.join(dir, "summary.json"), "utf8"));
}

async function fetchJson(url, { method = "GET", body = null, resolveIp = "", headers = {} } = {}) {
  const text = await fetchText(url, { method, body, resolveIp, headers: { "Content-Type": "application/json", ...headers } });
  return JSON.parse(text);
}

// Governance mutations through the active TEE include full-evidence Gemini
// arbitrations (image preapproval over the whole source bundle, activation
// acceptance) that routinely exceed 60s. Match coach-email-tee's
// activate-successor budget so a slow-but-healthy arbitration is not
// aborted mid-flight (the epoch-5 roll's first attempt died exactly here).
const GOVERNANCE_CALL_TIMEOUT_MS = 600_000;

async function fetchText(url, { method = "GET", body = null, resolveIp = "", headers = {} } = {}) {
  if (resolveIp) {
    const args = ["-fsS", "--max-time", String(GOVERNANCE_CALL_TIMEOUT_MS / 1000), "--resolve", `oauth-tee.femled.ai:443:${resolveIp}`];
    for (const [name, value] of Object.entries(headers)) args.push("-H", `${name}: ${value}`);
    if (method !== "GET") args.push("-X", method);
    if (body) args.push("--data-binary", JSON.stringify(body));
    args.push(url);
    return run("curl", args);
  }
  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
    signal: AbortSignal.timeout(GOVERNANCE_CALL_TIMEOUT_MS),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`${url} returned ${response.status}: ${text}`);
  return text;
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed: ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function canonicalize(value) {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  return Object.fromEntries(Object.keys(value).sort().filter((key) => value[key] !== undefined).map((key) => [key, canonicalize(value[key])]));
}

function canonicalStringify(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256Digest(value) {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function isSha256Digest(value) {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/i.test(value);
}

function stripTrailingSlash(value) {
  return String(value).replace(/\/+$/, "");
}

function usage() {
  return `Usage: node scripts/activate-successor.mjs --candidate-ip <ip> --image-digest <sha256:digest> [options]

Options:
  --tee-url <url>              Active predecessor TEE URL. Default: ${DEFAULT_TEE_URL}
  --image-repository <path>    Artifact Registry repository path. Default: ${DEFAULT_IMAGE_REPOSITORY}
  --workflow-run-id <id>       GitHub Actions run id containing compliance-summary artifact.
  --compliance-summary <path>  Local compliance summary JSON.
  --governance-oidc-token <t>  Governance-audience GitHub Actions OIDC token.
  --work-dir <path>            Directory to write request/response artifacts.
`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}