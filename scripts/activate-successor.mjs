#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
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
  "src/governance-replica-custody.js",
  "src/governance-routes.js",
  "src/governance-self-improvement.js",
  "src/governance-state.js",
  "src/governance-successor-decision.js",
  "src/http-helpers.js",
  "src/route-registry.js",
  "src/server.js",
  "src/vertex-gemini.js",
  "verifier/main.go",
  "test/first-principles.test.js",
  "test/governance.test.js",
  "test/replica-custody.test.js",
];

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log(usage());
    return;
  }
  const workDir = options.workDir || fs.mkdtempSync("/tmp/tee-successor-");
  fs.mkdirSync(workDir, { recursive: true });
  const report = { schema: "femled.tee.activation_successor.report.v1", stage: options.stage, workDir };

  if (options.stage === "abort") {
    Object.assign(report, await abortStage(options, workDir));
  } else if (options.stage === "finalize") {
    Object.assign(report, await finalizeStage(options, workDir));
  } else {
    const handoff = await handoffStage(options, workDir);
    const predecessorEpoch = Number(handoff.predecessorGovernance.payload.epoch || 0);
    Object.assign(report, {
      imageDigest: options.imageDigest,
      candidateIp: options.candidateIp,
      successorPayloadDigest: handoff.successorPayloadDigest,
      activationProofDigest: handoff.activationProofDigest,
      predecessorLineageDigest: handoff.predecessorGovernance.payload.lineageDigest,
      successorExpectedEpoch: predecessorEpoch + 1,
      postActivationIamReconciliation: {
        when: "after production traffic points at the active successor governance manifest",
        command: [
          "node scripts/reconcile-active-tee-iam.mjs",
          `--expected-image-digest ${options.imageDigest}`,
          `--pinned-predecessor-lineage-digest ${handoff.predecessorGovernance.payload.lineageDigest}`,
          `--min-governance-epoch ${predecessorEpoch + 1}`,
          `--candidate-image-digest ${options.imageDigest}`,
          "--write-default-tfvars-json",
        ].join(" \\\n  "),
        nextStep: "review the generated Terraform variables, then run terraform plan/apply from terraform/",
      },
    });
    if (options.stage === "all") Object.assign(report, await finalizeStage(options, workDir));
  }
  console.log(JSON.stringify(report, null, 2));
}

async function handoffStage(options, workDir) {
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

  // The candidate proves, under its own key and a key-bound attestation, that
  // it holds the keys this offer names.
  const candidateReadiness = await fetchJson(`${options.teeUrl}/governance/activation-readiness`, {
    method: "POST",
    resolveIp: options.candidateIp,
    headers: await governanceAuthHeaders(options),
    body: { activationNonce: activationOffer.activationNonce },
  });
  writeJson(path.join(workDir, "activation-readiness-response.json"), candidateReadiness);

  const activationComplete = await fetchJson(`${options.teeUrl}/governance/activation-complete`, {
    method: "POST",
    headers: await governanceAuthHeaders(options),
    body: {
      preapprovalEnvelope: preapproval.preapproval,
      candidate: preapproval.candidate,
      candidateReadiness,
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
  return {
    predecessorGovernance,
    successorPayloadDigest: activationComplete.successorCertificate.payloadDigest,
    activationProofDigest: activationApply.activationProof?.payloadDigest || null,
  };
}

// Finalize from the saved handoff evidence. The successor's proof comes from
// the apply response or, if that was lost, from the successor itself; the
// predecessor accepts it after the successor certificate expired as long as
// the successor applied while it was valid.
async function finalizeStage(options, workDir) {
  readEvidence(workDir, "activation-complete-response.json");
  let activationProof = readEvidence(workDir, "activation-apply-response.json", { optional: true })?.activationProof;
  if (!activationProof) {
    if (!options.candidateIp) throw new Error("the apply response is missing; --candidate-ip is needed to fetch the successor's proof");
    const served = await fetchJson(`${options.teeUrl}/governance/activation-proof`, {
      resolveIp: options.candidateIp,
      headers: await governanceAuthHeaders(options),
    });
    writeJson(path.join(workDir, "activation-proof-response.json"), served);
    activationProof = served.activationProof;
  }
  const finalized = await fetchJson(`${options.teeUrl}/governance/activation-finalize`, {
    method: "POST",
    resolveIp: options.predecessorIp,
    headers: await governanceAuthHeaders(options),
    body: { activationProof },
  });
  writeJson(path.join(workDir, "activation-finalize-response.json"), finalized);
  return { finalizeStatus: finalized.status, activationProofDigest: activationProof.payloadDigest };
}

// Unwind a handoff whose candidate never applied: the candidate's decline, or
// (--expired, once the candidate is gone) the expiry of the pending certificate.
async function abortStage(options, workDir) {
  const { activationNonce } = readEvidence(workDir, "activation-offer-response.json");
  let body;
  if (options.expired) {
    body = { expired: true, activationNonce };
  } else {
    const declined = await fetchJson(`${options.teeUrl}/governance/activation-decline`, {
      method: "POST",
      resolveIp: options.candidateIp,
      headers: await governanceAuthHeaders(options),
      body: { activationNonce },
    });
    writeJson(path.join(workDir, "activation-decline-response.json"), declined);
    body = { decline: declined.decline };
  }
  const aborted = await fetchJson(`${options.teeUrl}/governance/activation-abort`, {
    method: "POST",
    resolveIp: options.predecessorIp,
    headers: await governanceAuthHeaders(options),
    body,
  });
  writeJson(path.join(workDir, "activation-abort-response.json"), aborted);
  return { abortStatus: aborted.status, abortReason: aborted.abortedActivation?.reason || null };
}

function readEvidence(workDir, name, { optional = false } = {}) {
  const file = path.join(workDir, name);
  if (!fs.existsSync(file)) {
    if (optional) return null;
    throw new Error(`${name} is missing from ${workDir}`);
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

export function parseArgs(argv) {
  const options = {
    stage: "all",
    teeUrl: DEFAULT_TEE_URL,
    imageRepository: DEFAULT_IMAGE_REPOSITORY,
    candidateIp: "",
    predecessorIp: "",
    expired: false,
    workDir: "",
    workflowRunId: "",
    complianceSummary: "",
    governanceOidcToken: process.env.AUTH_BROKER_GOVERNANCE_OIDC_TOKEN || "",
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--stage") options.stage = argv[++i];
    else if (arg === "--tee-url") options.teeUrl = stripTrailingSlash(argv[++i]);
    else if (arg === "--candidate-ip") options.candidateIp = argv[++i];
    else if (arg === "--predecessor-ip") options.predecessorIp = argv[++i];
    else if (arg === "--expired") options.expired = true;
    else if (arg === "--image-digest") options.imageDigest = argv[++i];
    else if (arg === "--image-repository") options.imageRepository = argv[++i];
    else if (arg === "--workflow-run-id") options.workflowRunId = argv[++i];
    else if (arg === "--compliance-summary") options.complianceSummary = argv[++i];
    else if (arg === "--governance-oidc-token") options.governanceOidcToken = argv[++i];
    else if (arg === "--work-dir") options.workDir = argv[++i];
    else throw new Error(`unknown argument: ${arg}`);
  }
  if (options.help) return options;
  if (!["all", "handoff", "finalize", "abort"].includes(options.stage)) {
    throw new Error("--stage must be all, handoff, finalize or abort");
  }
  for (const [flag, value] of [["--candidate-ip", options.candidateIp], ["--predecessor-ip", options.predecessorIp]]) {
    if (value && !/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) throw new Error(`${flag} must be an IPv4 address`);
  }
  if (options.stage === "all" || options.stage === "handoff") {
    if (!options.candidateIp) throw new Error("--candidate-ip is required");
    if (!isSha256Digest(options.imageDigest)) throw new Error("--image-digest must be a sha256 digest");
    if (!options.complianceSummary && !options.workflowRunId) {
      throw new Error("--compliance-summary or --workflow-run-id is required");
    }
  } else {
    if (!options.workDir) throw new Error(`--work-dir with the handoff evidence is required for --stage ${options.stage}`);
    if (options.stage === "abort" && !options.expired && !options.candidateIp) {
      throw new Error("--candidate-ip is required to ask the candidate to decline (or pass --expired)");
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

// Errors name the method, path and status and quote the response; request
// headers (the governance token) and bodies never appear in them.
async function fetchText(url, { method = "GET", body = null, resolveIp = "", headers = {} } = {}) {
  const target = new URL(url);
  const payload = body ? JSON.stringify(body) : null;
  const { status, text } = resolveIp
    ? await requestPinned(target, { method, headers, payload, address: resolveIp })
    : await requestDirect(target, { method, headers, payload });
  if (status < 200 || status >= 300) {
    throw new Error(`${method} ${target.pathname} returned ${status}: ${text.slice(0, 2000)}`);
  }
  return text;
}

async function requestDirect(target, { method, headers, payload }) {
  const response = await fetch(target, {
    method,
    headers,
    body: payload,
    signal: AbortSignal.timeout(GOVERNANCE_CALL_TIMEOUT_MS),
  });
  return { status: response.status, text: await response.text() };
}

// Talks to one TEE by address while TLS still verifies the certificate for
// the URL's host name.
function requestPinned(target, { method, headers, payload, address }) {
  return new Promise((resolve, reject) => {
    const request = https.request(target, {
      method,
      headers: payload ? { ...headers, "Content-Length": Buffer.byteLength(payload) } : headers,
      timeout: GOVERNANCE_CALL_TIMEOUT_MS,
      lookup: (_hostname, lookupOptions, callback) => (lookupOptions?.all
        ? callback(null, [{ address, family: 4 }])
        : callback(null, address, 4)),
    }, (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode, text: Buffer.concat(chunks).toString("utf8") }));
      response.on("error", (error) => reject(new Error(`${method} ${target.pathname} response failed: ${error.message}`)));
    });
    request.on("timeout", () => request.destroy(new Error("timed out")));
    request.on("error", (error) => reject(new Error(`${method} ${target.pathname} to ${address} failed: ${error.message}`)));
    if (payload) request.write(payload);
    request.end();
  });
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
  return `Usage: node scripts/activate-successor.mjs [--stage all|handoff|finalize|abort] [options]

Stages:
  all (default)  handoff, then finalize
  handoff        preapprove, offer, candidate readiness, complete, candidate apply
  finalize       finalize from the saved evidence (fetches the successor's proof if the apply response is missing)
  abort          the candidate declines, then the predecessor aborts; with --expired, abort an expired activation

Options:
  --tee-url <url>              TEE URL (host name for TLS). Default: ${DEFAULT_TEE_URL}
  --candidate-ip <ip>          Address of the candidate (successor) TEE.
  --predecessor-ip <ip>        Address of the predecessor, when the URL no longer resolves to it.
  --expired                    abort stage: abort without a decline once the pending certificate has expired.
  --image-digest <digest>      Candidate image digest (handoff).
  --image-repository <path>    Artifact Registry repository path. Default: ${DEFAULT_IMAGE_REPOSITORY}
  --workflow-run-id <id>       GitHub Actions run id containing compliance-summary artifact.
  --compliance-summary <path>  Local compliance summary JSON.
  --governance-oidc-token <t>  Governance-audience GitHub Actions OIDC token.
  --work-dir <path>            Directory for request/response evidence (required for finalize and abort).
`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}