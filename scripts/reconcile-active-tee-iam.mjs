#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalStringify, sha256Digest } from "../src/canonical-json.js";
import {
  GENESIS_SCHEMA,
  SUCCESSOR_SCHEMA,
  verifyLineage,
} from "../src/governance-certificates.js";

const DEFAULT_TEE_URL = "https://oauth-tee.femled.ai";
const DEFAULT_TERRAFORM_OUTPUT_PATH = "terraform/active-tee.reconciled.auto.tfvars.json";
const REPORT_SCHEMA = "femled.tee.iam_reconciliation.report.v1";
const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    console.log(usage());
    return;
  }

  const manifest = await fetchJson(`${options.teeUrl}/.well-known/femled-tee-governance.json`);
  const decision = validateGovernanceManifestForReconciliation(manifest, options);
  const verifier = options.skipVerifier
    ? { status: "skipped", warning: "manifest attestation was not independently verified" }
    : runExistingVerifier(options, decision.activeImageDigest);
  const terraformInputs = buildTerraformInputs({
    activeImageDigest: decision.activeImageDigest,
    candidateImageDigests: loadCandidateImageDigests(options),
  });

  const report = {
    schema: REPORT_SCHEMA,
    generatedAt: new Date().toISOString(),
    teeUrl: options.teeUrl,
    dryRun: !options.writeTfvarsJson,
    verifier,
    decision,
    terraformInputs,
    writePath: options.writeTfvarsJson || null,
  };

  if (options.writeTfvarsJson) {
    const outputPath = path.resolve(REPO_ROOT, options.writeTfvarsJson);
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, renderTerraformVarsJson(terraformInputs));
  }

  console.log(JSON.stringify(report, null, 2));
}

export function parseArgs(argv) {
  const options = {
    teeUrl: DEFAULT_TEE_URL,
    expectedImageDigest: "",
    pinnedGovernanceLineageDigest: "",
    pinnedPredecessorLineageDigest: "",
    minGovernanceEpoch: 0,
    requireSuccessorLineage: false,
    candidateImageDigests: [],
    terraformInputJson: "",
    writeTfvarsJson: "",
    verifierBin: "",
    verifierDir: "verifier",
    skipVerifier: false,
    allowUnpinnedActive: false,
    help: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      i += 1;
      if (i >= argv.length) throw new Error(`${arg} requires a value`);
      return argv[i];
    };
    if (arg === "--help" || arg === "-h") options.help = true;
    else if (arg === "--tee-url") options.teeUrl = stripTrailingSlash(next());
    else if (arg === "--expected-image-digest") options.expectedImageDigest = requireDigest(next(), arg);
    else if (arg === "--pinned-governance-lineage-digest") options.pinnedGovernanceLineageDigest = requireDigest(next(), arg);
    else if (arg === "--pinned-predecessor-lineage-digest") options.pinnedPredecessorLineageDigest = requireDigest(next(), arg);
    else if (arg === "--min-governance-epoch") options.minGovernanceEpoch = numberArg(arg, next());
    else if (arg === "--require-successor-lineage") options.requireSuccessorLineage = true;
    else if (arg === "--candidate-image-digest") options.candidateImageDigests.push(requireDigest(next(), arg));
    else if (arg === "--candidate-image-digests") options.candidateImageDigests.push(...parseDigestList(next(), arg));
    else if (arg === "--terraform-input-json") options.terraformInputJson = next();
    else if (arg === "--write-tfvars-json") options.writeTfvarsJson = next() || DEFAULT_TERRAFORM_OUTPUT_PATH;
    else if (arg === "--write-default-tfvars-json") options.writeTfvarsJson = DEFAULT_TERRAFORM_OUTPUT_PATH;
    else if (arg === "--verifier-bin") options.verifierBin = next();
    else if (arg === "--verifier-dir") options.verifierDir = next();
    else if (arg === "--skip-verifier") options.skipVerifier = true;
    else if (arg === "--allow-unpinned-active") options.allowUnpinnedActive = true;
    else throw new Error(`unknown argument: ${arg}`);
  }

  if (!options.help && !hasLineageOrImagePin(options)) {
    throw new Error("reconciliation requires --expected-image-digest, a lineage pin, or --allow-unpinned-active");
  }
  return options;
}

export function validateGovernanceManifestForReconciliation(manifest, {
  expectedImageDigest = "",
  pinnedGovernanceLineageDigest = "",
  pinnedPredecessorLineageDigest = "",
  minGovernanceEpoch = 0,
  requireSuccessorLineage = false,
} = {}) {
  if (!manifest?.payload || !manifest.payloadDigest) {
    throw new Error("governance manifest missing payload or payloadDigest");
  }
  const payloadDigest = sha256Digest(canonicalStringify(manifest.payload));
  if (payloadDigest !== manifest.payloadDigest) {
    throw new Error(`manifest payloadDigest mismatch: expected ${payloadDigest}, got ${manifest.payloadDigest}`);
  }
  if (manifest.payload.status !== "active") {
    throw new Error(`governance status must be active, got ${JSON.stringify(manifest.payload.status)}`);
  }
  const activeImageDigest = requireDigest(manifest.payload.imageDigest, "manifest imageDigest");
  if (expectedImageDigest && activeImageDigest !== expectedImageDigest) {
    throw new Error(`active image digest ${activeImageDigest} does not match expected ${expectedImageDigest}`);
  }
  if (!Array.isArray(manifest.payload.lineage) || manifest.payload.lineage.length === 0) {
    throw new Error("governance lineage missing");
  }
  const lineageDigest = sha256Digest(canonicalStringify(manifest.payload.lineage));
  if (lineageDigest !== manifest.payload.lineageDigest) {
    throw new Error(`lineageDigest mismatch: expected ${lineageDigest}, got ${manifest.payload.lineageDigest}`);
  }
  if (pinnedGovernanceLineageDigest && lineageDigest !== pinnedGovernanceLineageDigest) {
    throw new Error(`lineageDigest ${lineageDigest} does not match pinned ${pinnedGovernanceLineageDigest}`);
  }

  const lineage = verifyLineage(manifest.payload.lineage);
  if (manifest.payload.epoch !== lineage.currentEpoch) {
    throw new Error(`governance epoch mismatch: lineage has ${lineage.currentEpoch}, manifest has ${manifest.payload.epoch}`);
  }
  if (lineage.currentEpoch < minGovernanceEpoch) {
    throw new Error(`governance epoch ${lineage.currentEpoch} is below required minimum ${minGovernanceEpoch}`);
  }
  const mustExtendPredecessor = requireSuccessorLineage || Boolean(pinnedPredecessorLineageDigest);
  if (mustExtendPredecessor && manifest.payload.lineage.length < 2) {
    throw new Error("replacement reconciliation requires successor lineage");
  }
  if (pinnedPredecessorLineageDigest) {
    const predecessorLineageDigest = sha256Digest(canonicalStringify(manifest.payload.lineage.slice(0, -1)));
    if (predecessorLineageDigest !== pinnedPredecessorLineageDigest) {
      throw new Error(`predecessor lineage digest ${predecessorLineageDigest} does not match pinned ${pinnedPredecessorLineageDigest}`);
    }
  }

  const currentImageDigest = currentLineageImageDigest(lineage.certificates.at(-1));
  if (currentImageDigest !== activeImageDigest) {
    throw new Error(`lineage current image digest ${currentImageDigest} does not match manifest ${activeImageDigest}`);
  }
  const currentGovernanceKeyId = currentLineageGovernanceKeyId(lineage.certificates.at(-1));
  if (manifest.payload.governanceKeyId !== currentGovernanceKeyId) {
    throw new Error(`governanceKeyId mismatch: lineage has ${currentGovernanceKeyId}, manifest has ${manifest.payload.governanceKeyId}`);
  }

  return {
    status: "accepted",
    activeImageDigest,
    lineageDigest,
    predecessorLineageDigest: manifest.payload.lineage.length > 1
      ? sha256Digest(canonicalStringify(manifest.payload.lineage.slice(0, -1)))
      : null,
    epoch: lineage.currentEpoch,
    governanceKeyId: manifest.payload.governanceKeyId || null,
  };
}

export function buildTerraformInputs({ activeImageDigest, candidateImageDigests = [] } = {}) {
  const active = requireDigest(activeImageDigest, "activeImageDigest");
  const remainingCandidates = uniqueDigests(candidateImageDigests).filter((digest) => digest !== active);
  return {
    container_image_digest: active,
    candidate_image_digests: remainingCandidates,
  };
}

export function renderTerraformVarsJson(terraformInputs) {
  return `${JSON.stringify(terraformInputs, null, 2)}\n`;
}

function runExistingVerifier(options, activeImageDigest) {
  const args = [
    "--tee-url", options.teeUrl,
    "--pinned-image-digest", activeImageDigest,
  ];
  if (options.pinnedGovernanceLineageDigest) {
    args.push("--pinned-governance-lineage-digest", options.pinnedGovernanceLineageDigest);
  }
  if (options.pinnedPredecessorLineageDigest) {
    args.push("--pinned-predecessor-lineage-digest", options.pinnedPredecessorLineageDigest);
  }
  if (options.requireSuccessorLineage || options.pinnedPredecessorLineageDigest) {
    args.push("--require-successor-lineage");
  }
  if (options.minGovernanceEpoch > 0) {
    args.push("--min-governance-epoch", String(options.minGovernanceEpoch));
  }

  const verifierDir = path.resolve(REPO_ROOT, options.verifierDir);
  const command = options.verifierBin || "go";
  const commandArgs = options.verifierBin ? args : ["run", ".", ...args];
  const result = spawnSync(command, commandArgs, {
    cwd: options.verifierBin ? REPO_ROOT : verifierDir,
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`verifier failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return {
    status: "passed",
    command: [command, ...commandArgs].join(" "),
  };
}

async function fetchJson(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(60_000) });
  const text = await response.text();
  if (!response.ok) throw new Error(`${url} returned ${response.status}: ${text}`);
  return JSON.parse(text);
}

function loadCandidateImageDigests(options) {
  const fromArgs = uniqueDigests(options.candidateImageDigests);
  if (!options.terraformInputJson) return fromArgs;
  const inputPath = path.resolve(REPO_ROOT, options.terraformInputJson);
  const parsed = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  return uniqueDigests([
    ...fromArgs,
    ...(Array.isArray(parsed.candidate_image_digests) ? parsed.candidate_image_digests : []),
  ]);
}

function currentLineageImageDigest(certificate) {
  if (certificate?.schema === GENESIS_SCHEMA) return requireDigest(certificate.imageDigest, "genesis imageDigest");
  if (certificate?.schema === SUCCESSOR_SCHEMA) return requireDigest(certificate.candidateImageDigest, "successor candidateImageDigest");
  throw new Error(`unexpected terminal lineage schema ${certificate?.schema}`);
}

function currentLineageGovernanceKeyId(certificate) {
  if (certificate?.schema === GENESIS_SCHEMA) return requireDigest(certificate.governanceKeyId, "genesis governanceKeyId");
  if (certificate?.schema === SUCCESSOR_SCHEMA) return requireDigest(certificate.successorGovernanceKeyId, "successor governanceKeyId");
  throw new Error(`unexpected terminal lineage schema ${certificate?.schema}`);
}

function parseDigestList(value, label) {
  return String(value)
    .split(",")
    .map((digest) => digest.trim())
    .filter(Boolean)
    .map((digest) => requireDigest(digest, label));
}

function uniqueDigests(values) {
  return [...new Set((values || []).map((value) => requireDigest(value, "image digest")))];
}

function hasLineageOrImagePin(options) {
  return options.allowUnpinnedActive
    || options.expectedImageDigest
    || options.pinnedGovernanceLineageDigest
    || options.pinnedPredecessorLineageDigest;
}

function numberArg(label, value) {
  const number = Number.parseInt(value, 10);
  if (!Number.isInteger(number) || number < 0) throw new Error(`${label} must be a non-negative integer`);
  return number;
}

function requireDigest(value, label) {
  if (!isSha256Digest(value)) throw new Error(`${label} must be a sha256 digest`);
  return value.toLowerCase();
}

function isSha256Digest(value) {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/i.test(value);
}

function stripTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function usage() {
  return `Usage: node scripts/reconcile-active-tee-iam.mjs [options]

Fetches the live TEE governance manifest, verifies the active successor evidence,
and emits Terraform variable input that promotes the active image digest.

Safety pins (at least one required unless --allow-unpinned-active is set):
  --expected-image-digest <sha256>              Exact active image digest expected after handoff.
  --pinned-predecessor-lineage-digest <sha256>  Require lineage to extend this predecessor digest.
  --pinned-governance-lineage-digest <sha256>   Require exact current lineage digest.

Options:
  --tee-url <url>                               Default: ${DEFAULT_TEE_URL}
  --min-governance-epoch <n>                    Minimum accepted governance epoch.
  --require-successor-lineage                   Reject fresh genesis lineage.
  --candidate-image-digest <sha256>             Candidate digest to remove if now active. Repeatable.
  --candidate-image-digests <csv>               Comma-separated candidate digests.
  --terraform-input-json <path>                 Existing JSON tfvars input to read candidate list from.
  --write-tfvars-json <path>                    Write reconciled JSON tfvars to path.
  --write-default-tfvars-json                   Write ${DEFAULT_TERRAFORM_OUTPUT_PATH}.
  --verifier-bin <path>                         Existing verifier binary. Default: go run . in verifier/.
  --verifier-dir <path>                         Verifier source directory. Default: verifier
  --skip-verifier                               Unit-test/local-only escape hatch; leaves attestation unchecked.
  --allow-unpinned-active                       Permit reconciliation without an image or lineage pin.
`;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
