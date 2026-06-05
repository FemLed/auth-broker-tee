import { gunzipSync } from "node:zlib";
import { canonicalStringify, sha256Digest } from "./canonical-json.js";
import { getWifAccessToken } from "./gcp-auth.js";
import { buildSourceStructureEvidence } from "./source-structure-evidence.js";

const SOURCE_BEARING_PREFIXES = [
  "src/",
  "test/",
  ".github/scripts/",
  ".github/workflows/",
  ".compliance/",
  "verifier/",
];
const SOURCE_BEARING_FILES = new Set([
  "Dockerfile",
  "package.json",
  "package-lock.json",
]);

export const GOVERNANCE_CRITICAL_SOURCE_FILES = [
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
  "src/governance-routes.js",
  "src/governance-state.js",
  "src/governance-successor-decision.js",
  "src/route-registry.js",
  "src/server.js",
  "src/vertex-gemini.js",
  "verifier/main.go",
];

export async function inspectCandidateImageEvidence({
  candidateImageDigest,
  candidateImageReference = null,
  manifest = null,
  manifestDigest = null,
  config = null,
  sourceBundle = null,
  requireCompleteGovernanceCriticalSource = Boolean(sourceBundle?.requireCompleteGovernanceCriticalSource),
} = {}) {
  if (!isSha256Digest(candidateImageDigest)) {
    throw new Error("candidateImageDigest must be a sha256 digest");
  }

  let resolvedManifest = manifest;
  let resolvedConfig = config;
  if (!resolvedManifest && candidateImageReference) {
    const fetched = await fetchOciManifestByDigest(candidateImageReference, candidateImageDigest);
    resolvedManifest = fetched.manifest;
    manifestDigest = manifestDigest || fetched.manifestDigest;
    resolvedConfig = resolvedConfig || fetched.config;
  }

  const resolvedManifestDigest = manifestDigest || (resolvedManifest
    ? sha256Digest(canonicalStringify(resolvedManifest))
    : candidateImageDigest);
  if (resolvedManifest && resolvedManifestDigest !== candidateImageDigest) {
    throw new Error(`candidate manifest digest mismatch: expected ${candidateImageDigest}, got ${resolvedManifestDigest}`);
  }

  const normalizedSourceBundle = normalizeSourceBundle(sourceBundle || {});
  const sourceTreeDigest = sha256Digest(canonicalStringify(normalizedSourceBundle.sourceFiles));
  const sourceStructureEvidence = buildSourceStructureEvidence(normalizedSourceBundle.sourceFiles);
  const sourceStructureDigest = sha256Digest(canonicalStringify(sourceStructureEvidence));
  const criticalSourceCompleteness = buildCriticalSourceCompleteness(normalizedSourceBundle.sourceFiles);
  const filesystemDigest = sha256Digest(canonicalStringify({
    manifest: resolvedManifest || null,
    config: resolvedConfig || null,
    sourceFiles: normalizedSourceBundle.sourceFiles,
  }));
  const changedFiles = Object.keys(normalizedSourceBundle.sourceFiles).sort();
  const hardCheckResults = runGovernanceHardChecks({
    sourceFiles: normalizedSourceBundle.sourceFiles,
    config: resolvedConfig,
    selfHealingProposalDigest: sourceBundle?.selfHealingProposalDigest || null,
    sourceStructureEvidence,
    criticalSourceCompleteness,
    requireCompleteGovernanceCriticalSource,
  });

  return {
    candidateImageDigest,
    candidateImageReference,
    candidateManifestDigest: resolvedManifestDigest,
    candidateSourceTreeDigest: sourceTreeDigest,
    candidateFilesystemDigest: filesystemDigest,
    candidatePolicyManifestDigest: sourceBundle?.policyManifestDigest || null,
    candidatePromptDigest: sourceBundle?.promptDigest || null,
    candidateModelPolicyDigest: sourceBundle?.modelPolicyDigest || null,
    candidateModelProbeDigest: sourceBundle?.modelProbeDigest || null,
    candidateModelCatalogEvidenceDigest: sourceBundle?.modelCatalogEvidenceDigest || null,
    candidateModelPolicyDiffDigest: sourceBundle?.modelPolicyDiffDigest || null,
    candidateRouteTrustAnchorsDigest: sourceBundle?.routeTrustAnchorsDigest || null,
    candidateSourceStructureDigest: sourceStructureDigest,
    candidateSourceStructure: sourceStructureEvidence,
    criticalSourceCompleteness,
    selfHealingProposalDigest: sourceBundle?.selfHealingProposalDigest || null,
    candidateChangedFiles: changedFiles,
    manifest: resolvedManifest,
    config: resolvedConfig,
    hardCheckResults,
    sourceBundleDigest: sha256Digest(canonicalStringify(normalizedSourceBundle)),
    sourceBundleEvidence: normalizeSourceBundleEvidence(sourceBundle || {}),
  };
}

export function runGovernanceHardChecks({
  sourceFiles = {},
  config = null,
  selfHealingProposalDigest = null,
  sourceStructureEvidence = null,
  criticalSourceCompleteness = null,
  requireCompleteGovernanceCriticalSource = false,
} = {}) {
  const failures = [];
  const warnings = [];
  const sourceEntries = Object.entries(sourceFiles);

  if (sourceEntries.length === 0) {
    failures.push("candidate source bundle is empty; active TEE cannot inspect modification");
  }
  if (requireCompleteGovernanceCriticalSource && criticalSourceCompleteness?.status !== "complete") {
    failures.push(`candidate source bundle is missing governance-critical files: ${(criticalSourceCompleteness?.missingFiles || []).join(", ") || "unknown"}`);
  }

  for (const [path, content] of sourceEntries) {
    if (!isSourceBearingPath(path)) {
      warnings.push(`ignoring non-source-bearing file ${path}`);
      continue;
    }
    const structure = sourceStructureEvidence?.files?.find((file) => file.path === path);
    for (const envRead of structure?.envReads || []) {
      if (/^(TEE_GOVERNANCE_BOOTSTRAP|TEE_GOVERNANCE_MODE|GOVERNANCE_MODE)$/i.test(envRead.name)) {
        failures.push(`${path} reads ${envRead.name}, which could make governance mode environment-controlled`);
      }
      if (/GOVERNANCE_PRIVATE_KEY|SECRET_MANAGER.*GOVERNANCE/i.test(envRead.name)) {
        failures.push(`${path} reads ${envRead.name}, which could expose governance private material`);
      }
      if (/^FIRST_PRINCIPLES_(OIDC_AUDIENCE|REPOSITORY|WORKFLOW_REFS|WORKFLOW_REF)$/i.test(envRead.name)) {
        failures.push(`${path} reads ${envRead.name}, which could retarget first-principles trust roots`);
      }
      if (/^FIRST_PRINCIPLES_MODEL$/i.test(envRead.name)) {
        failures.push(`${path} reads ${envRead.name}, which could make model selection runtime-controlled`);
      }
    }
    for (const declaration of [
      ...(structure?.declarations || []),
      ...(structure?.exports || []),
    ]) {
      if (/breakGlass|ownerRecovery|adminRecovery|resetToGenesis|reset.*Genesis/i.test(declaration.name)) {
        failures.push(`${path} declares ${declaration.name}, which appears to add break-glass, owner recovery, admin recovery, or reset-to-genesis behavior`);
      }
      if (/governance[_-]?private[_-]?key|governanceSecret|exportGovernanceKey/i.test(declaration.name)) {
        failures.push(`${path} declares ${declaration.name}, which could expose governance private material`);
      }
    }
    if (!structure && !/\.(mjs|js)$/.test(path)) {
      const text = String(content);
      if (/BEGIN PRIVATE KEY/i.test(text)) {
        failures.push(`${path} contains private key material`);
      }
      if (/tee-env-(TEE_GOVERNANCE_BOOTSTRAP|TEE_GOVERNANCE_MODE|GOVERNANCE_MODE)/i.test(text)) {
        failures.push(`${path} appears to make governance mode launch-config controlled`);
      }
    }
  }

  const labels = config?.config?.Labels || config?.Labels || {};
  if (labels["tee.launch_policy.allow_cmd_override"] && labels["tee.launch_policy.allow_cmd_override"] !== "false") {
    failures.push("candidate image allows command override");
  }
  const allowedEnv = labels["tee.launch_policy.allow_env_override"] || "";
  if (/GOVERNANCE|PRIVATE|SECRET/i.test(allowedEnv)) {
    failures.push("candidate launch policy allows governance or secret env override");
  }
  if (selfHealingProposalDigest && !/^sha256:[a-f0-9]{64}$/i.test(selfHealingProposalDigest)) {
    failures.push("selfHealingProposalDigest must be a sha256 digest");
  }
  for (const file of sourceStructureEvidence?.governanceCriticalParseFailures || []) {
    failures.push(`${file} could not be parsed for governance-critical source structure evidence`);
  }
  for (const failure of sourceStructureEvidence?.parseFailures || []) {
    if (!failure.governanceCritical) {
      warnings.push(`${failure.file} could not be parsed for source structure evidence`);
    }
  }
  for (const finding of sourceStructureEvidence?.highRiskFindings || []) {
    warnings.push(`${finding.file} structure finding: ${finding.kind}`);
  }
  for (const hint of sourceStructureEvidence?.semanticRiskHints || []) {
    warnings.push(`${hint.file} semantic risk hint for Gemini review: ${hint.kind}`);
  }

  return {
    schema: "femled.tee.governance.hard_checks.v1",
    status: failures.length === 0 ? "passed" : "failed",
    failures,
    warnings,
    checkedAt: new Date().toISOString(),
  };
}

export function buildCriticalSourceCompleteness(sourceFiles = {}) {
  const present = GOVERNANCE_CRITICAL_SOURCE_FILES.filter((file) =>
    Object.prototype.hasOwnProperty.call(sourceFiles, file)
  );
  const missing = GOVERNANCE_CRITICAL_SOURCE_FILES.filter((file) =>
    !Object.prototype.hasOwnProperty.call(sourceFiles, file)
  );
  return {
    schema: "femled.tee.governance.critical_source_completeness.v1",
    status: missing.length === 0 ? "complete" : "incomplete",
    requiredFiles: GOVERNANCE_CRITICAL_SOURCE_FILES,
    presentFiles: present,
    missingFiles: missing,
  };
}

async function fetchOciManifestByDigest(imageReference, candidateImageDigest) {
  const parsed = parseImageReference(imageReference, candidateImageDigest);
  const token = await maybeGetRegistryToken(parsed.registry);
  const manifestResp = await fetch(`https://${parsed.registry}/v2/${parsed.repository}/manifests/${candidateImageDigest}`, {
    headers: {
      Accept: [
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
      ].join(", "),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    signal: AbortSignal.timeout(15000),
  });
  if (!manifestResp.ok) {
    throw new Error(`candidate image manifest fetch failed: ${manifestResp.status}`);
  }
  const manifestText = await manifestResp.text();
  const manifestDigest = sha256Digest(manifestText);
  const manifest = JSON.parse(manifestText);
  let config = null;
  if (manifest.config?.digest) {
    const configResp = await fetch(`https://${parsed.registry}/v2/${parsed.repository}/blobs/${manifest.config.digest}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      signal: AbortSignal.timeout(15000),
    });
    if (!configResp.ok) {
      throw new Error(`candidate image config fetch failed: ${configResp.status}`);
    }
    const bytes = Buffer.from(await configResp.arrayBuffer());
    config = JSON.parse(maybeGunzip(bytes).toString("utf8"));
  }
  return { manifest, manifestDigest, config };
}

function parseImageReference(imageReference, digest) {
  const withoutDigest = imageReference.includes("@")
    ? imageReference.slice(0, imageReference.indexOf("@"))
    : imageReference;
  const slash = withoutDigest.indexOf("/");
  if (slash <= 0) {
    throw new Error("candidateImageReference must include registry/repository");
  }
  return {
    registry: withoutDigest.slice(0, slash),
    repository: withoutDigest.slice(slash + 1).replace(/:[^/:]+$/, ""),
    digest,
  };
}

async function maybeGetRegistryToken(registry) {
  if (!registry.endsWith("pkg.dev")) return null;
  try {
    return await getWifAccessToken();
  } catch {
    return null;
  }
}

function maybeGunzip(bytes) {
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return gunzipSync(bytes);
  }
  return bytes;
}

function normalizeSourceBundle(sourceBundle) {
  const sourceFiles = {};
  const files = sourceBundle.files || sourceBundle.sourceFiles || {};
  for (const [path, content] of Object.entries(files)) {
    if (!isSourceBearingPath(path)) continue;
    sourceFiles[path] = String(content);
  }
  return {
    schema: "femled.tee.governance.source_bundle.v1",
    sourceFiles,
  };
}

function normalizeSourceBundleEvidence(sourceBundle) {
  return {
    schema: "femled.tee.governance.source_bundle_evidence.v1",
    complianceRulesDigest: sourceBundle.complianceRulesDigest || null,
    complianceSummaryDigest: sourceBundle.complianceSummaryDigest || null,
    complianceSummary: sourceBundle.complianceSummary || null,
    workflowRunId: sourceBundle.workflowRunId ? String(sourceBundle.workflowRunId) : null,
    headSha: sourceBundle.headSha || sourceBundle.sourceRevision || null,
    buildPredicateDigest: sourceBundle.buildPredicateDigest || null,
    provenanceDigest: sourceBundle.provenanceDigest || null,
    sourceImageBindingDigest: sourceBundle.sourceImageBindingDigest || null,
    imageSignatureDigest: sourceBundle.imageSignatureDigest || null,
    modelProbeDigest: sourceBundle.modelProbeDigest || null,
    modelCatalogEvidenceDigest: sourceBundle.modelCatalogEvidenceDigest || null,
    modelPolicyDiffDigest: sourceBundle.modelPolicyDiffDigest || null,
  };
}

function isSourceBearingPath(path) {
  return SOURCE_BEARING_FILES.has(path) || SOURCE_BEARING_PREFIXES.some((prefix) => path.startsWith(prefix));
}

function isSha256Digest(value) {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/i.test(value);
}