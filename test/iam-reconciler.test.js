import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { canonicalStringify, sha256Digest } from "../src/canonical-json.js";
import { createInMemoryGovernanceKeyMaterial } from "../src/governance-crypto.js";
import {
  signGenesisCertificate,
  signSuccessorCertificate,
} from "../src/governance-certificates.js";
import {
  buildTerraformInputs,
  parseArgs,
  renderTerraformVarsJson,
  validateGovernanceManifestForReconciliation,
} from "../scripts/reconcile-active-tee-iam.mjs";

test("IAM reconciler accepts active successor lineage with pinned predecessor", () => {
  const { manifest, successorImageDigest, predecessorLineageDigest } = successorManifest();

  const decision = validateGovernanceManifestForReconciliation(manifest, {
    expectedImageDigest: successorImageDigest,
    pinnedPredecessorLineageDigest: predecessorLineageDigest,
    minGovernanceEpoch: 2,
  });

  assert.equal(decision.status, "accepted");
  assert.equal(decision.activeImageDigest, successorImageDigest);
  assert.equal(decision.predecessorLineageDigest, predecessorLineageDigest);
  assert.equal(decision.epoch, 2);
});

test("IAM reconciler rejects inactive, wrong digest, and non-extending lineage", () => {
  const { manifest, predecessorImageDigest, successorImageDigest, predecessorLineageDigest } = successorManifest();

  assert.throws(
    () => validateGovernanceManifestForReconciliation({
      ...manifest,
      payload: { ...manifest.payload, status: "inactive" },
      payloadDigest: sha256Digest(canonicalStringify({ ...manifest.payload, status: "inactive" })),
    }, { expectedImageDigest: successorImageDigest }),
    /must be active/
  );
  assert.throws(
    () => validateGovernanceManifestForReconciliation(manifest, { expectedImageDigest: predecessorImageDigest }),
    /does not match expected/
  );
  assert.throws(
    () => validateGovernanceManifestForReconciliation(manifest, {
      expectedImageDigest: successorImageDigest,
      pinnedPredecessorLineageDigest: sha256Digest("wrong predecessor"),
    }),
    /does not match pinned/
  );
  assert.throws(
    () => validateGovernanceManifestForReconciliation(genesisManifest(), {
      requireSuccessorLineage: true,
    }),
    /requires successor lineage/
  );
  assert.throws(
    () => validateGovernanceManifestForReconciliation({
      ...manifest,
      payloadDigest: sha256Digest("not the payload"),
    }, { expectedImageDigest: successorImageDigest }),
    /payloadDigest mismatch/
  );
});

test("IAM reconciler emits Terraform inputs that promote active digest and clean candidates", () => {
  const active = digestOf("active-image");
  const stale = digestOf("stale-candidate");
  const inputs = buildTerraformInputs({
    activeImageDigest: active,
    candidateImageDigests: [stale, active, stale],
  });

  assert.deepEqual(inputs, {
    container_image_digest: active,
    candidate_image_digests: [stale],
  });
  assert.equal(renderTerraformVarsJson(inputs), `${JSON.stringify(inputs, null, 2)}\n`);
});

test("IAM reconciler requires explicit image or lineage pin unless overridden", () => {
  assert.throws(
    () => parseArgs(["--skip-verifier"]),
    /requires --expected-image-digest/
  );
  assert.equal(parseArgs(["--allow-unpinned-active", "--skip-verifier"]).allowUnpinnedActive, true);
});

test("IAM reconciler does not contain direct broad IAM mutation commands", () => {
  const script = fs.readFileSync("scripts/reconcile-active-tee-iam.mjs", "utf8");
  assert.doesNotMatch(script, /setIamPolicy/);
  assert.doesNotMatch(script, /add-iam-policy-binding/);
  assert.doesNotMatch(script, /roles\/iam\.serviceAccountAdmin/);
  assert.doesNotMatch(script, /roles\/owner|roles\/editor/);
});

function successorManifest() {
  const predecessorKeys = createInMemoryGovernanceKeyMaterial();
  const successorKeys = createInMemoryGovernanceKeyMaterial();
  const predecessorImageDigest = digestOf("predecessor-image");
  const successorImageDigest = digestOf("successor-image");
  const genesis = signGenesisCertificate({
    keyMaterial: predecessorKeys,
    imageDigest: predecessorImageDigest,
    routeRegistryStatus: {},
    now: new Date("2026-05-10T00:00:00Z"),
  });
  const successor = signSuccessorCertificate({
    keyMaterial: predecessorKeys,
    predecessorEpoch: 1,
    successorEpoch: 2,
    candidateImageDigest: successorImageDigest,
    candidateAttestationDigest: digestOf("candidate-attestation"),
    candidateAttestationNonce: digestOf("activation-nonce"),
    preapprovalPayloadDigest: digestOf("preapproval"),
    successorDecisionPacketDigest: digestOf("successor-decision"),
    successorArbitrationDigest: digestOf("successor-arbitration"),
    successorGovernancePublicKeyPem: successorKeys.governancePublicKeyPem,
    successorGovernanceKeyId: successorKeys.governanceKeyId,
    successorActivationPublicKeyPem: successorKeys.activationPublicKeyPem,
    now: new Date("2026-05-10T00:01:00Z"),
  });
  const lineage = [genesis, successor];
  const predecessorLineageDigest = sha256Digest(canonicalStringify([genesis]));
  const payload = {
    schema: "femled.tee.governance.manifest.v1",
    status: "active",
    epoch: 2,
    governanceKeyId: successorKeys.governanceKeyId,
    imageDigest: successorImageDigest,
    lineage,
    lineageDigest: sha256Digest(canonicalStringify(lineage)),
  };
  return {
    manifest: {
      payload,
      payloadDigest: sha256Digest(canonicalStringify(payload)),
      attestationToken: "test-only",
    },
    predecessorImageDigest,
    successorImageDigest,
    predecessorLineageDigest,
  };
}

function genesisManifest() {
  const keys = createInMemoryGovernanceKeyMaterial();
  const imageDigest = digestOf("genesis-image");
  const genesis = signGenesisCertificate({
    keyMaterial: keys,
    imageDigest,
    routeRegistryStatus: {},
    now: new Date("2026-05-10T00:00:00Z"),
  });
  const lineage = [genesis];
  const payload = {
    schema: "femled.tee.governance.manifest.v1",
    status: "active",
    epoch: 1,
    governanceKeyId: keys.governanceKeyId,
    imageDigest,
    lineage,
    lineageDigest: sha256Digest(canonicalStringify(lineage)),
  };
  return {
    payload,
    payloadDigest: sha256Digest(canonicalStringify(payload)),
    attestationToken: "test-only",
  };
}

function digestOf(value) {
  return sha256Digest(value);
}
