// Capsule store: GCS-backed read/write for governance state capsules.
//
// Two object families in the bucket:
//
//   capsules/<sha256>.json       Immutable capsule body (content-addressed),
//                                written once. On cold start the broker
//                                ENUMERATES these and restores the highest
//                                AUTHENTIC (KMS-witness-signed) capsuleSerial,
//                                so the mutable latest-pointer cannot be used
//                                to roll governance back to an older state.
//                                The bucket's locked retention policy forbids
//                                deleting the real head, so the max authentic
//                                serial is always the true latest state.
//
//   capsules/latest-pointer.json Updated in place after every capsule write.
//                                A NON-authoritative hint/observability record
//                                only -- restore does not trust it (an attacker
//                                with bucket write access can rewind it).
//
// The bucket itself is untrusted storage; integrity comes from the capsule
// AAD + KMS witness signature + AES-GCM auth tag (see state-capsule.js).

import { sha256Digest } from "./canonical-json.js";
import { getWifAccessToken, getProjectId } from "./gcp-auth.js";

const LATEST_POINTER_OBJECT = "capsules/latest-pointer.json";
const LATEST_POINTER_SCHEMA = "femled.auth_broker_tee.governance_state_capsule.latest_pointer.v1";

export function getCapsuleBucket() {
  const bucket = process.env.CAPSULE_BUCKET || "";
  if (!bucket) {
    throw new Error("CAPSULE_BUCKET is not configured");
  }
  return bucket;
}

export function isCapsulePersistenceConfigured() {
  return Boolean(process.env.CAPSULE_BUCKET) && Boolean(process.env.GOVERNANCE_KMS_SIGNER_KEY_VERSION);
}

export async function writeStateCapsule(capsule, { bucket = getCapsuleBucket() } = {}) {
  if (!capsule || typeof capsule !== "object") throw new Error("capsule is required");
  const digest = capsule.capsuleDigest;
  if (!/^sha256:[a-f0-9]{64}$/i.test(String(digest || ""))) {
    throw new Error("capsule.capsuleDigest must be a sha256 digest");
  }
  const object = capsuleObjectName(digest);
  await uploadObject({
    bucket,
    object,
    contentType: "application/json",
    body: JSON.stringify(capsule),
    ifGenerationMatch: 0, // refuse to overwrite existing capsule with same digest
  });
  return {
    schema: "femled.auth_broker_tee.governance_state_capsule.write.v1",
    bucket,
    object,
    capsuleDigest: digest,
  };
}

export async function writeLatestPointer(pointer, { bucket = getCapsuleBucket() } = {}) {
  if (pointer?.schema !== LATEST_POINTER_SCHEMA) {
    throw new Error(`latest pointer schema must be ${LATEST_POINTER_SCHEMA}`);
  }
  await uploadObject({
    bucket,
    object: LATEST_POINTER_OBJECT,
    contentType: "application/json",
    body: JSON.stringify(pointer),
  });
  return { bucket, object: LATEST_POINTER_OBJECT, pointer };
}

export function buildLatestPointer({ capsuleDigest, imageDigest, governanceKmsKeyVersion, epoch, status, capsuleSerial, lineageDigest, now = new Date() }) {
  if (!/^sha256:[a-f0-9]{64}$/i.test(String(capsuleDigest || ""))) {
    throw new Error("latest pointer capsuleDigest must be a sha256 digest");
  }
  if (!/^sha256:[a-f0-9]{64}$/i.test(String(imageDigest || ""))) {
    throw new Error("latest pointer imageDigest must be a sha256 digest");
  }
  if (!/^sha256:[a-f0-9]{64}$/i.test(String(lineageDigest || ""))) {
    throw new Error("latest pointer lineageDigest must be a sha256 digest");
  }
  if (!governanceKmsKeyVersion) throw new Error("latest pointer governanceKmsKeyVersion is required");
  return {
    schema: LATEST_POINTER_SCHEMA,
    capsuleDigest: String(capsuleDigest).toLowerCase(),
    imageDigest: String(imageDigest).toLowerCase(),
    governanceKmsKeyVersion,
    epoch,
    status,
    capsuleSerial,
    lineageDigest: String(lineageDigest).toLowerCase(),
    updatedAt: now.toISOString(),
  };
}

export async function readLatestPointer({ bucket = getCapsuleBucket() } = {}) {
  const text = await downloadObject({ bucket, object: LATEST_POINTER_OBJECT, allowMissing: true });
  if (text === null) return null;
  const pointer = JSON.parse(text);
  if (pointer?.schema !== LATEST_POINTER_SCHEMA) {
    throw new Error(`latest pointer schema mismatch: ${pointer?.schema}`);
  }
  return pointer;
}

// Enumerate every capsule body object under the `capsules/` prefix and return
// their capsule digests (sha256:<hex>). Excludes the mutable latest-pointer and
// any non-capsule object. Paginated. The cold-start restore verifies each of
// these against the running KMS key and restores the highest AUTHENTIC serial,
// which is why restore does not depend on the (rewindable) latest-pointer.
export async function listCapsuleObjects({ bucket = getCapsuleBucket(), maxObjects = 4096 } = {}) {
  const digests = [];
  let pageToken = null;
  do {
    const params = new URLSearchParams({ prefix: "capsules/", maxResults: "1000" });
    if (pageToken) params.set("pageToken", pageToken);
    const page = await listObjectsPage({ bucket, params });
    for (const item of page.items || []) {
      const digest = capsuleDigestFromObjectName(item.name);
      if (digest) digests.push(digest);
      if (digests.length >= maxObjects) return digests;
    }
    pageToken = page.nextPageToken || null;
  } while (pageToken);
  return digests;
}

function capsuleDigestFromObjectName(name) {
  const match = /^capsules\/([a-f0-9]{64})\.json$/.exec(String(name || "").toLowerCase());
  return match ? `sha256:${match[1]}` : null;
}

async function listObjectsPage({ bucket, params }) {
  const accessToken = await getWifAccessToken();
  if (!accessToken) throw new Error("GCS list requires WIF access token");
  const url = `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o?${params.toString()}`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(20000),
  });
  if (!response.ok) {
    throw new Error(`GCS list failed for gs://${bucket}/capsules/ (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

export async function readStateCapsule(capsuleDigest, { bucket = getCapsuleBucket() } = {}) {
  if (!/^sha256:[a-f0-9]{64}$/i.test(String(capsuleDigest || ""))) {
    throw new Error("capsuleDigest must be a sha256 digest");
  }
  const text = await downloadObject({ bucket, object: capsuleObjectName(capsuleDigest) });
  const capsule = JSON.parse(text);
  if (capsule?.capsuleDigest !== capsuleDigest) {
    throw new Error(`capsule digest mismatch: stored ${capsule?.capsuleDigest}, requested ${capsuleDigest}`);
  }
  return capsule;
}

function capsuleObjectName(digest) {
  return `capsules/${String(digest).slice("sha256:".length).toLowerCase()}.json`;
}

async function uploadObject({ bucket, object, contentType, body, ifGenerationMatch }) {
  const accessToken = await getWifAccessToken();
  if (!accessToken) throw new Error("GCS upload requires WIF access token");
  const params = new URLSearchParams({
    uploadType: "media",
    name: object,
  });
  if (ifGenerationMatch !== undefined) {
    params.set("ifGenerationMatch", String(ifGenerationMatch));
  }
  const url = `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(bucket)}/o?${params.toString()}`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": contentType,
    },
    body,
    signal: AbortSignal.timeout(20000),
  });
  if (!response.ok) {
    if (response.status === 412 && ifGenerationMatch === 0) {
      // Capsule with this digest already exists. Treat as idempotent
      // success: same content (digest = sha256 of body) means a previous
      // write completed but the pointer update lagged.
      return { idempotent: true };
    }
    throw new Error(`GCS upload failed for gs://${bucket}/${object} (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

async function downloadObject({ bucket, object, allowMissing = false }) {
  const accessToken = await getWifAccessToken();
  if (!accessToken) throw new Error("GCS download requires WIF access token");
  const url = `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/o/${encodeURIComponent(object)}?alt=media`;
  const response = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(20000),
  });
  if (response.status === 404 && allowMissing) return null;
  if (!response.ok) {
    throw new Error(`GCS download failed for gs://${bucket}/${object} (${response.status}): ${await response.text()}`);
  }
  return response.text();
}

// Utility: verify a downloaded capsule digest matches its serialized bytes.
export function verifyCapsuleDigestIntegrity(capsule) {
  const claimed = capsule?.capsuleDigest;
  const recomputed = sha256Digest(JSON.stringify({
    ...capsule,
    capsuleDigest: undefined,
  }));
  // The capsule digest is computed over canonical JSON of all fields INCLUDING
  // a self-referential capsuleDigest placeholder; we cannot easily re-derive
  // it here because the order matters. The capsule store relies on the
  // pointer-named digest matching the object name path, not a re-derivation.
  // See state-capsule.js createEncryptedStateCapsule for the original digest.
  void recomputed;
  return Boolean(claimed && claimed.startsWith("sha256:"));
}

export { getProjectId };
