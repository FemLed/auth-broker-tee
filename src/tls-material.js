// In-enclave TLS material holder (ephemeral -- no at-rest form).
//
// The leaf private key + cert chain live ONLY here, in process memory. There is
// NO sealed capsule and no Secret Manager copy: nothing is persisted to KMS,
// GCS, or disk, so a GCP project/org IAM owner has nothing to decrypt. The cert
// is minted fresh in-enclave on every cold boot (see acme-renewal.js
// bootstrapTls) and rotated in place on renewal via server.setSecureContext(),
// so renewals never need a VM reset. setSecureContext only affects NEW
// connections; established connections keep the previous cert until they close,
// which is acceptable for rotation.

import crypto from "node:crypto";

let current = null; // { keyPem, certPem, mintedAt }
let tlsServer = null;
let lastRotatedAt = null;

export function setTlsServer(server) {
  tlsServer = server;
}

export function adoptTlsMaterial({ keyPem, certPem, mintedAt = null }) {
  if (!keyPem || !certPem) throw new Error("adoptTlsMaterial requires keyPem and certPem");
  current = { keyPem, certPem, mintedAt: mintedAt || null };
  if (tlsServer) {
    tlsServer.setSecureContext({ key: keyPem, cert: certPem });
    lastRotatedAt = new Date().toISOString();
  }
  return current;
}

export function getCurrentTlsMaterial() {
  return current;
}

export function getCurrentCertExpiry() {
  if (!current?.certPem) return null;
  return certExpiryFromPem(current.certPem);
}

export function certExpiryFromPem(certPem) {
  try {
    const x509 = new crypto.X509Certificate(certPem);
    return new Date(x509.validTo);
  } catch {
    return null;
  }
}

export function getTlsMaterialStatus() {
  if (!current) return { adopted: false };
  return {
    adopted: true,
    mintedAt: current.mintedAt,
    expiresAt: getCurrentCertExpiry()?.toISOString() ?? null,
    lastRotatedAt,
  };
}

export function resetTlsMaterialForTests(next = null) {
  current = next;
  tlsServer = null;
  lastRotatedAt = null;
}
