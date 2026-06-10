// In-enclave TLS material holder.
//
// The leaf private key + cert chain live ONLY here (process memory) while the
// TEE runs; the sole at-rest form is the sealed capsule (tls-capsule.js).
// Rotation is in-process: adoptTlsMaterial() swaps the HTTPS listener's secure
// context via server.setSecureContext(), so renewals and lineage-driven
// re-mints never need a VM reset. setSecureContext only affects NEW
// connections; established connections keep the previous cert until they
// close, which is acceptable for rotation.
//
// `origin` records how the current material entered this enclave:
//   minted_in_enclave  this process performed the ACME order (fresh key)
//   carried_over       unsealed from the lineage capsule (predecessor's key,
//                      the successor-activation / restart carry-over path)
// Genesis enforcement keys off this: a genesis event must never inherit a
// carried-over cert (see acme-renewer-supervisor.js reconcileTlsWithLineage).

import crypto from "node:crypto";

let current = null; // { keyPem, certPem, mintedAt, lineageId, origin }
let tlsServer = null;
let lastRotatedAt = null;

export function setTlsServer(server) {
  tlsServer = server;
}

export function adoptTlsMaterial({ keyPem, certPem, mintedAt = null, lineageId = null }, { origin }) {
  if (!keyPem || !certPem) throw new Error("adoptTlsMaterial requires keyPem and certPem");
  if (origin !== "minted_in_enclave" && origin !== "carried_over") {
    throw new Error(`adoptTlsMaterial origin must be minted_in_enclave or carried_over, got ${origin}`);
  }
  current = { keyPem, certPem, mintedAt: mintedAt || null, lineageId: lineageId ?? null, origin };
  if (tlsServer) {
    tlsServer.setSecureContext({ key: keyPem, cert: certPem });
    lastRotatedAt = new Date().toISOString();
  }
  return current;
}

export function getCurrentTlsMaterial() {
  return current;
}

// Re-bind the in-memory material to a governance lineage anchor (the genesis
// certificate's governanceKeyId) once governance establishes it. The caller
// re-seals the capsule afterward so the at-rest AAD carries the same anchor.
export function setTlsLineageId(lineageId) {
  if (!current) return null;
  current.lineageId = lineageId ?? null;
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
    origin: current.origin,
    mintedAt: current.mintedAt,
    expiresAt: getCurrentCertExpiry()?.toISOString() ?? null,
    lineageId: current.lineageId,
    lastRotatedAt,
  };
}

export function resetTlsMaterialForTests(next = null) {
  current = next;
  tlsServer = null;
  lastRotatedAt = null;
}
