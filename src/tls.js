import fs from "node:fs";
import crypto from "node:crypto";
import { fetchSecretValue, writeSecretValue } from "./gcp-auth.js";

const TLS_CERT_SECRET = process.env.TLS_CERT_SECRET;
const TLS_KEY_SECRET = process.env.TLS_KEY_SECRET;

export async function loadTlsCredentials() {
  if (process.env.TLS_CERT_PATH && process.env.TLS_KEY_PATH) {
    return {
      cert: fs.readFileSync(process.env.TLS_CERT_PATH, "utf8"),
      key: fs.readFileSync(process.env.TLS_KEY_PATH, "utf8"),
    };
  }

  if (!TLS_CERT_SECRET || !TLS_KEY_SECRET) {
    throw new Error(
      "TLS credentials not configured. Set TLS_CERT_SECRET and TLS_KEY_SECRET " +
        "(Secret Manager resource names) or TLS_CERT_PATH and TLS_KEY_PATH (file paths)."
    );
  }

  const [cert, key] = await Promise.all([
    fetchSecretValue(TLS_CERT_SECRET),
    fetchSecretValue(TLS_KEY_SECRET),
  ]);

  return { cert, key };
}

export function isCertExpiringSoon(certPem, thresholdDays = 30) {
  try {
    const x509 = new crypto.X509Certificate(certPem);
    const expiresAt = new Date(x509.validTo).getTime();
    const msRemaining = expiresAt - Date.now();
    const daysRemaining = msRemaining / (1000 * 60 * 60 * 24);
    return daysRemaining < thresholdDays;
  } catch {
    return true;
  }
}

export function getCertSecretName() {
  return TLS_CERT_SECRET;
}

export function getKeySecretName() {
  return TLS_KEY_SECRET;
}

export async function persistTlsCredentials(cert, key) {
  if (!TLS_CERT_SECRET || !TLS_KEY_SECRET) {
    console.log("[TLS] No Secret Manager paths configured, skipping persist");
    return;
  }

  const certSecretParent = TLS_CERT_SECRET.replace(/\/versions\/.*$/, "");
  const keySecretParent = TLS_KEY_SECRET.replace(/\/versions\/.*$/, "");

  await Promise.all([
    writeSecretValue(certSecretParent, cert),
    writeSecretValue(keySecretParent, key),
  ]);
}
