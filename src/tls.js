import crypto from "node:crypto";
import { fetchSecretByName, writeSecretValue } from "./gcp-auth.js";

const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID;
const TLS_CERT_SECRET_NAME = "auth-broker-tls-cert";
const TLS_KEY_SECRET_NAME = "auth-broker-tls-key";

export async function loadTlsCredentials() {
  try {
    const [cert, key] = await Promise.all([
      fetchSecretByName(TLS_CERT_SECRET_NAME),
      fetchSecretByName(TLS_KEY_SECRET_NAME),
    ]);

    return { cert, key };
  } catch (error) {
    throw new Error(`TLS credentials not configured in Secret Manager: ${error.message}`);
  }
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

export async function persistTlsCredentials(cert, key) {
  const certParent = `projects/${GCP_PROJECT_ID}/secrets/${TLS_CERT_SECRET_NAME}`;
  const keyParent = `projects/${GCP_PROJECT_ID}/secrets/${TLS_KEY_SECRET_NAME}`;

  await Promise.all([
    writeSecretValue(certParent, cert),
    writeSecretValue(keyParent, key),
  ]);
}
