import fs from "node:fs";
import { fetchSecretValue } from "./gcp-auth.js";

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
