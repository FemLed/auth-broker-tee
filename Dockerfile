FROM node:20-alpine@sha256:f25b0e9d3d116e267d4ff69a3a99c0f4cf6ae94eadd87f1bf7bd68ea3ff0bef7

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --production --ignore-scripts && rm -rf /root/.npm /root/.cache /tmp/*

COPY src/ ./src/

ENV SOURCE_DATE_EPOCH=0
ENV NODE_ENV=production

# The governance key is generated in enclave memory; there is no KMS governance
# key and no state capsule. The OAuth redirect, scopes, project and route
# collection are image-PINNED: launch metadata is controlled by whoever
# administers the project, and an overridable redirect or scope set would let
# them divert users' authorization codes. Tenants also check these values in
# the attestation's container env.
ENV GCP_PROJECT_ID="prod-femled-couple-router"
ENV GCP_PROJECT_NUMBER="125139120897"
ENV AUTH_BROKER_ROUTE_FIRESTORE_COLLECTION="auth_broker_route_documents"
ENV REDIRECT_URI="https://oauth-tee.femled.ai/callback"
ENV GOOGLE_SCOPES="openid email profile https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/gmail.modify"

# Ephemeral in-enclave TLS trust roots, image-PINNED like the configuration
# above. The renewer signer key authenticates this caller to the
# authoritative-dns-tee renewer route for ACME DNS-01; the renewer is baked ON
# because in-enclave minting is mandatory (there is no Secret Manager TLS pair
# and no sealed capsule). TLS is EPHEMERAL: every cold boot mints a fresh cert
# in enclave memory and nothing is persisted, so a GCP project/org IAM owner has
# no TLS ciphertext to decrypt. A non-secret mint ledger (src/tls-mint-log.js)
# guards the Let's Encrypt weekly limit against reboot loops.
ENV RENEWER_KMS_SIGNER_KEY_VERSION="projects/prod-femled-couple-router/locations/us-west1/keyRings/auth-broker-acme-renewer/cryptoKeys/renewer-governance-signer/cryptoKeyVersions/1"
ENV ACME_RENEWER_ENABLED="true"

LABEL "tee.launch_policy.log_redirect"="never"
LABEL "tee.launch_policy.allow_cmd_override"="false"
# ACME_RENEWER_DRY_RUN is a toggle for staged validation via add-metadata. The
# REPLICA_* values only locate the other custody replica (src/governance-replica-
# custody.js): custody is granted on that replica's key-bound attestation, never
# on these values. None of them is a trust root (every trust-root value is
# image-baked above / in src).
LABEL "tee.launch_policy.allow_env_override"="ACME_RENEWER_DRY_RUN,REPLICA_ROLE,REPLICA_PEER_URL,REPLICA_PEER_INSTANCE"

# OCI source/revision labels so Cosign and the verifier can correlate
# image -> commit at a glance. COMMIT_SHA is set by the build-and-attest
# GHA workflow at build time. Local builds get a placeholder; the
# attestation predicate is the load-bearing source of truth.
ARG COMMIT_SHA=local
LABEL org.opencontainers.image.source="https://github.com/FemLed/auth-broker-tee"
LABEL org.opencontainers.image.revision="${COMMIT_SHA}"
LABEL org.opencontainers.image.title="femled-auth-broker-tee"
LABEL org.opencontainers.image.description="Hardware-sealed OAuth broker. See https://github.com/FemLed/auth-broker-tee/blob/main/VERIFICATION.md to verify."
LABEL org.opencontainers.image.licenses="PolyForm-Noncommercial-1.0.0"

EXPOSE 443
EXPOSE 8080

CMD ["node", "src/server.js"]