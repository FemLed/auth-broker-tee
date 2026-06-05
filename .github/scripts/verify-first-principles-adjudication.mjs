#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import { canonicalStringify } from "../../src/canonical-json.js";

const CONFIDENTIAL_SPACE_ISSUER = "https://confidentialcomputing.googleapis.com";
const CONFIDENTIAL_SPACE_AUDIENCE = "https://oauth-tee.femled.ai";

const args = new Map();
for (let i = 2; i < process.argv.length; i += 2) {
  args.set(process.argv[i], process.argv[i + 1]);
}

const responsePath = args.get("--response") || "first-principles-response.json";
const requestPath = args.get("--request") || "first-principles-request.json";
const requireApprove = process.argv.includes("--require-approve");

const response = JSON.parse(fs.readFileSync(responsePath, "utf8"));
const request = JSON.parse(fs.readFileSync(requestPath, "utf8"));
const expectedImageDigest = process.env.FIRST_PRINCIPLES_TEE_EXPECTED_IMAGE_DIGEST;
const expectedPromptDigest = process.env.FIRST_PRINCIPLES_EXPECTED_PROMPT_DIGEST;

if (!expectedImageDigest) {
  fail("FIRST_PRINCIPLES_TEE_EXPECTED_IMAGE_DIGEST is required so GitHub does not trust an arbitrary GCP-owner-controlled TEE");
}
if (!response.payload || !response.attestationToken) {
  fail("Adjudication response must include payload and attestationToken");
}

const payload = response.payload;
const failures = [];
const payloadDigest = sha256Digest(canonicalStringify(payload));
expectEqual("payloadDigest", response.payloadDigest, payloadDigest);
expectEqual("schema", payload.schema, "femled.first_principles.adjudication.v1");
expectEqual("repository", payload.repository, request.repository);
expectEqual("eventName", payload.eventName, request.eventName);
expectEqual("headSha", payload.headSha, request.headSha);
expectEqual("workflowRunId", String(payload.workflowRunId), String(request.workflowRunId));
expectEqual("nonce", payload.nonce, request.nonce);
expectEqual("diffDigest", payload.diffDigest, sha256Digest(request.diff));
expectEqual("changedFilesDigest", payload.changedFilesDigest, sha256Digest(canonicalStringify(request.changedFiles)));
if (request.complianceRulesDigest) expectEqual("complianceRulesDigest", payload.complianceRulesDigest, request.complianceRulesDigest);
if (expectedPromptDigest) expectEqual("promptDigest", payload.promptDigest, expectedPromptDigest);
if (payload.expiresAt && Date.parse(payload.expiresAt) < Date.now()) failures.push("adjudication expired");
if (!["APPROVE", "REQUEST_CHANGES"].includes(payload.decision)) failures.push("decision must be APPROVE or REQUEST_CHANGES");
if (requireApprove && payload.decision !== "APPROVE") failures.push(`TEE requested changes: ${payload.reasoning}`);

const attestation = await verifyConfidentialSpaceAttestation(response.attestationToken);
if (!nonceMatches(attestation.eat_nonce, payloadDigest)) failures.push("attestation nonce does not bind to payload digest");
if (attestation.submods?.container?.image_digest !== expectedImageDigest) {
  failures.push(`attested image digest mismatch: expected ${expectedImageDigest}, got ${attestation.submods?.container?.image_digest}`);
}
if (attestation.dbgstat !== "disabled-since-boot") failures.push("TEE debug status is not disabled-since-boot");
if (attestation.swname !== "CONFIDENTIAL_SPACE") failures.push("attestation is not for Confidential Space");

if (failures.length > 0) fail(failures.join("; "));

if (process.env.GITHUB_OUTPUT) {
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `decision=${payload.decision}\n`);
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `image_digest=${attestation.submods?.container?.image_digest || ""}\n`);
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `model=${payload.model || ""}\n`);
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `policy_version=${payload.policyVersion || ""}\n`);
}

console.log(`TEE First Principles decision verified: ${payload.decision}`);
console.log(`Reasoning: ${payload.reasoning}`);

function expectEqual(name, actual, expected) {
  if (actual !== expected) failures.push(`${name} mismatch: expected ${expected}, got ${actual}`);
}

function fail(message) {
  console.error(`::error::${message}`);
  process.exit(1);
}

function sha256Digest(input) {
  return `sha256:${crypto.createHash("sha256").update(input).digest("hex")}`;
}

async function verifyConfidentialSpaceAttestation(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) fail("attestationToken is not a JWT");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  const signedData = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], "base64url");

  const discoveryResp = await fetch("https://confidentialcomputing.googleapis.com/.well-known/openid-configuration");
  if (!discoveryResp.ok) fail(`Confidential Space OIDC discovery failed: ${discoveryResp.status}`);
  const discovery = await discoveryResp.json();
  const jwksResp = await fetch(discovery.jwks_uri);
  if (!jwksResp.ok) fail(`Confidential Space JWKS fetch failed: ${jwksResp.status}`);
  const jwks = await jwksResp.json();
  const jwk = jwks.keys.find((key) => key.kid === header.kid);
  if (!jwk) fail(`No Confidential Space JWKS key for kid ${header.kid}`);

  const valid = crypto.verify("RSA-SHA256", signedData, crypto.createPublicKey({ key: jwk, format: "jwk" }), signature);
  if (!valid) fail("Confidential Space attestation signature verification failed");
  if (payload.iss !== CONFIDENTIAL_SPACE_ISSUER) fail(`attestation iss mismatch: ${payload.iss}`);
  if (payload.aud !== CONFIDENTIAL_SPACE_AUDIENCE) fail(`attestation aud mismatch: ${payload.aud}`);
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) fail("attestation is expired");
  return payload;
}

function nonceMatches(eatNonce, expected) {
  if (Array.isArray(eatNonce)) return eatNonce.includes(expected);
  return eatNonce === expected;
}
