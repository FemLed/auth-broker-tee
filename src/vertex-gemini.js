import { GoogleGenAI } from "@google/genai";
import { canonicalStringify, sha256Digest } from "./canonical-json.js";
import { getProjectId, getWifAccessToken } from "./gcp-auth.js";
import {
  FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
  FIRST_PRINCIPLES_MODEL,
  FIRST_PRINCIPLES_MODEL_POLICY,
  FIRST_PRINCIPLES_RESPONSE_MIME_TYPE,
  FIRST_PRINCIPLES_RESPONSE_SCHEMA,
  FIRST_PRINCIPLES_VERTEX_LOCATION,
  isPermittedSuccessorModelCandidate,
} from "./first-principles-review.js";
import {
  isVertexCircuitOpen,
  recordModelProbe,
  recordVertexCall,
  recordVertexCircuitOpen,
  recordVertexRetryExhausted,
} from "./governance-monitor.js";

const MAX_VERTEX_ATTEMPTS = 3;
const BASE_RETRY_DELAY_MS = 500;
export const FIRST_PRINCIPLES_VERTEX_GOOGLE_SEARCH_TOOLS = Object.freeze([
  Object.freeze({ googleSearch: {} }),
]);

export async function generateFirstPrinciplesContent(prompt, {
  model = FIRST_PRINCIPLES_MODEL,
  probe = false,
  googleSearch = false,
} = {}) {
  if (isVertexCircuitOpen()) {
    const error = new Error("Vertex AI circuit breaker is open");
    recordVertexCircuitOpen({ model, reason: error.message });
    throw error;
  }

  const startedAt = Date.now();
  let lastError = null;
  let attemptsMade = 0;
  let exhaustedRetries = false;
  for (let attempt = 1; attempt <= MAX_VERTEX_ATTEMPTS; attempt += 1) {
    attemptsMade = attempt;
    try {
      const text = await generateOnce(prompt, { model, googleSearch });
      recordVertexCall({
        status: "success",
        durationMs: Date.now() - startedAt,
        retries: attempt - 1,
        model,
      });
      if (probe) recordModelProbe({ status: "success", model });
      return text;
    } catch (error) {
      lastError = error;
      const retryable = isRetryableVertexError(error);
      if (attempt >= MAX_VERTEX_ATTEMPTS || !retryable) {
        exhaustedRetries = retryable && attempt >= MAX_VERTEX_ATTEMPTS;
        break;
      }
      await sleep(BASE_RETRY_DELAY_MS * attempt);
    }
  }

  recordVertexCall({
    status: "failed",
    durationMs: Date.now() - startedAt,
    retries: Math.max(0, attemptsMade - 1),
    model,
    reason: lastError?.message || "unknown Vertex failure",
  });
  if (exhaustedRetries) {
    recordVertexRetryExhausted({ reason: lastError?.message || "unknown Vertex failure" });
  }
  if (probe) recordModelProbe({ status: "failed", model, reason: lastError?.message || "unknown Vertex failure" });
  throw lastError || new Error("Vertex AI generation failed");
}

export async function probeFirstPrinciplesModelCandidate(model) {
  if (!isPermittedSuccessorModelCandidate(model)) {
    recordModelProbe({ status: "failed", model, reason: "model does not match image-baked successor model constraints" });
    return {
      status: "rejected",
      model,
      reason: "model does not match image-baked successor model constraints",
    };
  }
  try {
    const text = await generateFirstPrinciplesContent(
      FIRST_PRINCIPLES_MODEL_POLICY.goldenProbe.prompt,
      { model, probe: true, googleSearch: true }
    );
    return {
      status: "passed",
      model,
      responseDigest: `sha256:${await digestText(text)}`,
    };
  } catch (error) {
    return {
      status: "failed",
      model,
      reason: error.message,
    };
  }
}

export async function listFirstPrinciplesModelCatalogCandidates() {
  const accessToken = await getWifAccessToken();
  const projectId = getProjectId();
  const models = [];
  let pageToken = "";
  do {
    const url = vertexPublisherModelCatalogUrl({ pageToken });
    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "x-goog-user-project": projectId,
      },
      signal: AbortSignal.timeout(15000),
    });
    if (!response.ok) {
      throw new Error(`Vertex model catalog fetch failed (${response.status}): ${await response.text()}`);
    }
    const body = await response.json();
    models.push(...(body.publisherModels || body.models || []));
    pageToken = body.nextPageToken || "";
  } while (pageToken);
  return models
    .map(normalizePublisherModel)
    .filter((model) => isPermittedSuccessorModelCandidate(model.model))
    .sort((a, b) => b.rank - a.rank || a.model.localeCompare(b.model));
}

async function generateOnce(prompt, { model, googleSearch = false }) {
  const accessToken = await getWifAccessToken();
  const genAI = new GoogleGenAI({
    vertexai: true,
    project: getProjectId(),
    location: FIRST_PRINCIPLES_VERTEX_LOCATION,
    googleAuthOptions: {
      scopes: ["https://www.googleapis.com/auth/cloud-platform"],
    },
    httpOptions: {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  });

  const response = await genAI.models.generateContent({
    model,
    contents: prompt,
    config: {
      temperature: FIRST_PRINCIPLES_GENERATION_TEMPERATURE,
      responseMimeType: FIRST_PRINCIPLES_RESPONSE_MIME_TYPE,
      responseSchema: FIRST_PRINCIPLES_RESPONSE_SCHEMA,
      ...(googleSearch ? { tools: FIRST_PRINCIPLES_VERTEX_GOOGLE_SEARCH_TOOLS } : {}),
    },
  });

  return response.text.trim();
}

export function vertexPublisherModelCatalogUrl({
  location = FIRST_PRINCIPLES_VERTEX_LOCATION,
  pageSize = 300,
  pageToken = "",
} = {}) {
  const host = location === "global"
    ? "https://aiplatform.googleapis.com"
    : `https://${location}-aiplatform.googleapis.com`;
  const params = new URLSearchParams({ pageSize: String(pageSize) });
  if (pageToken) params.set("pageToken", pageToken);
  return `${host}/v1beta1/publishers/google/models?${params}`;
}

function vertexPublisherModelBaseUrl() {
  const location = FIRST_PRINCIPLES_VERTEX_LOCATION;
  const host = location === "global"
    ? "https://aiplatform.googleapis.com"
    : `https://${location}-aiplatform.googleapis.com`;
  return `${host}/v1/projects/${getProjectId()}/locations/${location}`;
}

function normalizePublisherModel(model = {}) {
  const rawName = model.name || model.publisherModel || model.model || "";
  const id = String(rawName).split("/").pop();
  return {
    schema: "femled.tee.model_policy.catalog_candidate.v1",
    model: id,
    publisher: "google",
    displayName: model.displayName || model.versionId || id,
    versionId: model.versionId || null,
    launchStage: model.launchStage || model.state || null,
    supportedActions: model.supportedActions || [],
    rank: rankModelName(id),
    catalogDigest: sha256Digest(canonicalStringify(model)),
  };
}

function rankModelName(model) {
  const text = String(model || "").toLowerCase();
  const version = /gemini-([0-9]+)(?:[.-]([0-9]+))?/.exec(text);
  const major = Number.parseInt(version?.[1] || "0", 10);
  const minor = Number.parseInt(version?.[2] || "0", 10);
  const proWeight = /pro/.test(text) ? 100 : 0;
  const previewPenalty = /preview|experimental|exp/.test(text) ? -5 : 0;
  return major * 1000 + minor * 10 + proWeight + previewPenalty;
}

function isRetryableVertexError(error) {
  const message = error?.message || "";
  return /429|500|502|503|504|ECONNRESET|ETIMEDOUT|network|fetch/i.test(message);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function digestText(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

