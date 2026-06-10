// In-TEE collector that gathers the proposed-change evidence DIRECTLY FROM GITHUB.
//
// The adjudicator must never trust a caller-supplied diff. A CI run only *claims*
// a commit SHA; this collector independently verifies that commit exists in the
// repo and pulls the real diff + the full contents of the changed files from
// GitHub (the independent source of truth), then canonicalizes and sha256
// digest-pins everything so the reviewed artifact is verifiable.
//
// The auth-broker holds the FemLed GitHub App private key itself, so it mints its
// OWN short-lived, read-only installation token in-process (no broker round-trip)
// via createGitHubRepoInstallationToken.
//
// Because Git commit SHAs are content-addressed, reviewing the tree at
// `commitSha` is provably the same bytes the merged/deployed tree carries.
//
// Mirrors the authoritative-dns-tee / tenant-adjudicator-tee evidence pattern:
// tight network timeouts, never throw past the boundary, return
// { present, content, digest, error }.

import { canonicalStringify, sha256Digest } from "./canonical-json.js";

const GITHUB_API = "https://api.github.com";
const DEFAULT_TIMEOUT_MS = 12000;
// Fail-closed payload guards (NOT content truncation): the reviewer model has a
// large context window, so the diff and changed files are sent in FULL. These
// generous ceilings exist only so a pathologically large change cannot exhaust
// TEE memory -- when one is exceeded the collector FAILS CLOSED (throws ->
// present:false -> no adjudication) rather than silently truncating the evidence
// the reviewer must see. A change that fits these guards but still overflows the
// model's context window fails closed on the Gemini call itself.
const MAX_CHANGED_FILES = 1000;
const MAX_DIFF_BYTES = 4 * 1024 * 1024;
const MAX_TOTAL_SOURCE_BYTES = 8 * 1024 * 1024;

// Files whose FULL contents (not just the patch) the TEE pulls so Gemini and any
// deterministic checks can review the whole file at the reviewed commit, not just
// the changed hunks. Covers infrastructure/deploy files AND application/business
// logic source (where most product-mission and broker-trust signal lives).
const FULL_CONTENT_PATTERN =
  /(\.(tf|tfvars|js|mjs|cjs|ts|tsx|jsx|go|py|rb|rs|java|kt|swift|sh|sql|json|ya?ml|toml)|(^|\/)Dockerfile|(^|\/)cloudbuild\.ya?ml)$/i;
// Noise that is never useful as whole-file review context (lockfiles, minified
// bundles, source maps) and would only burn the byte budget.
const FULL_CONTENT_EXCLUDE = /((^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock)|\.min\.(js|css)|\.map)$/i;
// Vendored dependencies and build/artifact output are dropped from the review
// ENTIRELY (not counted, diffed, or content-pulled). These directories hold
// third-party libraries (which the reviewer model already knows) and compiled
// artifacts -- e.g. .terraform provider binaries, node_modules, .venv, dist/build
// -- so a repo that commits them cannot blow the model's context window or trip
// the fail-closed payload guards. Proprietary source and dependency manifests
// (package.json, requirements.txt, go.mod, lockfiles) live OUTSIDE these dirs and
// are still reviewed; lockfile content changes remain visible in the diff.
const REVIEW_EXCLUDE_PATH =
  /(^|\/)(node_modules|\.terraform|\.venv|venv|vendor|__pycache__|dist|build|out|coverage|\.next|\.nuxt|\.svelte-kit|target|\.git)(\/|$)/i;
const SHA_PATTERN = /^[0-9a-f]{7,40}$/i;

export const GITHUB_SOURCE_EVIDENCE_SCHEMA = "femled.auth_broker_tee.github_source_evidence.v1";

// Default token minter: the broker holds the GitHub App key, so it mints its own
// read-only installation token in-process. Lazy import avoids a module cycle
// (routes.js pulls in many broker modules).
async function defaultGetToken(repoOwner, repoName, { permissions = { contents: "read" } } = {}) {
  const { createGitHubRepoInstallationToken } = await import("./routes.js");
  const { tokenData } = await createGitHubRepoInstallationToken({ owner: repoOwner, repo: repoName, permissions });
  if (!tokenData?.token) throw new Error("installation token response missing token");
  return tokenData.token;
}

export async function collectGitHubSourceEvidence({
  repoOwner,
  repoName,
  commitSha,
  baseSha = null,
  getToken = defaultGetToken,
  fetchImpl = fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
} = {}) {
  try {
    if (!repoOwner || !repoName) throw new Error("repoOwner and repoName are required");
    if (!SHA_PATTERN.test(String(commitSha || ""))) throw new Error("commitSha must be a git SHA the TEE can resolve");

    const token = await getToken(repoOwner, repoName, { permissions: { contents: "read" }, fetchImpl });
    const headers = {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "auth-broker-tee",
    };

    // 1. Independently verify the claimed commit exists in THIS repo.
    const commit = await ghJson(fetchImpl, `${GITHUB_API}/repos/${repoOwner}/${repoName}/commits/${commitSha}`, headers, timeoutMs);
    if (commit.sha !== commitSha) {
      throw new Error("GitHub returned a different commit sha than requested");
    }
    const treeSha = commit.commit?.tree?.sha || null;

    // 2. Pull the real changed-file set + patches. Diff against the base when
    //    known; otherwise use the commit's own file set.
    let allRawFiles;
    if (baseSha && SHA_PATTERN.test(baseSha) && baseSha !== commitSha) {
      const compare = await ghJson(fetchImpl, `${GITHUB_API}/repos/${repoOwner}/${repoName}/compare/${baseSha}...${commitSha}`, headers, timeoutMs);
      allRawFiles = Array.isArray(compare.files) ? compare.files : [];
    } else {
      allRawFiles = Array.isArray(commit.files) ? commit.files : [];
    }

    // Drop vendored dependencies / build artifacts from the review entirely so a
    // repo that commits them cannot exhaust the model context window or trip the
    // fail-closed guards below. Excluded paths are counted (excludedPathCount) for
    // auditability but are never diffed or content-pulled.
    const rawFiles = allRawFiles.filter((file) => !REVIEW_EXCLUDE_PATH.test(file.filename || ""));
    const excludedPathCount = allRawFiles.length - rawFiles.length;

    // Fail closed (never silently drop reviewable files) if the change set is
    // pathologically large for TEE memory.
    if (rawFiles.length > MAX_CHANGED_FILES) {
      throw new Error(`changed file count ${rawFiles.length} exceeds fail-closed guard ${MAX_CHANGED_FILES}`);
    }
    const changedFiles = rawFiles.map((file) => ({
      path: file.filename,
      status: file.status,
      additions: file.additions ?? null,
      deletions: file.deletions ?? null,
    }));
    const changedFilePaths = changedFiles.map((file) => file.path);

    // 3. Synthesize the FULL unified diff from the GitHub-supplied patches (no
    //    truncation; fail closed if it is pathologically large).
    let diff = "";
    for (const file of rawFiles) {
      const header = `diff --git a/${file.filename} b/${file.filename}\nstatus: ${file.status}\n`;
      const patch = typeof file.patch === "string" ? file.patch : `(no textual patch: ${file.status})`;
      diff += `${header}${patch}\n`;
    }
    if (Buffer.byteLength(diff, "utf8") > MAX_DIFF_BYTES) {
      throw new Error(`synthesized diff exceeds fail-closed guard ${MAX_DIFF_BYTES} bytes`);
    }

    // 4. Pull the FULL contents of every changed source file at the exact commit
    //    so the review sees whole files, not hunks. No per-file or total
    //    truncation: if a matching file cannot be fetched whole, or the aggregate
    //    is pathologically large, FAIL CLOSED rather than under-review.
    //
    //    Attachability is decided FIRST (by policy: not removed, matches
    //    FULL_CONTENT_PATTERN, not excluded as lockfile/minified noise) and
    //    reported alongside the contents, so the evidence manifest can
    //    distinguish "nothing was attachable by design" (docs-only or
    //    deletion-only changes, fully covered by the TEE-fetched diff) from
    //    "attachable files exist but contents are missing" (an evidence
    //    completeness failure).
    const attachableChangedFilePaths = changedFiles
      .filter((file) => file.status !== "removed"
        && FULL_CONTENT_PATTERN.test(file.path)
        && !FULL_CONTENT_EXCLUDE.test(file.path))
      .map((file) => file.path);
    const sourceFiles = {};
    let totalSourceBytes = 0;
    for (const path of attachableChangedFilePaths) {
      const content = await ghFileContent(fetchImpl, repoOwner, repoName, path, commitSha, headers, timeoutMs);
      if (content === null) {
        throw new Error(`could not fetch full contents of changed source file ${path}`);
      }
      totalSourceBytes += Buffer.byteLength(content, "utf8");
      if (totalSourceBytes > MAX_TOTAL_SOURCE_BYTES) {
        throw new Error(`changed source bytes exceed fail-closed guard ${MAX_TOTAL_SOURCE_BYTES}`);
      }
      sourceFiles[path] = content;
    }

    const diffDigest = sha256Digest(diff);
    const sourceFilesDigest = sha256Digest(canonicalStringify(sourceFiles));
    const summary = {
      schema: GITHUB_SOURCE_EVIDENCE_SCHEMA,
      repo: `${repoOwner}/${repoName}`,
      commitSha,
      baseSha: baseSha && SHA_PATTERN.test(baseSha) ? baseSha : null,
      treeSha,
      parentShas: (commit.parents || []).map((parent) => parent.sha),
      changedFiles,
      changedFilePaths,
      attachableChangedFilePaths,
      diffDigest,
      sourceFilesDigest,
      excludedPathCount,
      collectedAt: new Date().toISOString(),
    };
    const evidenceDigest = sha256Digest(canonicalStringify(summary));

    return {
      present: true,
      error: null,
      commitSha,
      baseSha: summary.baseSha,
      treeSha,
      diff,
      changedFilePaths,
      attachableChangedFilePaths,
      excludedPathCount,
      sourceFiles,
      evidenceDigest,
      summary,
    };
  } catch (error) {
    return {
      present: false,
      error: error?.message || String(error || "unknown error"),
    };
  }
}

async function ghJson(fetchImpl, url, headers, timeoutMs) {
  const response = await fetchImpl(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
  if (!response.ok) throw new Error(`GitHub ${url} returned ${response.status}`);
  return response.json();
}

async function ghFileContent(fetchImpl, owner, repo, path, ref, headers, timeoutMs) {
  const url = `${GITHUB_API}/repos/${owner}/${repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(ref)}`;
  const response = await fetchImpl(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
  if (response.status === 404) return null;
  if (!response.ok) throw new Error(`GitHub contents ${path} returned ${response.status}`);
  const data = await response.json();
  if (data.type !== "file") return null;
  // Files above the contents API's ~1MB JSON limit return encoding "none" with
  // empty content. Surface that as an error so the caller FAILS CLOSED instead
  // of reviewing an empty file body.
  if (data.encoding !== "base64" || typeof data.content !== "string") {
    throw new Error(`GitHub contents ${path} is too large to fetch whole via the contents API (encoding=${data.encoding ?? "unknown"})`);
  }
  return Buffer.from(data.content, "base64").toString("utf8");
}
