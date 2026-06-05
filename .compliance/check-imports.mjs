#!/usr/bin/env node
/**
 * check-imports.mjs
 *
 * Walks every .js file in src/ and asserts that every static import
 * specifier is either:
 *   - a node:* builtin in forbidden-imports.json#node_builtins
 *   - an external npm package in forbidden-imports.json#external_npm
 *   - a relative path starting with "./" or "../"
 *
 * AND that nothing in the file imports anything in the
 * `_explicitly_forbidden_even_if_added_to_allowlist` list (defense in depth
 * against accidental allowlist additions).
 *
 * Dynamic imports (`await import(...)`) are also checked when the argument
 * is a string literal; a non-literal dynamic import fails the check (you
 * cannot statically audit what a runtime-computed module name resolves to).
 *
 * Output: JSON to stdout. Exit 0 iff every import passes.
 */
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { parse } from "acorn";
import * as walk from "acorn-walk";

const HERE_DEFAULT = path.dirname(fileURLToPath(import.meta.url));
const HERE = process.env.COMPLIANCE_ALLOWLIST_DIR
  ? path.resolve(process.env.COMPLIANCE_ALLOWLIST_DIR)
  : HERE_DEFAULT;
const REPO = process.env.COMPLIANCE_REPO_OVERRIDE
  ? path.resolve(process.env.COMPLIANCE_REPO_OVERRIDE)
  : path.resolve(HERE_DEFAULT, "..");
const SRC = path.join(REPO, "src");
const ALLOWLIST_PATH = path.join(HERE, "forbidden-imports.json");

function emit(status, fields = {}) {
  process.stdout.write(JSON.stringify({ status, ...fields }, null, 2) + "\n");
  process.exit(status === "passed" ? 0 : 1);
}

const allowlist = JSON.parse(await readFile(ALLOWLIST_PATH, "utf8"));
const allowedBuiltins = new Set(allowlist.node_builtins || []);
const allowedExternal = new Set(allowlist.external_npm || []);
const explicitlyForbidden = new Set(allowlist._explicitly_forbidden_even_if_added_to_allowlist || []);
const relativePrefix = allowlist.internal_relative_prefix || "./";

async function jsFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const out = [];
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...(await jsFiles(p)));
    } else if (e.isFile() && (e.name.endsWith(".js") || e.name.endsWith(".mjs"))) {
      out.push(p);
    }
  }
  return out;
}

function classify(spec) {
  if (typeof spec !== "string") return { kind: "non-literal" };

  // Normalize bare builtin -> node:builtin (acorn returns the literal source string)
  const normalized = spec.startsWith("node:") ? spec : (
    isLikelyBuiltinBare(spec) ? `node:${spec}` : spec
  );

  if (explicitlyForbidden.has(normalized)) return { kind: "explicitly-forbidden", normalized };
  if (allowedBuiltins.has(normalized)) return { kind: "allowed-builtin", normalized };
  if (allowedExternal.has(spec)) return { kind: "allowed-external", normalized: spec };
  if (spec.startsWith(relativePrefix) || spec.startsWith("../")) return { kind: "allowed-relative", normalized: spec };

  return { kind: "unknown", normalized };
}

const KNOWN_BARE_BUILTINS = new Set([
  "crypto", "fs", "http", "http2", "https", "net", "os", "path", "stream",
  "url", "util", "buffer", "events", "querystring", "timers", "zlib",
  "child_process", "vm", "worker_threads", "dgram", "dns", "dns/promises",
  "tls", "cluster", "perf_hooks", "process", "readline", "string_decoder",
  "v8", "trace_events", "wasi",
]);

function isLikelyBuiltinBare(spec) {
  // Best-effort: if it looks like a Node builtin without `node:` prefix, treat as such.
  return KNOWN_BARE_BUILTINS.has(spec);
}

const files = await jsFiles(SRC);
const violations = [];
const allImports = []; // [{file, spec, kind, line}]

for (const file of files) {
  const rel = path.relative(REPO, file);
  let source;
  try { source = await readFile(file, "utf8"); }
  catch (err) { violations.push({ file: rel, error: `read failed: ${err.message}` }); continue; }

  let ast;
  try { ast = parse(source, { ecmaVersion: "latest", sourceType: "module", locations: true }); }
  catch (err) { violations.push({ file: rel, error: `parse failed: ${err.message}` }); continue; }

  const recordImport = (specNode, kind = "static") => {
    if (!specNode) return;
    let spec, line;
    if (specNode.type === "Literal" && typeof specNode.value === "string") {
      spec = specNode.value;
      line = specNode.loc?.start?.line;
    } else {
      // Dynamic non-literal import -- fail closed.
      violations.push({
        file: rel,
        line: specNode.loc?.start?.line,
        error: `non-literal ${kind} import specifier (cannot be audited statically)`,
      });
      return;
    }
    const c = classify(spec);
    allImports.push({ file: rel, spec, kind, classification: c.kind, line });
    if (c.kind !== "allowed-builtin" && c.kind !== "allowed-external" && c.kind !== "allowed-relative") {
      violations.push({
        file: rel,
        line,
        spec,
        classification: c.kind,
        message: `import '${spec}' is not in the allowlist`,
      });
    }
  };

  walk.simple(ast, {
    ImportDeclaration(node) { recordImport(node.source); },
    ImportExpression(node)   { recordImport(node.source, "dynamic"); },
    CallExpression(node) {
      // require("...")
      if (node.callee.type === "Identifier" && node.callee.name === "require" && node.arguments.length >= 1) {
        recordImport(node.arguments[0], "require");
      }
    },
  });
}

if (violations.length > 0) {
  emit("failed", {
    error: "import allowlist violations",
    violations,
    discovered_imports: allImports,
    remediation:
      "Either remove the import, or add it to .compliance/forbidden-imports.json (allowlist) -- " +
      "but not to _explicitly_forbidden_even_if_added_to_allowlist. The diff bumps the rules " +
      "digest, which verifiers will see.",
  });
}

emit("passed", {
  files_scanned: files.length,
  imports_total: allImports.length,
  imports_by_kind: allImports.reduce((acc, i) => { acc[i.classification] = (acc[i.classification] || 0) + 1; return acc; }, {}),
});
