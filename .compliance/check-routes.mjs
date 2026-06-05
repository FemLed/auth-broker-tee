#!/usr/bin/env node
/**
 * check-routes.mjs
 *
 * Walks every .js / .mjs file under src/ and asserts that every HTTP
 * route surface matches an entry in .compliance/route-allowlist.json.
 *
 * Detection scheme (applied to every file):
 *   1. Find every SwitchStatement whose discriminant accesses `.pathname`
 *      (e.g. `switch (url.pathname)`). Collect string-literal case tests.
 *   2. Find every BinaryExpression of the form `*.url === "..."` or
 *      `*.pathname === "..."` (matches the healthServer pattern in
 *      server.js, AND any future `if (url.pathname === "/secret-backdoor")`
 *      sneak path elsewhere in src/).
 *
 * Exit 0 iff:
 *   - Every allowlisted main-server route appears in some discovered
 *     switch.
 *   - Every allowlisted health-server route appears in some discovered
 *     switch OR equality test.
 *   - Every discovered switch case is allowlisted (no extra main routes).
 *   - Every discovered equality literal is allowlisted (no equality
 *     bypass routes outside the audited switch).
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
const ALLOWLIST_PATH = path.join(HERE, "route-allowlist.json");

function emit(status, fields = {}) {
  process.stdout.write(JSON.stringify({ status, ...fields }, null, 2) + "\n");
  process.exit(status === "passed" ? 0 : 1);
}

const allowlist = JSON.parse(await readFile(ALLOWLIST_PATH, "utf8"));

async function jsFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const out = [];
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...(await jsFiles(p)));
    else if (e.isFile() && (e.name.endsWith(".js") || e.name.endsWith(".mjs"))) out.push(p);
  }
  return out;
}

function memberAccessName(node) {
  if (!node || node.type !== "MemberExpression" || node.computed) return null;
  if (node.object.type === "Identifier" && node.property.type === "Identifier") {
    return `${node.object.name}.${node.property.name}`;
  }
  return null;
}

const discoveredSwitchRoutes = new Map(); // value -> file
const discoveredEqualityRoutes = new Map(); // value -> file
const parseErrors = [];

for (const file of await jsFiles(SRC)) {
  const rel = path.relative(REPO, file);
  let source, ast;
  try { source = await readFile(file, "utf8"); }
  catch (err) { parseErrors.push({ file: rel, error: `read failed: ${err.message}` }); continue; }
  try { ast = parse(source, { ecmaVersion: "latest", sourceType: "module", locations: true }); }
  catch (err) { parseErrors.push({ file: rel, error: `parse failed: ${err.message}` }); continue; }

  walk.simple(ast, {
    SwitchStatement(node) {
      const name = memberAccessName(node.discriminant);
      if (!name || !name.endsWith(".pathname")) return;
      for (const c of node.cases) {
        if (c.test === null) continue; // default
        if (c.test.type === "Literal" && typeof c.test.value === "string") {
          discoveredSwitchRoutes.set(c.test.value, rel);
        } else {
          parseErrors.push({
            file: rel,
            error: `non-literal case test at line ${c.test.loc?.start?.line}: ${source.slice(c.test.start, c.test.end)}`,
          });
        }
      }
    },
    BinaryExpression(node) {
      if (node.operator !== "===" && node.operator !== "==") return;
      let memberName, literalValue;
      if (memberAccessName(node.left) && node.right.type === "Literal" && typeof node.right.value === "string") {
        memberName = memberAccessName(node.left);
        literalValue = node.right.value;
      } else if (memberAccessName(node.right) && node.left.type === "Literal" && typeof node.left.value === "string") {
        memberName = memberAccessName(node.right);
        literalValue = node.left.value;
      } else {
        return;
      }
      if (memberName.endsWith(".url") || memberName.endsWith(".pathname")) {
        discoveredEqualityRoutes.set(literalValue, rel);
      }
    },
  });
}

if (parseErrors.length > 0) {
  emit("failed", { error: "parse / non-literal case errors", details: parseErrors });
}

const expectedMain = new Set(allowlist._main_server_routes || []);
const expectedHealth = new Set(allowlist._health_server_routes || []);
const allExpected = new Set([...expectedMain, ...expectedHealth]);

const missingMain = [...expectedMain].filter((r) => !discoveredSwitchRoutes.has(r));
const extraMain = [...discoveredSwitchRoutes.keys()].filter((r) => !expectedMain.has(r));

const allDiscoveredHealth = new Set([...discoveredEqualityRoutes.keys(), ...discoveredSwitchRoutes.keys()]);
const missingHealth = [...expectedHealth].filter((r) => !allDiscoveredHealth.has(r));

const extraEquality = [...discoveredEqualityRoutes.keys()].filter((r) => !allExpected.has(r));

const failed =
  missingMain.length > 0 ||
  extraMain.length > 0 ||
  missingHealth.length > 0 ||
  extraEquality.length > 0;

const annotate = (routes, source) => routes.map((r) => ({ route: r, file: source.get(r) }));

if (failed) {
  emit("failed", {
    error: "route allowlist drift detected",
    missing_from_source: { main: missingMain, health: missingHealth },
    unexpected_in_source: {
      main: annotate(extraMain, discoveredSwitchRoutes),
      equality: annotate(extraEquality, discoveredEqualityRoutes),
    },
    discovered: {
      main_switch: [...discoveredSwitchRoutes.keys()].sort(),
      url_equality: [...discoveredEqualityRoutes.keys()].sort(),
    },
    expected: {
      main: [...expectedMain].sort(),
      health: [...expectedHealth].sort(),
    },
    remediation: "Update both the source AND .compliance/route-allowlist.json -- they must agree. Equality-style route checks anywhere under src/ (e.g. `if (url.pathname === '/foo')`) are also gated by this allowlist, not just switch cases in server.js.",
  });
}

emit("passed", {
  files_scanned: (await jsFiles(SRC)).length,
  discovered_main_routes: [...discoveredSwitchRoutes.keys()].sort(),
  discovered_equality_routes: [...discoveredEqualityRoutes.keys()].sort(),
});
