#!/usr/bin/env node
/**
 * check-secrets.mjs
 *
 * Three complementary checks; all must pass:
 *
 *   A. The SECRETS object in src/server.js exactly mirrors the `read` map
 *      in secrets-allowlist.json (env-var name -> Secret Manager id).
 *
 *   B. Every direct fetchSecretByName / fetchSecretValue / writeSecretValue
 *      call across src/ resolves a string-literal secret name and that
 *      name is authorized:
 *        - read      : present in `read` (auto-allowed) OR in `aux_read`
 *                      with a `file` matching the call site
 *        - write     : present in `write` with a `file` matching the call
 *                      site
 *      Non-literal arguments fail the check (a runtime-computed name
 *      cannot be statically audited). Helper-definition files in
 *      `callsite_check_excludes` are skipped; caller-side dynamic patterns
 *      must be listed in `validated_secret_loader_calls` and match the
 *      audited SECRETS-object loader shape exactly.
 *
 *   C. Every `process.env.X` MemberExpression read across src/ where X
 *      matches `env_var_token_regex` must be in `env_var_allowlist`.
 *      This catches "snuck-in" sensitive env-var reads
 *      (e.g. `process.env.SNUCK_IN_API_KEY`) that don't go through any
 *      Secret Manager call but still indicate the workload depends on a
 *      sensitive value.
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
const SERVER_PATH = path.join(REPO, "src", "server.js");
const ALLOWLIST_PATH = path.join(HERE, "secrets-allowlist.json");

function emit(status, fields = {}) {
  process.stdout.write(JSON.stringify({ status, ...fields }, null, 2) + "\n");
  process.exit(status === "passed" ? 0 : 1);
}

const allowlist = JSON.parse(await readFile(ALLOWLIST_PATH, "utf8"));
const expectedReadByEnv = allowlist.read || {};
const auxRead = allowlist.aux_read || {};
const writeAllow = allowlist.write || {};
const excludedFiles = new Set(allowlist.callsite_check_excludes || []);
const validatedSecretLoaderCalls = allowlist.validated_secret_loader_calls || [];
const envVarAllowlist = new Set(allowlist.env_var_allowlist || []);
const envVarTokenRegex = new RegExp(allowlist.env_var_token_regex || "token|secret|key|credential|password|hmac|api_key", "i");

// ---------------------------------------------------------------------------
// A. SECRETS object in server.js mirrors `read` map
// ---------------------------------------------------------------------------
const serverText = await readFile(SERVER_PATH, "utf8");

let serverAst;
try {
  serverAst = parse(serverText, { ecmaVersion: "latest", sourceType: "module", locations: true });
} catch (err) {
  emit("failed", { error: `parse error in src/server.js: ${err.message}` });
}

let discoveredMap = null;

walk.simple(serverAst, {
  VariableDeclaration(node) {
    for (const decl of node.declarations) {
      if (decl.id?.type !== "Identifier" || decl.id.name !== "SECRETS") continue;
      if (decl.init?.type !== "ObjectExpression") {
        emit("failed", { error: "SECRETS is declared but is not an ObjectExpression" });
      }
      if (discoveredMap !== null) {
        emit("failed", { error: "SECRETS declared more than once" });
      }
      const map = {};
      for (const prop of decl.init.properties) {
        if (prop.type !== "Property") {
          emit("failed", { error: `non-Property entry in SECRETS at line ${prop.loc?.start?.line}` });
        }
        let key;
        if (prop.key.type === "Identifier") key = prop.key.name;
        else if (prop.key.type === "Literal" && typeof prop.key.value === "string") key = prop.key.value;
        else emit("failed", { error: `non-string SECRETS key at line ${prop.key.loc?.start?.line}` });

        if (prop.value.type !== "Literal" || typeof prop.value.value !== "string") {
          emit("failed", {
            error: `SECRETS value for '${key}' is not a string literal (would let runtime indirection determine which secret is fetched)`,
          });
        }
        map[key] = prop.value.value;
      }
      discoveredMap = map;
    }
  },
});

if (discoveredMap === null) {
  emit("failed", { error: "SECRETS object not found in src/server.js" });
}

const expectedKeys = new Set(Object.keys(expectedReadByEnv));
const discoveredKeys = new Set(Object.keys(discoveredMap));
const missingFromSrc = [...expectedKeys].filter((k) => !discoveredKeys.has(k));
const extraInSrc = [...discoveredKeys].filter((k) => !expectedKeys.has(k));
const mismatched = [];
for (const k of expectedKeys) {
  if (discoveredKeys.has(k) && discoveredMap[k] !== expectedReadByEnv[k]) {
    mismatched.push({ key: k, source: discoveredMap[k], allowlist: expectedReadByEnv[k] });
  }
}

if (missingFromSrc.length || extraInSrc.length || mismatched.length) {
  emit("failed", {
    error: "SECRETS object drift in src/server.js",
    missing_from_source: missingFromSrc,
    unexpected_in_source: extraInSrc,
    mismatched_secret_names: mismatched,
    discovered: discoveredMap,
    expected: expectedReadByEnv,
    remediation: "Update both src/server.js (SECRETS) AND .compliance/secrets-allowlist.json#read. If adding a new secret, also update terraform/main.tf locals and grant WIF access.",
  });
}

// ---------------------------------------------------------------------------
// Helpers shared by checks B and C
// ---------------------------------------------------------------------------
const FETCH_FNS = new Set(["fetchSecretByName", "fetchSecretValue"]);
const WRITE_FNS = new Set(["writeSecretValue"]);
const allowedReadByValue = new Set(Object.values(expectedReadByEnv));

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

function literalsOnlyTemplate(node, fileScope) {
  const parts = [];
  for (let i = 0; i < node.quasis.length; i++) {
    parts.push(node.quasis[i].value.cooked);
    if (i < node.expressions.length) {
      const expr = node.expressions[i];
      if (expr.type === "Identifier") {
        const v = fileScope.get(expr.name);
        if (typeof v === "string") {
          parts.push(v);
          continue;
        }
      }
      if (expr.type === "Literal" && typeof expr.value === "string") {
        parts.push(expr.value);
        continue;
      }
      return null;
    }
  }
  return parts.join("");
}

function staticSecretFromTemplate(node, fileScope) {
  // Build a representation that mixes literal chunks with any
  // interpolation that statically resolves to a string. Unresolvable
  // interpolations become an opaque marker. Then look for the
  // `/secrets/<NAME>` pattern in that merged text. This catches the
  // common pattern `projects/${process.env.X}/secrets/${KNOWN_CONST}`
  // where the secret-name slot is pinned at build time even though the
  // project namespace is dynamic.
  const parts = [];
  for (let i = 0; i < node.quasis.length; i++) {
    parts.push(node.quasis[i].value.cooked);
    if (i < node.expressions.length) {
      const expr = node.expressions[i];
      if (expr.type === "Literal" && typeof expr.value === "string") {
        parts.push(expr.value);
      } else if (expr.type === "Identifier") {
        const v = fileScope.get(expr.name);
        if (typeof v === "string") parts.push(v);
        else parts.push("\u0000");
      } else {
        parts.push("\u0000");
      }
    }
  }
  const merged = parts.join("");
  const m = /\/secrets\/([A-Za-z0-9_.\-]+)(?:\/|$)/.exec(merged);
  return m ? m[1] : null;
}

function resolveStringArg(node, fileScope) {
  if (!node) return { kind: "missing" };
  if (node.type === "Literal" && typeof node.value === "string") {
    return { kind: "literal", value: node.value };
  }
  if (node.type === "TemplateLiteral") {
    const fully = literalsOnlyTemplate(node, fileScope);
    if (fully !== null) return { kind: "literal", value: fully };
    const staticName = staticSecretFromTemplate(node, fileScope);
    if (staticName) {
      return { kind: "literal", value: `projects/<dynamic>/secrets/${staticName}/versions/latest`, via: "static-template-quasi" };
    }
    return { kind: "non-literal", reason: "template literal interpolations not statically resolvable AND no static `/secrets/<NAME>/` quasi" };
  }
  if (node.type === "Identifier") {
    const v = fileScope.get(node.name);
    if (typeof v === "string") return { kind: "literal", value: v, via: node.name };
    if (v && typeof v === "object" && v.templateNode) {
      return resolveStringArg(v.templateNode, fileScope);
    }
    return { kind: "non-literal", reason: `identifier '${node.name}' is not a top-level string constant` };
  }
  return { kind: "non-literal", reason: `unsupported expression '${node.type}'` };
}

function extractSecretName(value) {
  const m = /\/secrets\/([^/]+)/.exec(value);
  return m ? m[1] : value;
}

async function buildFileScope(ast) {
  const scope = new Map();
  walk.simple(ast, {
    VariableDeclaration(node) {
      for (const decl of node.declarations) {
        if (decl.id?.type !== "Identifier") continue;
        if (decl.init?.type === "Literal" && typeof decl.init.value === "string") {
          scope.set(decl.id.name, decl.init.value);
        } else if (decl.init?.type === "TemplateLiteral") {
          scope.set(decl.id.name, { templateNode: decl.init });
        }
      }
    },
  });
  return scope;
}

function memberPropertyName(node) {
  if (!node || node.type !== "MemberExpression") return null;
  if (!node.computed && node.property?.type === "Identifier") return node.property.name;
  if (node.computed && node.property?.type === "Literal" && typeof node.property.value === "string") return node.property.value;
  return null;
}

function memberObjectName(node) {
  if (!node || node.type !== "MemberExpression") return null;
  return node.object?.type === "Identifier" ? node.object.name : null;
}

function isObjectEntriesCall(node, objectName) {
  return node?.type === "CallExpression" &&
    node.callee?.type === "MemberExpression" &&
    node.callee.object?.type === "Identifier" &&
    node.callee.object.name === "Object" &&
    memberPropertyName(node.callee) === "entries" &&
    node.arguments[0]?.type === "Identifier" &&
    node.arguments[0].name === objectName;
}

function functionDeclaresValidatedMapSource(fnNode, mapSourceName, validatedMapName) {
  let found = false;
  walk.simple(fnNode.body, {
    VariableDeclarator(decl) {
      if (found) return;
      if (decl.id?.type !== "Identifier" || decl.id.name !== mapSourceName) return;
      if (isObjectEntriesCall(decl.init, validatedMapName)) found = true;
    },
  });
  return found;
}

function callbackBindsArrayValueParam(callbackNode, argumentName, valueParamIndex) {
  if (!callbackNode || (callbackNode.type !== "ArrowFunctionExpression" && callbackNode.type !== "FunctionExpression")) {
    return false;
  }
  const param = callbackNode.params?.[0];
  if (param?.type !== "ArrayPattern") return false;
  return param.elements?.[valueParamIndex]?.type === "Identifier" &&
    param.elements[valueParamIndex].name === argumentName;
}

function isMapCallForCallback(node, mapSourceName, callbackNode) {
  return node?.type === "CallExpression" &&
    node.callee?.type === "MemberExpression" &&
    memberObjectName(node.callee) === mapSourceName &&
    memberPropertyName(node.callee) === "map" &&
    node.arguments.includes(callbackNode);
}

function functionName(node) {
  if (node?.type === "FunctionDeclaration") return node.id?.name || "";
  if ((node?.type === "FunctionExpression" || node?.type === "ArrowFunctionExpression") && node.id?.name) return node.id.name;
  return "";
}

function isValidatedSecretLoaderCall(node, ancestors, rel, calleeName) {
  const arg = node.arguments[0];
  if (!arg || arg.type !== "Identifier") return false;

  const chain = ancestors || [];
  for (const rule of validatedSecretLoaderCalls) {
    const valueParamIndex = Number.isInteger(rule.value_param_index) ? rule.value_param_index : 1;
    const mapSourceName = rule.map_source || "entries";
    const validatedMapName = rule.validated_map || "SECRETS";
    if (rule.file !== rel) continue;
    if (rule.callee !== calleeName) continue;
    if (rule.argument !== arg.name) continue;

    const callbackNode = [...chain].reverse().find((a) =>
      callbackBindsArrayValueParam(a, arg.name, valueParamIndex)
    );
    if (!callbackNode) continue;

    const mapCall = [...chain].reverse().find((a) =>
      isMapCallForCallback(a, mapSourceName, callbackNode)
    );
    if (!mapCall) continue;

    const enclosingFn = [...chain].reverse().find((a) =>
      ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"].includes(a?.type) &&
      functionName(a) === rule.function
    );
    if (!enclosingFn) continue;

    if (!functionDeclaresValidatedMapSource(enclosingFn, mapSourceName, validatedMapName)) continue;
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// B + C: cross-file scan
// ---------------------------------------------------------------------------
const callViolations = [];
const envVarViolations = [];
const observedDirectAccess = [];
const observedSensitiveEnvReads = [];

const files = await jsFiles(SRC);
for (const file of files) {
  const rel = path.relative(REPO, file);
  let source, ast;
  try { source = await readFile(file, "utf8"); }
  catch (err) { callViolations.push({ file: rel, error: `read failed: ${err.message}` }); continue; }
  try { ast = parse(source, { ecmaVersion: "latest", sourceType: "module", locations: true }); }
  catch (err) { callViolations.push({ file: rel, error: `parse failed: ${err.message}` }); continue; }

  const fileScope = await buildFileScope(ast);
  const skipCallSites = excludedFiles.has(rel);

  walk.ancestor(ast, {
    CallExpression(node, state, ancestors) {
      if (skipCallSites) return;
      let calleeName = null;
      if (node.callee.type === "Identifier") {
        calleeName = node.callee.name;
      } else if (node.callee.type === "MemberExpression" && node.callee.property.type === "Identifier") {
        calleeName = node.callee.property.name;
      }
      if (!calleeName) return;
      const isFetch = FETCH_FNS.has(calleeName);
      const isWrite = WRITE_FNS.has(calleeName);
      if (!isFetch && !isWrite) return;

      const argNode = node.arguments[0];
      const resolved = resolveStringArg(argNode, fileScope);
      const line = node.loc?.start?.line;

      const ancestorChain = Array.isArray(ancestors) ? ancestors : state;
      if (isFetch && isValidatedSecretLoaderCall(node, ancestorChain, rel, calleeName)) {
        observedDirectAccess.push({
          file: rel,
          secret: "<validated SECRETS map>",
          mode: "read",
          line,
          via: "validated_secret_loader_calls",
        });
        return;
      }

      if (resolved.kind !== "literal") {
        callViolations.push({
          file: rel,
          line,
          callee: calleeName,
          error: `non-literal first argument: ${resolved.reason || resolved.kind}`,
        });
        return;
      }

      const secretName = extractSecretName(resolved.value);
      const mode = isWrite ? "write" : "read";
      observedDirectAccess.push({ file: rel, secret: secretName, mode, line });

      if (mode === "read") {
        if (allowedReadByValue.has(secretName)) return;
        const aux = auxRead[secretName];
        if (!aux) {
          callViolations.push({
            file: rel,
            line,
            callee: calleeName,
            secret: secretName,
            error: `read of '${secretName}' is not in secrets-allowlist.json (#read or #aux_read)`,
          });
          return;
        }
        if (aux.file && aux.file !== rel) {
          callViolations.push({
            file: rel,
            line,
            callee: calleeName,
            secret: secretName,
            error: `read of '${secretName}' must originate from '${aux.file}', not '${rel}'`,
          });
          return;
        }
      } else {
        const w = writeAllow[secretName];
        if (!w) {
          callViolations.push({
            file: rel,
            line,
            callee: calleeName,
            secret: secretName,
            error: `write of '${secretName}' is not in secrets-allowlist.json#write`,
          });
          return;
        }
        if (w.file && w.file !== rel) {
          callViolations.push({
            file: rel,
            line,
            callee: calleeName,
            secret: secretName,
            error: `write of '${secretName}' must originate from '${w.file}', not '${rel}'`,
          });
          return;
        }
      }
    },

    // Check C: token-like process.env.X reads.
    MemberExpression(node) {
      // Match exactly `process.env.X` or `process.env["X"]`.
      if (node.object?.type !== "MemberExpression") return;
      if (node.object.object?.type !== "Identifier" || node.object.object.name !== "process") return;
      if (node.object.property?.type !== "Identifier" || node.object.property.name !== "env") return;

      let envName;
      if (!node.computed && node.property?.type === "Identifier") envName = node.property.name;
      else if (node.computed && node.property?.type === "Literal" && typeof node.property.value === "string") envName = node.property.value;
      else return;

      if (!envVarTokenRegex.test(envName)) return;
      observedSensitiveEnvReads.push({ file: rel, env_var: envName, line: node.loc?.start?.line });
      if (!envVarAllowlist.has(envName)) {
        envVarViolations.push({
          file: rel,
          line: node.loc?.start?.line,
          env_var: envName,
          error: `process.env.${envName} matches the token-like regex but is not in secrets-allowlist.json#env_var_allowlist`,
        });
      }
    },
  });
}

if (callViolations.length > 0 || envVarViolations.length > 0) {
  emit("failed", {
    error: "secret-access policy violations",
    callsite_violations: callViolations,
    env_var_violations: envVarViolations,
    observed_direct_access: observedDirectAccess,
    observed_sensitive_env_reads: observedSensitiveEnvReads,
    remediation: "Either remove the offending call/read OR add it to the appropriate section of .compliance/secrets-allowlist.json AND grant matching IAM in terraform/main.tf.",
  });
}

emit("passed", {
  secrets_count: Object.keys(discoveredMap).length,
  discovered: discoveredMap,
  observed_direct_access: observedDirectAccess,
  observed_sensitive_env_reads: observedSensitiveEnvReads,
});
