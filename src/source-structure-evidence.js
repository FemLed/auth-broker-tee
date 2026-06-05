import { parse } from "acorn";
import * as walk from "acorn-walk";

const STRUCTURE_SCHEMA = "femled.tee.source_structure_evidence.v1";
const MAX_FILES = 120;
const MAX_IMPORTS_PER_FILE = 40;
const MAX_SYMBOLS_PER_FILE = 60;
const MAX_FINDINGS_PER_FILE = 60;
const MAX_TOTAL_FINDINGS = 160;
const MAX_ERROR_LENGTH = 240;

const JS_EXTENSIONS = new Set([".js", ".mjs"]);
const GOVERNANCE_CRITICAL_PATTERNS = [
  /(^|\/)src\/governance-/,
  /(^|\/)src\/first-principles-/,
  /(^|\/)src\/vertex-gemini\.js$/,
  /(^|\/)src\/gcp-auth\.js$/,
  /(^|\/)src\/attestation\.js$/,
  /(^|\/)src\/route-registry\.js$/,
  /(^|\/)src\/server\.js$/,
];
const SENSITIVE_CALLEES = new Set([
  "fetch",
  "fetchSecretByName",
  "fetchSecretValue",
  "writeSecretValue",
  "getWifAccessToken",
  "getMetadataAccessToken",
  "requestAttestationToken",
  "signGovernancePayload",
  "verifyGovernanceEnvelope",
  "signGenesisCertificate",
  "signPreapprovalCertificate",
  "signSuccessorCertificate",
  "signRetirementCertificate",
  "createActivationChallenge",
  "completeActivation",
  "applyActivationBundle",
  "initializeGovernance",
  "GoogleGenAI",
]);
const SURFACE_PATTERNS = [
  ["governance", /governance/i],
  ["activation", /activation/i],
  ["first-principles", /first[-_]principles|FIRST_PRINCIPLES/],
  ["model-policy", /modelPolicy|MODEL_POLICY|FIRST_PRINCIPLES_MODEL|vertex-gemini|GoogleGenAI/],
  ["route-registry", /route[-_]registry|RouteRegistry|routeBundle|routeTrust/i],
  ["attestation", /attestation|ConfidentialSpace|requestAttestationToken/i],
  ["wif", /WIF|getWifAccessToken|workload identity|sts\.googleapis/i],
  ["secret-manager", /SecretManager|fetchSecret|writeSecret|secretmanager/i],
  ["cloud-run", /Cloud Run|run\.googleapis|traffic|deploy/i],
];
const SEMANTIC_RISK_PATTERNS = [
  ["governance-private-material", /GOVERNANCE_PRIVATE_KEY|BEGIN PRIVATE KEY|SECRET_MANAGER.*governance/i],
  ["environment-governance-mode", /TEE_GOVERNANCE_BOOTSTRAP|TEE_GOVERNANCE_MODE|GOVERNANCE_MODE/i],
  ["break-glass-or-recovery", /break[-_ ]?glass|owner recovery|admin recovery|reset[-_ ]?to[-_ ]?genesis/i],
  ["first-principles-env-retarget", /FIRST_PRINCIPLES_(OIDC_AUDIENCE|REPOSITORY|WORKFLOW_REFS|WORKFLOW_REF)/],
];
const GOVERNANCE_LITERAL_PATTERN = /^(active|genesis)$/i;
const GOVERNANCE_LITERAL_TEXT_PATTERN = /break[-_ ]?glass|owner recovery|admin recovery|reset[-_ ]?to[-_ ]?genesis|GOVERNANCE_PRIVATE_KEY|TEE_GOVERNANCE_MODE|TEE_GOVERNANCE_BOOTSTRAP|GOVERNANCE_MODE/i;

export function buildSourceStructureEvidence(sourceFiles = {}) {
  const files = Object.entries(sourceFiles)
    .map(([path, content]) => [String(path), String(content)])
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(0, MAX_FILES);
  const omittedFileCount = Math.max(0, Object.keys(sourceFiles || {}).length - files.length);
  const fileSummaries = [];
  const parseFailures = [];
  const highRiskFindings = [];

  for (const [path, content] of files) {
    const summary = summarizeFile(path, content);
    fileSummaries.push(summary);
    if (summary.status === "parse_failed") {
      parseFailures.push({
        file: path,
        governanceCritical: summary.governanceCritical,
        error: summary.parseError,
      });
    }
    for (const finding of summary.highRiskFindings || []) {
      highRiskFindings.push({ file: path, ...finding });
    }
  }

  const surfaces = uniqueSorted(fileSummaries.flatMap((file) => file.governanceSurfaces || []));
  const semanticRiskHints = fileSummaries
    .flatMap((file) => file.semanticRiskHints || [])
    .slice(0, MAX_TOTAL_FINDINGS);
  return {
    schema: STRUCTURE_SCHEMA,
    status: parseFailures.length > 0 || highRiskFindings.length > 0 ? "degraded" : "passed",
    fileCount: fileSummaries.length,
    omittedFileCount,
    parseFailures: parseFailures.slice(0, MAX_TOTAL_FINDINGS),
    highRiskFindings: highRiskFindings.slice(0, MAX_TOTAL_FINDINGS),
    governanceCriticalParseFailures: parseFailures
      .filter((failure) => failure.governanceCritical)
      .map((failure) => failure.file)
      .slice(0, MAX_TOTAL_FINDINGS),
    governanceSurfaces: surfaces,
    semanticRiskHints,
    importGraph: fileSummaries
      .filter((file) => (file.imports || []).length > 0)
      .map((file) => ({
        file: file.path,
        imports: file.imports.map((item) => item.spec),
      })),
    files: fileSummaries,
  };
}

function summarizeFile(path, content) {
  const base = {
    path,
    kind: fileKind(path),
    byteLength: Buffer.byteLength(content, "utf8"),
    lineCount: content === "" ? 0 : content.split("\n").length,
    governanceCritical: isGovernanceCriticalPath(path),
  };
  if (!JS_EXTENSIONS.has(extensionOf(path))) {
    return {
      ...base,
      status: "metadata_only",
      imports: [],
      exports: [],
      declarations: [],
      sensitiveCalls: [],
      envReads: [],
      literalSignals: [],
      semanticRiskHints: semanticRiskHintsFor(path, content),
      highRiskFindings: [],
      governanceSurfaces: classifySurfaces(path, content),
    };
  }

  let ast;
  try {
    ast = parse(content, {
      ecmaVersion: "latest",
      sourceType: "module",
      locations: true,
      allowHashBang: true,
    });
  } catch (error) {
    return {
      ...base,
      status: "parse_failed",
      parseError: formatParseError(error),
      imports: [],
      exports: [],
      declarations: [],
      sensitiveCalls: [],
      envReads: [],
      highRiskFindings: [{
        kind: "parse_failed",
        line: error.loc?.line || null,
        detail: truncate(error.message, MAX_ERROR_LENGTH),
      }],
      semanticRiskHints: semanticRiskHintsFor(path, content),
      literalSignals: [],
      governanceSurfaces: classifySurfaces(path, content),
    };
  }

  const imports = [];
  const exports = [];
  const declarations = [];
  const sensitiveCalls = [];
  const envReads = [];
  const literalSignals = [];
  const highRiskFindings = [];

  walk.ancestor(ast, {
    ImportDeclaration(node) {
      imports.push({
        kind: "static",
        spec: literalValue(node.source),
        line: lineOf(node),
      });
    },
    ImportExpression(node) {
      const spec = literalValue(node.source);
      imports.push({
        kind: "dynamic",
        spec: spec || "<non-literal>",
        line: lineOf(node),
      });
      if (!spec) {
        highRiskFindings.push({
          kind: "non_literal_dynamic_import",
          line: lineOf(node),
          detail: "Dynamic import specifier is not statically auditable",
        });
      }
    },
    CallExpression(node, ancestors) {
      if (calleeName(node.callee) === "require") {
        const spec = literalValue(node.arguments?.[0]);
        imports.push({
          kind: "require",
          spec: spec || "<non-literal>",
          line: lineOf(node),
        });
        if (!spec) {
          highRiskFindings.push({
            kind: "non_literal_require",
            line: lineOf(node),
            detail: "require() specifier is not statically auditable",
          });
        }
      }
      const name = calleeName(node.callee);
      if (SENSITIVE_CALLEES.has(name)) {
        sensitiveCalls.push({
          name,
          line: lineOf(node),
          enclosing: enclosingSymbol(ancestors),
        });
      }
    },
    NewExpression(node, ancestors) {
      const name = calleeName(node.callee);
      if (SENSITIVE_CALLEES.has(name)) {
        sensitiveCalls.push({
          name,
          line: lineOf(node),
          enclosing: enclosingSymbol(ancestors),
        });
      }
    },
    MemberExpression(node) {
      const envName = processEnvName(node);
      if (envName) {
        envReads.push({
          name: envName,
          line: lineOf(node),
        });
      }
    },
    Literal(node, ancestors) {
      if (typeof node.value !== "string") return;
      const parent = ancestors[ancestors.length - 2];
      const value = String(node.value);
      if (!GOVERNANCE_LITERAL_PATTERN.test(value) && !GOVERNANCE_LITERAL_TEXT_PATTERN.test(value)) return;
      literalSignals.push({
        value: truncate(value, MAX_ERROR_LENGTH),
        line: lineOf(node),
        context: literalContext(parent),
        enclosing: enclosingSymbol(ancestors),
      });
    },
    ExportNamedDeclaration(node) {
      collectExports(node, exports);
      collectDeclaration(node.declaration, declarations);
    },
    ExportDefaultDeclaration(node) {
      exports.push({
        kind: "default",
        name: declarationName(node.declaration) || "default",
        line: lineOf(node),
      });
      collectDeclaration(node.declaration, declarations);
    },
    ExportAllDeclaration(node) {
      exports.push({
        kind: "all",
        name: literalValue(node.source) || "*",
        line: lineOf(node),
      });
    },
    FunctionDeclaration(node, ancestors) {
      if (isTopLevel(ancestors)) collectDeclaration(node, declarations);
    },
    ClassDeclaration(node, ancestors) {
      if (isTopLevel(ancestors)) collectDeclaration(node, declarations);
    },
    VariableDeclaration(node, ancestors) {
      if (isTopLevel(ancestors)) collectDeclaration(node, declarations);
    },
    MethodDefinition(node, ancestors) {
      if (ancestors.some((item) => item.type === "ClassDeclaration")) {
        declarations.push({
          kind: "method",
          name: propertyName(node.key),
          line: lineOf(node),
        });
      }
    },
  });

  const surfaces = classifySurfaces(path, content, {
    imports,
    exports,
    declarations,
    sensitiveCalls,
    envReads,
  });
  const semanticRiskHints = semanticRiskHintsFor(path, content, { literalSignals });
  return {
    ...base,
    status: highRiskFindings.length > 0 ? "degraded" : "parsed",
    imports: sortAndLimit(uniqueBy(imports, importKey), MAX_IMPORTS_PER_FILE),
    exports: sortAndLimit(uniqueBy(exports, exportKey), MAX_SYMBOLS_PER_FILE),
    declarations: sortAndLimit(uniqueBy(declarations, declarationKey), MAX_SYMBOLS_PER_FILE),
    sensitiveCalls: sortAndLimit(uniqueBy(sensitiveCalls, callKey), MAX_FINDINGS_PER_FILE),
    envReads: sortAndLimit(uniqueBy(envReads, envKey), MAX_FINDINGS_PER_FILE),
    literalSignals: sortAndLimit(uniqueBy(literalSignals, literalSignalKey), MAX_FINDINGS_PER_FILE),
    semanticRiskHints: sortAndLimit(uniqueBy(semanticRiskHints, semanticRiskHintKey), MAX_FINDINGS_PER_FILE),
    highRiskFindings: sortAndLimit(highRiskFindings, MAX_FINDINGS_PER_FILE),
    governanceSurfaces: surfaces,
  };
}

function semanticRiskHintsFor(path, content, structural = {}) {
  const hints = [];
  for (const [kind, pattern] of SEMANTIC_RISK_PATTERNS) {
    if (pattern.test(content)) {
      hints.push({
        kind,
        file: path,
        evidence: "lexical_match",
        reviewOnly: true,
      });
    }
  }
  for (const signal of structural.literalSignals || []) {
    if (GOVERNANCE_LITERAL_TEXT_PATTERN.test(signal.value) || GOVERNANCE_LITERAL_PATTERN.test(signal.value)) {
      hints.push({
        kind: "governance-literal",
        file: path,
        line: signal.line,
        context: signal.context,
        evidence: signal.value,
        reviewOnly: true,
      });
    }
  }
  return hints;
}

function collectExports(node, exports) {
  if (!node) return;
  if (node.declaration) {
    for (const exported of exportedDeclarationNames(node.declaration)) {
      exports.push({
        kind: "declaration",
        name: exported,
        line: lineOf(node),
      });
    }
  }
  for (const specifier of node.specifiers || []) {
    exports.push({
      kind: "named",
      name: propertyName(specifier.exported),
      line: lineOf(specifier),
    });
  }
}

function exportedDeclarationNames(node) {
  if (!node) return ["anonymous"];
  if (node.type === "VariableDeclaration") {
    const names = (node.declarations || []).map((declaration) => propertyName(declaration.id)).filter(Boolean);
    return names.length > 0 ? names : ["anonymous"];
  }
  return [declarationName(node) || "anonymous"];
}

function collectDeclaration(node, declarations) {
  if (!node) return;
  if (node.type === "FunctionDeclaration") {
    declarations.push({
      kind: "function",
      name: node.id?.name || "anonymous",
      line: lineOf(node),
    });
    return;
  }
  if (node.type === "ClassDeclaration") {
    declarations.push({
      kind: "class",
      name: node.id?.name || "anonymous",
      line: lineOf(node),
    });
    return;
  }
  if (node.type === "VariableDeclaration") {
    for (const declaration of node.declarations || []) {
      const name = propertyName(declaration.id);
      if (!name) continue;
      declarations.push({
        kind: variableKind(declaration.init),
        name,
        line: lineOf(declaration),
      });
    }
  }
}

function variableKind(init) {
  if (!init) return "constant";
  if (init.type === "ArrowFunctionExpression" || init.type === "FunctionExpression") return "function";
  if (init.type === "ClassExpression") return "class";
  return "constant";
}

function literalContext(parent) {
  if (!parent) return "unknown";
  if (parent.type === "BinaryExpression" || parent.type === "LogicalExpression") return parent.operator || parent.type;
  if (parent.type === "AssignmentExpression") return "assignment";
  if (parent.type === "VariableDeclarator") return "variable-initializer";
  if (parent.type === "Property") return "object-property";
  if (parent.type === "CallExpression") return "call-argument";
  if (parent.type === "TemplateElement") return "template";
  return parent.type || "unknown";
}

function processEnvName(node) {
  if (node?.type !== "MemberExpression") return null;
  if (node.object?.type === "MemberExpression" && propertyName(node.object.property) === "env") {
    if (node.object.object?.type === "Identifier" && node.object.object.name === "process") {
      return propertyName(node.property) || "<computed>";
    }
  }
  return null;
}

function calleeName(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    const object = calleeName(node.object);
    const property = propertyName(node.property);
    return property || object;
  }
  return "";
}

function enclosingSymbol(ancestors) {
  for (const node of [...ancestors].reverse()) {
    if (["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "MethodDefinition"].includes(node.type)) {
      return declarationName(node) || propertyName(node.key) || "anonymous";
    }
  }
  return "top-level";
}

function declarationName(node) {
  if (!node) return "";
  if (node.id?.name) return node.id.name;
  if (node.type === "MethodDefinition") return propertyName(node.key);
  return "";
}

function propertyName(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "PrivateIdentifier") return `#${node.name}`;
  if (node.type === "Literal") return String(node.value);
  if (node.type === "Property") return propertyName(node.key);
  return "";
}

function literalValue(node) {
  return node?.type === "Literal" && typeof node.value === "string" ? node.value : "";
}

function isTopLevel(ancestors) {
  return ancestors.length >= 2 && ancestors[ancestors.length - 2]?.type === "Program";
}

function classifySurfaces(path, content, structural = {}) {
  const haystack = [
    path,
    content.slice(0, 20000),
    ...(structural.imports || []).map((item) => item.spec),
    ...(structural.exports || []).map((item) => item.name),
    ...(structural.declarations || []).map((item) => item.name),
    ...(structural.sensitiveCalls || []).map((item) => item.name),
    ...(structural.envReads || []).map((item) => item.name),
  ].join("\n");
  const surfaces = [];
  for (const [surface, pattern] of SURFACE_PATTERNS) {
    if (pattern.test(haystack)) surfaces.push(surface);
  }
  return uniqueSorted(surfaces);
}

function isGovernanceCriticalPath(path) {
  return GOVERNANCE_CRITICAL_PATTERNS.some((pattern) => pattern.test(path));
}

function fileKind(path) {
  const ext = extensionOf(path);
  if (JS_EXTENSIONS.has(ext)) return "javascript";
  if (ext === ".json") return "json";
  if (ext === ".md") return "markdown";
  if (ext === ".tf") return "terraform";
  if (path === "Dockerfile") return "dockerfile";
  return ext ? ext.slice(1) : "unknown";
}

function extensionOf(path) {
  const match = /\.([^.\\/]+)$/.exec(path);
  return match ? `.${match[1].toLowerCase()}` : "";
}

function formatParseError(error) {
  return {
    message: truncate(error.message, MAX_ERROR_LENGTH),
    line: error.loc?.line || null,
    column: error.loc?.column || null,
  };
}

function lineOf(node) {
  return node?.loc?.start?.line || null;
}

function sortAndLimit(values, limit) {
  return [...values].sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))).slice(0, limit);
}

function uniqueBy(values, keyFn) {
  const seen = new Set();
  const out = [];
  for (const value of values) {
    const key = keyFn(value);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function uniqueSorted(values) {
  return [...new Set(values.filter(Boolean).map(String))].sort();
}

function importKey(item) {
  return `${item.kind}:${item.spec}:${item.line}`;
}

function exportKey(item) {
  return `${item.kind}:${item.name}:${item.line}`;
}

function declarationKey(item) {
  return `${item.kind}:${item.name}:${item.line}`;
}

function callKey(item) {
  return `${item.name}:${item.line}:${item.enclosing}`;
}

function envKey(item) {
  return `${item.name}:${item.line}`;
}

function literalSignalKey(item) {
  return `${item.value}:${item.line}:${item.context}:${item.enclosing}`;
}

function semanticRiskHintKey(item) {
  return `${item.kind}:${item.file}:${item.line || ""}:${item.context || ""}:${item.evidence || ""}`;
}

function truncate(value, limit) {
  const text = String(value || "");
  return text.length <= limit ? text : `${text.slice(0, limit - 15)}...[truncated]`;
}
