import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const REPO_ROOT = path.resolve(new URL("..", import.meta.url).pathname);
const SKIP_DIRS = new Set([".git", "node_modules"]);

test("public auth-broker repo does not contain tenant deployment inventory", async () => {
  const files = await listFiles(REPO_ROOT);
  const bannedPathFragments = [
    ["tenant", "pin", "targets"].join("-"),
    ["rotate", "tenant", "tee", "pins"].join("-"),
  ];
  const bannedContent = [
    { needle: ["emily", "loves", "justin"].join("-"), scope: "all" },
    { needle: ["Justin", "Wickett"].join(" "), scope: "all" },
    { needle: ["Emily", "Poplawski"].join(" "), scope: "all" },
    { needle: "019a8314-3e69-7bb1-b8ee-19bc54723979", scope: "route-bundles" },
    { needle: "api-019a8314-3e69-7bb1-b8ee-19bc54723979.femled.ai", scope: "route-bundles" },
    { needle: "app-019a8314-3e69-7bb1-b8ee-19bc54723979.femled.ai", scope: "route-bundles" },
  ];

  for (const file of files) {
    const relativePath = path.relative(REPO_ROOT, file);
    for (const fragment of bannedPathFragments) {
      assert(
        !relativePath.includes(fragment),
        `tenant deployment inventory path must not be present: ${relativePath}`
      );
    }

    const body = await fs.readFile(file, "utf8").catch(() => "");
    for (const { needle, scope } of bannedContent) {
      if (scope === "route-bundles" && !relativePath.startsWith("route-bundles/")) {
        continue;
      }
      assert(
        !body.toLowerCase().includes(needle.toLowerCase()),
        `public repo content must not contain tenant/person identifier ${needle} in ${relativePath}`
      );
    }
  }
});

async function listFiles(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...await listFiles(fullPath));
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  return files;
}
