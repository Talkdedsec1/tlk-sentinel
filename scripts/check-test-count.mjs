import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const output = execFileSync(
  process.execPath,
  ["--disable-warning=ExperimentalWarning", "--test", "tests/*.test.mjs"],
  {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  },
);

const actual = Number(output.match(/^ℹ tests (\d+)$/m)?.[1]);
if (!actual) {
  console.error("could not read the test count out of the runner output");
  process.exit(1);
}

const readme = readFileSync(resolve(root, "README.md"), "utf8");

const claims = [
  ["badge", /tests-(\d+)%20passing/],
  ["prose", /(\d+) tests on Node's built-in runner/],
  ["layout", /tests\/\s+(\d+) tests, no framework/],
  ["türkçe", /`npm test` — (\d+) test,/],
];

const wrong = [];
for (const [where, re] of claims) {
  const hit = readme.match(re);
  if (!hit) wrong.push(`${where}: the sentence this check anchors on is gone from README.md`);
  else if (Number(hit[1]) !== actual) wrong.push(`${where}: README says ${hit[1]}, the suite has ${actual}`);
}

if (wrong.length) {
  console.error(`test count drifted (${actual} tests):`);
  for (const line of wrong) console.error("  " + line);
  process.exit(1);
}

console.log(`README matches the suite: ${actual} tests`);
