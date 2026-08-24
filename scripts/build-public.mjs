import { cp, rm, mkdir, writeFile, readFile, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve, dirname, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(root, "dist-public");

const excludedPaths = [
  "profiles/self.json",
  "rules/private",
  ".env",
  "node_modules",
  "dist-public",
  ".git",
  "packages/core/dist",
  "packages/agent/dist",
  "packages/web/dist",
  "scripts/sign-brand.mjs",
  "scripts/.brand-private.pem",
].map((p) => resolve(root, p));

const excludedNames = [/\.tsbuildinfo$/, /^\.env$/, /\.db(-wal|-shm)?$/, /\.log$/];

function keep(p) {
  for (const e of excludedPaths) {
    if (p === e || p.startsWith(e + sep)) return false;
  }
  const name = p.slice(p.lastIndexOf(sep) + 1);
  return !excludedNames.some((re) => re.test(name));
}

const include = [
  "packages",
  "profiles/public.json",
  "rules/public",
  "data/reputation",
  "tests",
  "scripts/build-public.mjs",
  "scripts/check-test-count.mjs",
  "CHANGELOG.md",
  "deploy",
  "assets",
  ".github",
  "package.json",
  "LICENSE",
  "README.md",
  "SECURITY.md",
  ".env.example",
  ".gitignore",
];

const stage = resolve(root, ".dist-public-stage");
await rm(stage, { recursive: true, force: true });
await mkdir(stage, { recursive: true });

for (const rel of include) {
  const src = resolve(root, rel);
  if (!existsSync(src)) continue;
  await cp(src, resolve(stage, rel), { recursive: true, filter: keep });
}

const leakHits = [];
async function walk(dir) {
  for (const name of await readdir(dir)) {
    const full = resolve(dir, name);
    const s = await stat(full);
    if (s.isDirectory()) {
      if (name === "node_modules" || name === ".git") continue;
      await walk(full);
    } else if (/\.(json|ts|env|pem)$/.test(name)) {
      const text = await readFile(full, "utf8");
      const secret =
        /hmac_secret\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{12,}/i.test(text) ||
        /TLK_DISCORD_WEBHOOK=\s*https?:\/\//i.test(text) ||
        /BEGIN (?:EC |RSA )?PRIVATE KEY/.test(text);
      if (secret && !/\.env\.example$/.test(name)) leakHits.push(full.replace(out, "dist-public"));
    }
  }
}
await walk(stage);

const structural = [];
if (existsSync(resolve(stage, "rules/private"))) structural.push("rules/private present");
if (existsSync(resolve(stage, "profiles/self.json"))) structural.push("profiles/self.json present");
if (existsSync(resolve(stage, "scripts/.brand-private.pem"))) structural.push("brand private key present");

const pub = JSON.parse(await readFile(resolve(stage, "profiles/public.json"), "utf8"));
const bad = pub.response.autoBan || pub.response.mode !== "monitor" || pub.detectors.loadPrivateRules;

if (leakHits.length || bad || structural.length) {
  await rm(stage, { recursive: true, force: true });
  console.error("PUBLIC BUILD REJECTED (nothing was written):");
  if (bad) console.error("  public.json not in safe default (autoBan/enforce/private on)");
  for (const h of structural) console.error("  structural:", h);
  for (const h of leakHits) console.error("  secret:", h);
  process.exit(1);
}

await writeFile(
  resolve(stage, "BUILD-INFO.txt"),
  `tlk-sentinel public build\nbuilt: ${new Date().toISOString()}\n` +
    `leak scan: clean\nstructural: clean\n`,
);

await mkdir(out, { recursive: true });
for (const entry of await readdir(out)) {
  if (entry === ".git" || entry === "node_modules") continue;
  await rm(resolve(out, entry), { recursive: true, force: true });
}
for (const entry of await readdir(stage)) {
  await cp(resolve(stage, entry), resolve(out, entry), { recursive: true });
}
await rm(stage, { recursive: true, force: true });

console.log(`public build ready -> ${out} (leak + structural clean)`);
