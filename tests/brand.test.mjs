import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, cpSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

function withTamperedBrand(replacement) {
  const dir = mkdtempSync(join(tmpdir(), "tlks-brand-"));
  cpSync(resolve("packages/core/dist"), join(dir, "dist"), { recursive: true });
  const brandPath = join(dir, "dist", "brand.js");
  const src = readFileSync(brandPath, "utf8");
  writeFileSync(brandPath, src.replace("made by talkdedsec", replacement));
  return dir;
}

function runInDir(dir, body) {
  const script = join(dir, "probe.mjs");
  const entry = pathToFileURL(join(dir, "dist", "index.js")).href;
  writeFileSync(script, `import * as core from ${JSON.stringify(entry)};\n${body}\n`);
  return execFileSync(process.execPath, [script], { encoding: "utf8" });
}

test("brand verifies in a pristine build", () => {
  const out = runInDir(withTamperedBrand("made by talkdedsec"), `
    console.log(JSON.stringify({ state: core.verifyBrand(), tag: core.brandTag() }));
  `);
  const r = JSON.parse(out);
  assert.equal(r.state, "verified");
  assert.equal(r.tag, "tlk-sentinel · made by talkdedsec");
});

test("removing the attribution breaks the signature", () => {
  const dir = withTamperedBrand("made by someone-else");
  try {
    const r = JSON.parse(runInDir(dir, `
      console.log(JSON.stringify({ state: core.verifyBrand(), tag: core.brandTag(), banner: core.brandBanner() }));
    `));
    assert.equal(r.state, "tampered");
    assert.equal(r.tag, "tlk-sentinel · UNLICENSED-COPY");
    assert.match(r.banner, /SIGNATURE TAMPERED/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a tampered build refuses to enforce bans", () => {
  const dir = withTamperedBrand("made by someone-else");
  try {
    const profile = {
      profile: "self", label: "t", visibility: "self",
      response: { mode: "enforce", autoBan: true, banSeconds: 3600, maxBanSeconds: 86400, escalate: true },
      detectors: { loadPrivateRules: false, counterScan: false, activeDeception: true },
      alerts: { channels: ["stdout"] },
    };
    const profilePath = join(dir, "self.json");
    writeFileSync(profilePath, JSON.stringify(profile));

    const out = runInDir(dir, `
      const profile = core.loadProfile(${JSON.stringify(profilePath)});
      const rules = core.loadRuleDir(${JSON.stringify(resolve("rules/public"))});
      const e = new core.Engine({ profile, rules, lang: "en" });
      let acts = [];
      for (let i = 0; i < 6; i++) {
        acts = e.ingest({ origin: "sshd", at: Date.now(), ip: "45.60.60.60",
          line: "Failed password for root from 45.60.60.60 port 22 ssh2" });
      }
      console.log(JSON.stringify({
        branded: e.branded,
        alerted: acts.some(a => a.kind === "alert"),
        banned: acts.some(a => a.kind === "ban"),
        isBanned: e.isBanned("45.60.60.60"),
      }));
    `);
    const r = JSON.parse(out);
    assert.equal(r.branded, "tampered");
    assert.equal(r.alerted, true, "detection still reports");
    assert.equal(r.banned, false, "tampered build must not ban");
    assert.equal(r.isBanned, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
