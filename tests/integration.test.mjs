import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, appendFileSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const NODE_FLAGS = ["--disable-warning=ExperimentalWarning"];

const selfProfilePath = (() => {
  if (existsSync("./profiles/self.json")) return null;
  const base = JSON.parse(readFileSync("./profiles/public.json", "utf8"));
  base.profile = "self";
  base.visibility = "self";
  base.response = { mode: "enforce", autoBan: true, banSeconds: 21600, maxBanSeconds: 604800, escalate: true };
  base.detectors = { ...base.detectors, loadPrivateRules: false, activeDeception: true };
  const p = join(mkdtempSync(join(tmpdir(), "tlks-prof-")), "self.json");
  writeFileSync(p, JSON.stringify(base));
  return p;
})();

function startAgent(env, port) {
  const extra = env.TLK_PROFILE === "self" && selfProfilePath ? { TLK_PROFILE_PATH: selfProfilePath } : {};
  return spawn(process.execPath, [...NODE_FLAGS, "packages/agent/dist/index.js"], {
    env: { ...process.env, TLK_PANEL_PORT: String(port), ...env, ...extra },
    stdio: ["ignore", "pipe", "pipe"],
  });
}

async function waitFor(fn, tries = 40, gap = 150) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fn();
      if (r) return r;
    } catch {}
    await delay(gap);
  }
  return null;
}

test("agent end-to-end: tail -> detect -> ban -> store -> panel API", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tlks-e2e-"));
  const ngLog = join(dir, "access.log");
  writeFileSync(ngLog, "");
  const port = 8850;
  const token = "t0ken";

  const agent = startAgent({
    TLK_PROFILE: "self",
    TLK_LANG: "en",
    TLK_SSHD_LOG: "",
    TLK_NGINX_LOG: ngLog,
    TLK_FW_DRYRUN: "1",
    TLK_PANEL_TOKEN: token,
    TLK_DB: join(dir, "e2e.db"),
  }, port);

  let out = "";
  agent.stdout.on("data", d => (out += d));
  agent.stderr.on("data", d => (out += d));

  const base = `http://127.0.0.1:${port}`;
  const get = async (p, tok = token) => {
    const r = await fetch(`${base}${p}`, { headers: tok ? { "x-panel-token": tok } : {} });
    return { status: r.status, body: r.status === 200 ? await r.json() : null };
  };

  try {
    const up = await waitFor(async () => (await fetch(`${base}/api/stats`, { headers: { "x-panel-token": token } })).ok);
    assert.ok(up, `panel never came up:\n${out}`);

    const unauth = await fetch(`${base}/api/stats`);
    assert.equal(unauth.status, 401, "panel must reject missing token");

    const attack = '198.51.100.5 - - [x] "GET /?id=1 union select 1 HTTP/1.1" 200 12 "-" "sqlmap/1.0"\n';
    const stats = await waitFor(async () => {
      appendFileSync(ngLog, attack);
      const s = await get("/api/stats");
      return s.body && s.body.total > 0 ? s.body : null;
    });
    assert.ok(stats, `no threat recorded:\n${out}`);
    assert.ok(stats.banned > 0, "attack should be banned in self profile");

    const threats = await get("/api/threats");
    assert.ok(threats.body.length > 0);
    assert.equal(threats.body[0].ip, "198.51.100.5");

    const bans = await waitFor(async () => {
      const b = await get("/api/bans");
      return b.body && b.body.length > 0 ? b.body : null;
    });
    assert.ok(bans, "ban not persisted");

    const unban = await fetch(`${base}/api/unban`, {
      method: "POST",
      headers: { "x-panel-token": token, "content-type": "application/json" },
      body: JSON.stringify({ ip: bans[0].ip }),
    });
    assert.equal(unban.status, 200);
    const after = await get("/api/bans");
    assert.equal(after.body.find(b => b.ip === bans[0].ip), undefined, "unban must remove from list");

    const html = await fetch(`${base}/?token=${token}`);
    assert.equal(html.status, 200);
    const page = await html.text();
    assert.ok(page.includes("<svg"), "panel serves svg icons");

    assert.match(out, /signature ok/, "brand banner must verify");
    assert.match(out, /\[dry-run\] ban/, "dry-run must not touch real firewall");
  } finally {
    agent.kill();
    await delay(400);
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  }
});

test("panel rejects malformed ip and bad duration on ban endpoints", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tlks-val-"));
  const port = 8852;
  const token = "v";
  const agent = startAgent({
    TLK_PROFILE: "self", TLK_SSHD_LOG: "", TLK_NGINX_LOG: "",
    TLK_FW_DRYRUN: "1", TLK_PANEL_TOKEN: token, TLK_DB: join(dir, "v.db"),
  }, port);
  let out = "";
  agent.stdout.on("data", d => (out += d));

  const post = (path, body) => fetch(`http://127.0.0.1:${port}${path}`, {
    method: "POST",
    headers: { "x-panel-token": token, "content-type": "application/json" },
    body: JSON.stringify(body),
  });

  try {
    const up = await waitFor(async () => (await fetch(`http://127.0.0.1:${port}/api/stats`, { headers: { "x-panel-token": token } })).ok);
    assert.ok(up, `panel never came up:\n${out}`);

    for (const bad of ["1.2.3.4 }; drop", "$(id)", "999.999.999.999", "", null, 7]) {
      const r = await post("/api/ban", { ip: bad, seconds: 60 });
      assert.equal(r.status, 400, `ban accepted malformed ip: ${JSON.stringify(bad)}`);
    }
    const badDur = await post("/api/ban", { ip: "1.2.3.4", seconds: -5 });
    assert.equal(badDur.status, 400, "negative duration must be rejected");
    const huge = await post("/api/ban", { ip: "1.2.3.4", seconds: 99999999 });
    assert.equal(huge.status, 400, "absurd duration must be rejected");

    const badUnban = await post("/api/unban", { ip: "not-an-ip" });
    assert.equal(badUnban.status, 400);

    const ok = await post("/api/ban", { ip: "203.0.113.9", seconds: 60 });
    assert.equal(ok.status, 200, "valid ban must still work");

    const stats = await fetch(`http://127.0.0.1:${port}/api/stats`, { headers: { "x-panel-token": token } });
    assert.equal(stats.headers.get("x-content-type-options"), "nosniff", "panel sets safe headers");
  } finally {
    agent.kill();
    await delay(300);
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  }
});

test("panel refuses to bind non-loopback without token", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tlks-bind-"));
  const agent = startAgent({
    TLK_PROFILE: "public",
    TLK_SSHD_LOG: "",
    TLK_NGINX_LOG: "",
    TLK_PANEL_HOST: "0.0.0.0",
    TLK_PANEL_TOKEN: "",
    TLK_DB: join(dir, "b.db"),
  }, 8851);
  let out = "";
  agent.stdout.on("data", d => (out += d));
  await delay(1500);
  agent.kill();
  await delay(300);
  try { rmSync(dir, { recursive: true, force: true }); } catch {}
  assert.match(out, /panel DISABLED/, `expected refusal, got:\n${out}`);
});

test("public build strips self artifacts and passes checks", () => {
  execFileSync(process.execPath, ["scripts/build-public.mjs"], { stdio: "pipe" });
  assert.equal(existsSync("dist-public/rules/private"), false, "private rules leaked");
  assert.equal(existsSync("dist-public/profiles/self.json"), false, "self profile leaked");
  assert.equal(existsSync("dist-public/scripts/.brand-private.pem"), false, "brand key leaked");
  assert.ok(existsSync("dist-public/rules/public"), "public rules missing");
  assert.ok(existsSync("dist-public/LICENSE"), "license missing");
  const info = readFileSync("dist-public/BUILD-INFO.txt", "utf8");
  assert.match(info, /leak scan: clean/);
  assert.match(info, /structural: clean/);
  const pub = JSON.parse(readFileSync("dist-public/profiles/public.json", "utf8"));
  assert.equal(pub.response.mode, "monitor");
  assert.equal(pub.response.autoBan, false);
  assert.equal(pub.detectors.loadPrivateRules, false);
});

test("a rejected build never overwrites the previous good output", () => {
  execFileSync(process.execPath, ["scripts/build-public.mjs"], { stdio: "pipe" });
  const goodProfile = readFileSync("dist-public/profiles/public.json", "utf8");
  const goodInfo = readFileSync("dist-public/BUILD-INFO.txt", "utf8");
  assert.equal(JSON.parse(goodProfile).response.autoBan, false);

  const backup = readFileSync("./profiles/public.json", "utf8");
  const poisoned = JSON.parse(backup);
  poisoned.response.autoBan = true;
  writeFileSync("./profiles/public.json", JSON.stringify(poisoned, null, 2));

  let rejected = false;
  try {
    execFileSync(process.execPath, ["scripts/build-public.mjs"], { stdio: "pipe" });
  } catch {
    rejected = true;
  } finally {
    writeFileSync("./profiles/public.json", backup);
  }

  assert.ok(rejected, "poisoned profile must reject the build");
  assert.equal(
    readFileSync("dist-public/profiles/public.json", "utf8"),
    goodProfile,
    "rejected build must not leave an unsafe profile in the output",
  );
  assert.equal(readFileSync("dist-public/BUILD-INFO.txt", "utf8"), goodInfo);
  assert.equal(existsSync(".dist-public-stage"), false, "staging dir must be cleaned up");
});

test("public build is rejected if self profile sneaks in", () => {
  writeFileSync("dist-public-probe-marker", "");
  rmSync("dist-public-probe-marker", { force: true });
  const bad = JSON.parse(readFileSync("./profiles/public.json", "utf8"));
  bad.response.autoBan = true;
  writeFileSync("./profiles/_public.bak.json", readFileSync("./profiles/public.json"));
  writeFileSync("./profiles/public.json", JSON.stringify(bad, null, 2));
  let failed = false;
  try {
    execFileSync(process.execPath, ["scripts/build-public.mjs"], { stdio: "pipe" });
  } catch {
    failed = true;
  } finally {
    writeFileSync("./profiles/public.json", readFileSync("./profiles/_public.bak.json"));
    rmSync("./profiles/_public.bak.json", { force: true });
  }
  assert.ok(failed, "unsafe public profile must reject the build");
});
