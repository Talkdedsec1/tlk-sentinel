import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Reputation, ipFamily } from "../packages/core/dist/index.js";
import { DiscordAlerter, StdoutAlerter } from "../packages/agent/dist/responders/alert.js";
import { Firewall } from "../packages/agent/dist/responders/firewall.js";
import { loadConfig } from "../packages/agent/dist/config.js";

function threat(over = {}) {
  return {
    id: "t", rule: "ssh-bruteforce", origin: "sshd", severity: "high",
    ip: "203.0.113.5", at: Date.now(), summary: "SSH brute-force",
    evidence: ["Failed password for root"], hits: 5, window: 120, visibility: "public",
    ...over,
  };
}

async function captureWebhook(run) {
  const received = [];
  const server = createServer((req, res) => {
    const chunks = [];
    req.on("data", c => chunks.push(c));
    req.on("end", () => {
      try { received.push(JSON.parse(Buffer.concat(chunks).toString())); } catch { received.push(null); }
      res.writeHead(204).end();
    });
  });
  await new Promise(r => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/hook`;
  try {
    await run(url);
  } finally {
    await new Promise(r => server.close(r));
  }
  return received;
}

test("DiscordAlerter posts an embed carrying severity, ip and brand footer", async () => {
  const got = await captureWebhook(async url => {
    await new DiscordAlerter(url, "en").send(threat(), true);
  });
  assert.equal(got.length, 1, "webhook must be called once");
  const body = got[0];
  assert.equal(body.username, "tlk-sentinel");
  const e = body.embeds[0];
  assert.match(e.title, /BAN/);
  assert.ok(e.title.includes("SSH brute-force"));
  assert.equal(e.footer.text, "tlk-sentinel · made by talkdedsec");
  const field = n => e.fields.find(f => f.name === n)?.value;
  assert.equal(field("ip"), "203.0.113.5");
  assert.equal(field("severity"), "high");
  assert.equal(field("rule"), "ssh-bruteforce");
});

test("DiscordAlerter marks non-banned alerts differently", async () => {
  const got = await captureWebhook(async url => {
    await new DiscordAlerter(url, "en").send(threat(), false);
  });
  assert.match(got[0].embeds[0].title, /WARN/);
});

test("DiscordAlerter swallows an unreachable webhook", async () => {
  const alerter = new DiscordAlerter("http://127.0.0.1:1/nope", "en");
  await assert.doesNotReject(() => alerter.send(threat(), false));
});

test("StdoutAlerter localizes the ban tag", () => {
  const lines = [];
  const orig = process.stdout.write;
  process.stdout.write = s => { lines.push(String(s)); return true; };
  try {
    new StdoutAlerter("en").send(threat(), true);
    new StdoutAlerter("tr").send(threat({ summary: "SSH deneme" }), false);
  } finally {
    process.stdout.write = orig;
  }
  assert.match(lines[0], /\[BAN\] HIGH ssh-bruteforce ip=203\.0\.113\.5/);
  assert.match(lines[1], /\[UYARI\].*SSH deneme/);
});

test("firewall rejects malformed ip and absurd durations in dry-run", async () => {
  const lines = [];
  const orig = process.stdout.write;
  process.stdout.write = s => { lines.push(String(s)); return true; };
  const fw = new Firewall({ backend: "nft", dryRun: true, chain: "c" }, "en");
  try {
    await fw.ban("1.2.3.4 }; drop", 60);
    await fw.ban("203.0.113.9", -1);
    await fw.ban("203.0.113.9", 60);
    await fw.unban("$(id)");
  } finally {
    process.stdout.write = orig;
  }
  const text = lines.join("");
  assert.match(text, /rejected malformed ip/);
  assert.match(text, /rejected ban duration/);
  assert.match(text, /\[dry-run\] ban 203\.0\.113\.9 60s/);
  assert.equal(/\[dry-run\] ban 1\.2\.3\.4/.test(text), false, "malformed ip must never reach the backend");
});

test("reputation reads a country table without marking addresses blocked", () => {
  const dir = mkdtempSync(join(tmpdir(), "tlks-geo-"));
  const f = join(dir, "country.csv");
  writeFileSync(f, "# cidr,cc\n81.213.0.0/16,TR\n8.8.8.0/24,US\n");
  const rep = new Reputation();
  const n = rep.addCountryFile(f);
  assert.equal(n, 2);

  const tr = rep.lookup("81.213.4.9");
  assert.equal(tr.country, "TR");
  assert.equal(tr.blocked, false, "country data must not ban anyone");

  const us = rep.lookup("8.8.8.8");
  assert.equal(us.country, "US");
  assert.equal(rep.lookup("1.1.1.1").country, undefined);
  assert.equal(rep.addCountryFile(join(dir, "missing.csv")), 0);
  rmSync(dir, { recursive: true, force: true });
});

test("reputation blocklist and country data coexist on one address", () => {
  const dir = mkdtempSync(join(tmpdir(), "tlks-mix-"));
  writeFileSync(join(dir, "bad.txt"), "9.9.9.0/24\n");
  const geo = join(dir, "geo.csv");
  writeFileSync(geo, "9.9.9.0/24,NL\n");
  const rep = new Reputation();
  rep.addBlocklistDir(dir);
  rep.addCountryFile(geo);
  const hit = rep.lookup("9.9.9.7");
  assert.equal(hit.blocked, true);
  assert.deepEqual(hit.tags, ["bad"]);
  assert.equal(hit.country, "NL");
  rmSync(dir, { recursive: true, force: true });
});

test("ipFamily classifies v4, v6 and rejects junk", () => {
  assert.equal(ipFamily("192.168.0.1"), 4);
  assert.equal(ipFamily("::1"), 6);
  assert.equal(ipFamily("2001:db8::1"), 6);
  assert.equal(ipFamily("nope"), null);
  assert.equal(ipFamily("1.2.3.4; rm"), null);
});

test("loadConfig applies safe defaults and parses env", () => {
  const saved = { ...process.env };
  const clear = ["TLK_PROFILE", "TLK_LANG", "TLK_FW_DRYRUN", "TLK_FW_BACKEND", "TLK_ALLOWLIST",
                 "TLK_PANEL", "TLK_PANEL_HOST", "TLK_PANEL_PORT", "TLK_PANEL_TOKEN",
                 "TLK_INTEGRITY", "TLK_ANOMALY", "TLK_PROFILE_PATH", "TLK_SSHD_LOG", "TLK_NGINX_LOG"];
  for (const k of clear) delete process.env[k];
  try {
    const d = loadConfig("/srv/app");
    assert.match(d.profilePath, /public\.json$/, "defaults to the passive profile");
    assert.equal(d.lang, "tr");
    assert.equal(d.firewall.dryRun, true, "dry-run must be the default");
    assert.equal(d.panel.host, "127.0.0.1", "panel must default to loopback");
    assert.equal(d.panel.token, null);
    assert.deepEqual(d.allowlist, ["127.0.0.1", "::1"]);
    assert.deepEqual(d.integrityTargets, []);
    assert.equal(d.anomaly, true);

    process.env.TLK_LANG = "en";
    process.env.TLK_FW_DRYRUN = "0";
    process.env.TLK_ALLOWLIST = "10.0.0.1, 10.0.0.2 ,";
    process.env.TLK_INTEGRITY = "/etc/a.conf, /etc/b.conf";
    process.env.TLK_PANEL_PORT = "9001";
    process.env.TLK_ANOMALY = "0";
    process.env.TLK_PROFILE_PATH = "/custom/self.json";
    const c = loadConfig("/srv/app");
    assert.equal(c.lang, "en");
    assert.equal(c.firewall.dryRun, false);
    assert.deepEqual(c.allowlist, ["10.0.0.1", "10.0.0.2"]);
    assert.deepEqual(c.integrityTargets, ["/etc/a.conf", "/etc/b.conf"]);
    assert.equal(c.panel.port, 9001);
    assert.equal(c.anomaly, false);
    assert.match(c.profilePath, /self\.json$/);
  } finally {
    for (const k of clear) delete process.env[k];
    Object.assign(process.env, saved);
  }
});
