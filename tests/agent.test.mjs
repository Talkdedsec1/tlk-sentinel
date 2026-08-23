import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, appendFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { Tailer } from "../packages/agent/dist/sources/tail.js";
import { toEvent, nginxObservation } from "../packages/agent/dist/sources/parse.js";
import { IntegrityWatch } from "../packages/agent/dist/detectors/integrity.js";
import { ActiveDefense } from "../packages/agent/dist/responders/activedef.js";
import { Store } from "../packages/agent/dist/store.js";
import { dashboardHtml } from "../packages/agent/dist/panel-html.js";

function tmp() {
  return mkdtempSync(join(tmpdir(), "tlks-"));
}

test("parse: nginx line yields ip, sshd falls back to any ipv4", () => {
  const ng = toEvent("nginx", '203.0.113.7 - - [x] "GET / HTTP/1.1" 200 1 "-" "curl"');
  assert.equal(ng.ip, "203.0.113.7");
  const ssh = toEvent("sshd", "Failed password for root from 198.51.100.9 port 22 ssh2");
  assert.equal(ssh.ip, "198.51.100.9");
});

test("parse: nginxObservation extracts method/path/status/ua", () => {
  const o = nginxObservation('203.0.113.7 - - [x] "GET /admin?a=1 HTTP/1.1" 404 512 "-" "sqlmap/1.0"');
  assert.equal(o.ip, "203.0.113.7");
  assert.equal(o.method, "GET");
  assert.equal(o.path, "/admin?a=1");
  assert.equal(o.status, 404);
  assert.equal(o.ua, "sqlmap/1.0");
  assert.equal(nginxObservation("garbage line"), null);
});

test("tailer emits appended lines and survives truncation", async () => {
  const dir = tmp();
  const f = join(dir, "a.log");
  writeFileSync(f, "old\n");
  const seen = [];
  const tl = new Tailer(f);
  tl.on("line", l => seen.push(l));
  tl.start(true);
  await delay(120);
  appendFileSync(f, "one\ntwo\n");
  await delay(400);
  writeFileSync(f, "");
  await delay(200);
  appendFileSync(f, "three\n");
  await delay(400);
  tl.stop();
  rmSync(dir, { recursive: true, force: true });
  assert.ok(!seen.includes("old"), "must not replay pre-existing content");
  assert.ok(seen.includes("one") && seen.includes("two"), `got ${JSON.stringify(seen)}`);
  assert.ok(seen.includes("three"), `truncation not handled: ${JSON.stringify(seen)}`);
});

test("tailer survives logrotate (file replaced by a new inode)", async () => {
  const dir = tmp();
  const f = join(dir, "rot.log");
  writeFileSync(f, "");
  const seen = [];
  const tl = new Tailer(f, 300);
  tl.on("line", l => seen.push(l));
  tl.start(true);
  await delay(150);
  appendFileSync(f, "before\n");
  await delay(500);

  rmSync(f, { force: true });
  writeFileSync(join(dir, "rot.log.1"), "archived\n");
  await delay(500);
  writeFileSync(f, "after\n");
  await delay(1200);

  tl.stop();
  rmSync(dir, { recursive: true, force: true });
  assert.ok(seen.includes("before"), `pre-rotate line missing: ${JSON.stringify(seen)}`);
  assert.ok(seen.includes("after"), `post-rotate line missing: ${JSON.stringify(seen)}`);
});

test("integrity: baseline clean, change detected once", () => {
  const dir = tmp();
  const f = join(dir, "conf.json");
  writeFileSync(f, "a");
  const iw = new IntegrityWatch([f, join(dir, "missing.txt")]);
  assert.equal(iw.watched, 1);
  assert.equal(iw.scan().length, 0);
  writeFileSync(f, "b");
  const hits = iw.scan();
  assert.equal(hits.length, 1);
  assert.match(hits[0].line, /INTEGRITY-BREACH/);
  assert.equal(iw.scan().length, 0, "rebaselines after reporting");
  rmSync(dir, { recursive: true, force: true });
});

test("active defense: off when disabled, permabans after N criticals", async () => {
  const off = new ActiveDefense({ enabled: false, dryRun: true, backend: "nft", set: "s", criticalToPermanent: 1 });
  assert.equal(await off.consider({ ip: "5.5.5.5", severity: "critical" }), false);

  const on = new ActiveDefense({ enabled: true, dryRun: true, backend: "nft", set: "s", criticalToPermanent: 2 });
  assert.equal(await on.consider({ ip: "5.5.5.5", severity: "high" }), false, "non-critical ignored");
  assert.equal(await on.consider({ ip: "5.5.5.5", severity: "critical" }), false, "first critical");
  assert.equal(await on.consider({ ip: "5.5.5.5", severity: "critical" }), true, "second critical permabans");
});

test("active defense counts reputation hits as critical", async () => {
  const ad = new ActiveDefense({ enabled: true, dryRun: true, backend: "nft", set: "s", criticalToPermanent: 1 });
  assert.equal(await ad.consider({ ip: "6.6.6.6", severity: "low", reputation: ["tor"] }), true);
});

test("store: records threats, bans, stats and unban", () => {
  const dir = tmp();
  const st = new Store(join(dir, "d", "t.db"));
  const base = { id: "t1", at: Date.now(), rule: "r1", origin: "nginx", severity: "critical", ip: "2.2.2.2", summary: "s", hits: 3, visibility: "self" };
  st.recordThreat(base, true);
  st.recordThreat({ ...base, id: "t2", severity: "high", ip: "3.3.3.3" }, false);
  st.recordBan("2.2.2.2", Date.now() + 60000, "r1");

  const s = st.stats(3600 * 1000);
  assert.equal(s.total, 2);
  assert.equal(s.banned, 1);
  assert.equal(s.activeBans, 1);
  assert.equal(st.recentThreats(10).length, 2);
  assert.equal(st.activeBans().length, 1);

  st.removeBan("2.2.2.2");
  assert.equal(st.activeBans().length, 0);

  st.recordBan("4.4.4.4", 0, "perm", true);
  assert.equal(st.activeBans().length, 1, "permanent ban ignores expiry");

  st.recordBan("5.5.5.5", Date.now() - 1000, "expired");
  assert.equal(st.activeBans().length, 1, "expired ban not listed");

  st.close();
  rmSync(dir, { recursive: true, force: true });
});

test("panel html: no emoji, uses svg, escapes and localizes", () => {
  for (const lang of ["tr", "en"]) {
    const h = dashboardHtml(lang, "tlk-sentinel · made by talkdedsec");
    assert.equal(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(h), false, `emoji found in ${lang}`);
    assert.ok(h.includes("<svg"), "svg icons present");
    assert.ok(h.includes("made by talkdedsec"), "brand present");
    assert.ok(h.includes(`lang="${lang}"`));
  }
  const tr = dashboardHtml("tr", "x");
  const en = dashboardHtml("en", "x");
  assert.ok(tr.includes("Canlı akış"));
  assert.ok(en.includes("Live feed"));
});
