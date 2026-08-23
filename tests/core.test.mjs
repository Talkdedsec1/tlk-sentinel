import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Engine, SlidingWindow, Reputation, Anomaly,
  loadProfile, loadRuleDir, compileRule, resolveText, t,
  verifyBrand, brandTag, allows, decodeLayers, normalizeRequestLine, isValidIp,
} from "../packages/core/dist/index.js";

import * as fx from "./helpers.mjs";

const selfProfile = fx.selfProfile();
const publicProfile = fx.publicProfile();
const allRules = fx.allRules();
const pubRules = fx.publicRules();

function feed(engine, n, ip, line, origin = "sshd") {
  let last = [];
  for (let i = 0; i < n; i++) last = engine.ingest({ origin, at: Date.now(), ip, line });
  return last;
}

test("SlidingWindow counts within window and expires", () => {
  const w = new SlidingWindow(1000);
  const now = Date.now();
  assert.equal(w.add("a", now), 1);
  assert.equal(w.add("a", now + 100), 2);
  assert.equal(w.count("a", now + 100), 2);
  assert.equal(w.count("a", now + 5000), 0);
});

test("profile gate: public denies self-only, self allows all", () => {
  assert.equal(allows(publicProfile, "public"), true);
  assert.equal(allows(publicProfile, "self"), false);
  assert.equal(allows(selfProfile, "self"), true);
});

test("engine self enforce: ssh-root-attempt bans after threshold", () => {
  const e = new Engine({ profile: selfProfile, rules: allRules, lang: "en" });
  const line = "Failed password for root from 45.10.10.10 port 22 ssh2";
  const acts = feed(e, 2, "45.10.10.10", line);
  assert.ok(acts.some(a => a.kind === "ban"), "should ban");
  assert.equal(e.isBanned("45.10.10.10"), true);
});

test("engine allowlist skips banning", () => {
  const e = new Engine({ profile: selfProfile, rules: allRules, lang: "en", allowlist: ip => ip === "1.1.1.1" });
  const acts = feed(e, 5, "1.1.1.1", "Failed password for root from 1.1.1.1 port 22 ssh2");
  assert.equal(acts.length, 0);
  assert.equal(e.isBanned("1.1.1.1"), false);
});

test("engine public monitor: high severity alerts but never bans", () => {
  const e = new Engine({ profile: publicProfile, rules: pubRules, lang: "en" });
  const acts = feed(e, 5, "9.9.9.9", "Failed password for root from 9.9.9.9 port 22 ssh2");
  assert.ok(acts.some(a => a.kind === "alert"));
  assert.ok(!acts.some(a => a.kind === "ban"));
  assert.equal(e.isBanned("9.9.9.9"), false);
});

test("engine escalates ban on repeat offender", () => {
  const e = new Engine({ profile: selfProfile, rules: allRules, lang: "en" });
  const line = "Failed password for root from 45.20.20.20 port 22 ssh2";
  const first = feed(e, 2, "45.20.20.20", line);
  const firstBan = first.find(a => a.kind === "ban");
  const second = feed(e, 2, "45.20.20.20", line);
  const secondBan = second.find(a => a.kind === "ban");
  assert.equal(firstBan.seconds, selfProfile.response.banSeconds);
  assert.equal(secondBan.seconds, selfProfile.response.banSeconds * 4);
});

test("engine private rules excluded under public profile", () => {
  const withPriv = new Engine({ profile: publicProfile, rules: allRules, lang: "en" });
  const onlyPub = new Engine({ profile: publicProfile, rules: pubRules, lang: "en" });
  assert.equal(withPriv.activeRuleCount, onlyPub.activeRuleCount);
});

test("reputation enrich escalates blocklisted ip to critical + ban", () => {
  const rep = new Reputation();
  rep.addBlocklistDir("./tests/fixtures/reputation");
  const enrich = ip => { const i = rep.lookup(ip); return { country: i.country, reputation: i.tags }; };
  const e = new Engine({ profile: selfProfile, rules: allRules, lang: "en", enrich });
  const acts = e.ingest({ origin: "nginx", at: Date.now(), ip: "45.9.9.9", line: '45.9.9.9 - - [x] "GET / HTTP/1.1" 200 1 "-" "sqlmap"' });
  const alert = acts.find(a => a.kind === "alert");
  assert.equal(alert.threat.severity, "critical");
  assert.deepEqual(alert.threat.reputation, ["badnet"]);
  assert.ok(acts.some(a => a.kind === "ban"));
});

test("engine.raise produces synthetic threat and bans in self", () => {
  const e = new Engine({ profile: selfProfile, rules: [], lang: "en" });
  const acts = e.raise({ rule: "behavioral-anomaly", origin: "nginx", severity: "high", ip: "7.7.7.7", at: Date.now(), summary: "x", evidence: ["y"], hits: 120, score: 120 });
  assert.ok(acts.some(a => a.kind === "ban"));
});

test("i18n resolves rule summaries and UI strings", () => {
  const r = compileRule({ id: "x", origin: "sshd", match: "a", severity: "low", summary: { tr: "merhaba", en: "hello" } });
  assert.equal(resolveText(r.summary, "tr"), "merhaba");
  assert.equal(resolveText(r.summary, "en"), "hello");
  assert.equal(t("blocked", "tr"), "engellendi");
  assert.equal(t("blocked", "en"), "blocked");
});

test("brand signature verifies and tags correctly", () => {
  assert.equal(verifyBrand(), "verified");
  assert.equal(brandTag(), "tlk-sentinel · made by talkdedsec");
});

test("reputation: cidr, single ip, first-token, ipv6 empty", () => {
  const rep = new Reputation();
  const n = rep.addBlocklistDir("./tests/fixtures/reputation");
  assert.ok(n >= 2);
  assert.equal(rep.lookup("45.9.9.9").blocked, true);   // inside /24
  assert.equal(rep.lookup("45.9.10.1").blocked, false); // outside /24
  assert.equal(rep.lookup("8.8.8.8").blocked, false);
  assert.deepEqual(rep.lookup("::1").tags, []);
});

test("anomaly triggers on path-scan burst", () => {
  const an = new Anomaly({ pathTrigger: 5, rateTrigger: 1000, scoreTrigger: 40 });
  let s;
  for (let i = 0; i < 8; i++) s = an.observe({ ip: "3.3.3.3", at: Date.now(), path: "/p" + i, status: 404 });
  assert.ok(an.triggered(s));
  assert.ok(s.reasons.some(r => r.startsWith("paths=")));
});

test("decodeLayers handles single, double, plus and malformed input", () => {
  assert.equal(decodeLayers("a%20b"), "a b");
  assert.equal(decodeLayers("a%2520b"), "a b");
  assert.equal(decodeLayers("a+b"), "a b");
  assert.equal(decodeLayers("clean"), "clean");
  assert.doesNotThrow(() => decodeLayers("%E0%A4%A"));
  assert.ok(typeof decodeLayers("%E0%A4%A") === "string");
});

test("normalizeRequestLine keeps raw and appends decoded form", () => {
  const out = normalizeRequestLine("GET /?id=1%20union%20select%201");
  assert.ok(out.includes("%20"), "raw preserved");
  assert.ok(/union select/.test(out), "decoded appended");
  assert.equal(normalizeRequestLine("GET /plain"), "GET /plain");
});

test("anomaly cooldown prevents alert storms from one ip", () => {
  const an = new Anomaly({ pathTrigger: 5, rateTrigger: 1000, scoreTrigger: 40, cooldownMs: 60000 });
  const at = Date.now();
  let fires = 0;
  for (let i = 0; i < 30; i++) {
    const s = an.observe({ ip: "3.3.3.4", at: at + i, path: "/p" + i, status: 404 });
    if (an.triggered(s)) fires++;
  }
  assert.equal(fires, 1, `expected single fire, got ${fires}`);

  const later = an.observe({ ip: "3.3.3.4", at: at + 70000, path: "/z", status: 404 });
  assert.equal(an.triggered(later), true, "fires again after cooldown");
});

test("engine.unban clears ban and rule counters", () => {
  const e = new Engine({ profile: selfProfile, rules: allRules, lang: "en" });
  const line = "Failed password for root from 45.30.30.30 port 22 ssh2";
  feed(e, 2, "45.30.30.30", line);
  assert.equal(e.isBanned("45.30.30.30"), true);
  e.unban("45.30.30.30");
  assert.equal(e.isBanned("45.30.30.30"), false);
  const one = e.ingest({ origin: "sshd", at: Date.now(), ip: "45.30.30.30", line });
  assert.equal(one.length, 0, "counters reset, single hit must not re-trigger");
});

test("isValidIp accepts real addresses and rejects injection attempts", () => {
  assert.equal(isValidIp("192.168.1.1"), true);
  assert.equal(isValidIp("8.8.8.8"), true);
  assert.equal(isValidIp("::1"), true);
  assert.equal(isValidIp("2001:db8::ff00:42:8329"), true);

  assert.equal(isValidIp("999.1.1.1"), false);
  assert.equal(isValidIp("1.2.3"), false);
  assert.equal(isValidIp("1.2.3.4 }; drop"), false, "nft argument injection");
  assert.equal(isValidIp("1.2.3.4; rm -rf /"), false);
  assert.equal(isValidIp("$(whoami)"), false);
  assert.equal(isValidIp(""), false);
  assert.equal(isValidIp(null), false);
  assert.equal(isValidIp(42), false);
  assert.equal(isValidIp("a".repeat(200)), false);
});

test("rules strip stateful g/y flags so matching never skips", () => {
  const r = compileRule({ id: "g", origin: "sshd", match: "attack", flags: "gi", severity: "low", summary: "x" });
  assert.equal(r.re.flags.includes("g"), false);
  assert.equal(r.re.test("attack"), true);
  assert.equal(r.re.test("attack"), true, "second call must still match");
});

test("engine truncates oversized lines before matching", () => {
  const rule = compileRule({ id: "tail-probe", origin: "nginx", match: "NEEDLE", severity: "high", summary: "x", threshold: 1 });
  const e = new Engine({ profile: selfProfile, rules: [rule], lang: "en" });
  const near = e.ingest({ origin: "nginx", at: Date.now(), ip: "1.9.9.1", line: "x".repeat(100) + "NEEDLE" });
  assert.ok(near.length > 0, "needle inside limit is matched");
  const far = e.ingest({ origin: "nginx", at: Date.now(), ip: "1.9.9.2", line: "x".repeat(9000) + "NEEDLE" });
  assert.equal(far.length, 0, "content past the cap is not scanned");
});

test("integrity breaches are reported by the community build too", () => {
  const e = new Engine({ profile: publicProfile, rules: pubRules, lang: "en" });
  const acts = e.ingest({ origin: "integrity", at: Date.now(), line: "INTEGRITY-BREACH /etc/app.env aaa -> bbb" });
  const alert = acts.find(a => a.kind === "alert");
  assert.ok(alert, "public profile must surface integrity breaches");
  assert.equal(alert.threat.severity, "critical");
  assert.equal(alert.threat.rule, "integrity-breach");
  assert.ok(!acts.some(a => a.kind === "ban"), "monitor mode still never bans");
});

test("anomaly stays calm on normal traffic", () => {
  const an = new Anomaly();
  let s;
  for (let i = 0; i < 5; i++) s = an.observe({ ip: "4.4.4.4", at: Date.now(), path: "/home", status: 200 });
  assert.equal(an.triggered(s), false);
});
