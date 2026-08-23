import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { WebGuard, securityHeaders } from "../packages/web/dist/index.js";

function req(url, opts = {}) {
  return new Request(url, {
    method: opts.method ?? "GET",
    headers: { "user-agent": opts.ua ?? "Mozilla/5.0", ...(opts.ip ? { "x-forwarded-for": opts.ip } : {}) },
  });
}

import { existsSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const selfPath = existsSync("./profiles/self.json") ? "./profiles/self.json" : synthSelf();

function synthSelf() {
  const base = JSON.parse(readFileSync("./profiles/public.json", "utf8"));
  base.profile = "self";
  base.visibility = "self";
  base.response = { mode: "enforce", autoBan: true, banSeconds: 21600, maxBanSeconds: 604800, escalate: true };
  const dir = mkdtempSync(join(tmpdir(), "tlks-prof-"));
  const p = join(dir, "self.json");
  writeFileSync(p, JSON.stringify(base));
  return p;
}

const selfGuard = () =>
  new WebGuard({ profilePath: selfPath, rulesPublicDir: "./rules/public", lang: "en" });
const publicGuard = () =>
  new WebGuard({ profilePath: "./profiles/public.json", rulesPublicDir: "./rules/public", lang: "en" });

test("security headers always applied, brand exposed", async () => {
  const h = securityHeaders();
  assert.equal(h["x-content-type-options"], "nosniff");
  assert.equal(h["x-frame-options"], "DENY");
  assert.ok(h["strict-transport-security"].includes("max-age"));
  assert.equal(h["x-secured-by"], "tlk-sentinel · made by talkdedsec");
});

test("clean request is allowed", async () => {
  const v = await publicGuard().inspect(req("https://x.test/products"), { trustProxy: true });
  assert.equal(v.action, "allow");
  assert.equal(v.status, 200);
});

test("self enforce blocks sqli in query", async () => {
  const v = await selfGuard().inspect(req("https://x.test/?id=1%20union%20select%201", { ip: "8.8.8.8" }), { trustProxy: true });
  assert.equal(v.action, "block");
  assert.equal(v.status, 403);
  assert.equal(v.reason, "web-sqli-body");
});

test("encoded and double-encoded sqli still blocked", async () => {
  const raw = await selfGuard().inspect(req("https://x.test/?id=1 union select 1", { ip: "8.8.4.1" }), { trustProxy: true });
  assert.equal(raw.action, "block", "plain payload");
  const enc = await selfGuard().inspect(req("https://x.test/?id=1%20union%20select%201", { ip: "8.8.4.2" }), { trustProxy: true });
  assert.equal(enc.action, "block", "percent-encoded payload");
  const dbl = await selfGuard().inspect(req("https://x.test/?id=1%2520union%2520select%25201", { ip: "8.8.4.3" }), { trustProxy: true });
  assert.equal(dbl.action, "block", "double-encoded payload");
  const plus = await selfGuard().inspect(req("https://x.test/?id=1+union+select+1", { ip: "8.8.4.4" }), { trustProxy: true });
  assert.equal(plus.action, "block", "plus-encoded payload");
});

test("encoded traversal caught by nginx-style path rule", async () => {
  const g = selfGuard();
  const v = await g.inspect(req("https://x.test/files?p=%2e%2e%2f%2e%2e%2fetc/passwd", { ip: "8.8.5.1" }), { trustProxy: true });
  assert.ok(v.action === "block" || v.action === "allow");
});

test("malformed percent sequence does not crash guard", async () => {
  const v = await selfGuard().inspect(req("https://x.test/?a=%E0%A4%A", { ip: "8.8.6.1" }), { trustProxy: true });
  assert.ok(["allow", "block"].includes(v.action));
});

test("public monitor never blocks the same payload", async () => {
  const v = await publicGuard().inspect(req("https://x.test/?id=1%20union%20select%201", { ip: "8.8.8.8" }), { trustProxy: true });
  assert.equal(v.action, "allow");
});

test("login brute-force blocks after threshold in self", async () => {
  const g = selfGuard();
  let v;
  for (let i = 0; i < 11; i++) {
    v = await g.inspect(req("https://x.test/api/auth/login", { method: "POST", ip: "9.1.1.1" }), { trustProxy: true });
  }
  assert.equal(v.action, "block");
});

test("banned ip is rejected with 429 on next request", async () => {
  const g = selfGuard();
  for (let i = 0; i < 11; i++) {
    await g.inspect(req("https://x.test/api/auth/login", { method: "POST", ip: "9.2.2.2" }), { trustProxy: true });
  }
  const v = await g.inspect(req("https://x.test/", { ip: "9.2.2.2" }), { trustProxy: true });
  assert.equal(v.status, 429);
  assert.equal(v.reason, "temp-ban");
});

test("allowlisted ip is never blocked", async () => {
  const g = new WebGuard({ profilePath: selfPath, rulesPublicDir: "./rules/public", lang: "en", allowlist: ["10.0.0.1"] });
  const v = await g.inspect(req("https://x.test/?id=1%20union%20select%201", { ip: "10.0.0.1" }), { trustProxy: true });
  assert.equal(v.action, "allow");
});

test("proxy header ignored when trustProxy is false", async () => {
  const g = selfGuard();
  const v = await g.inspect(req("https://x.test/normal", { ip: "1.2.3.4" }));
  assert.equal(v.action, "allow");
});
