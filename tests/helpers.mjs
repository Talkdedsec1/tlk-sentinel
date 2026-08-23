import { existsSync } from "node:fs";
import { loadProfile, loadRuleDir, compileRule } from "../packages/core/dist/index.js";

const SELF_PROFILE = "./profiles/self.json";
const PRIVATE_RULES = "./rules/private";

export const hasSelfProfile = existsSync(SELF_PROFILE);
export const hasPrivateRules = existsSync(PRIVATE_RULES);

export function selfProfile() {
  if (hasSelfProfile) return loadProfile(SELF_PROFILE);
  const base = loadProfile("./profiles/public.json");
  return {
    ...base,
    profile: "self",
    visibility: "self",
    response: { mode: "enforce", autoBan: true, banSeconds: 21600, maxBanSeconds: 604800, escalate: true },
    detectors: { ...base.detectors, loadPrivateRules: hasPrivateRules, activeDeception: true },
  };
}

export function publicProfile() {
  return loadProfile("./profiles/public.json");
}

export function publicRules() {
  return loadRuleDir("./rules/public");
}

export function allRules() {
  const rules = loadRuleDir("./rules/public");
  if (hasPrivateRules) return [...rules, ...loadRuleDir(PRIVATE_RULES)];
  return [...rules, ...fallbackPrivateRules()];
}

function fallbackPrivateRules() {
  return [
    compileRule({
      id: "honeypot-admin-bait",
      origin: "nginx",
      match: "(/tlk-admin-real|/owner-panel)",
      flags: "i",
      severity: "critical",
      summary: { tr: "Bal kabı yoluna dokunuldu", en: "Honeypot path touched" },
      threshold: 1,
      windowSec: 300,
      visibility: "self",
    }),
    compileRule({
      id: "integrity-breach",
      origin: "integrity",
      match: "INTEGRITY-BREACH",
      severity: "critical",
      summary: { tr: "İzlenen kritik dosya değişti", en: "Watched critical file changed" },
      threshold: 1,
      windowSec: 3600,
      visibility: "self",
    }),
  ];
}
