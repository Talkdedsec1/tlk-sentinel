import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { LocalizedText, Origin, Severity, Visibility } from "./events.js";

export interface Rule {
  id: string;
  origin: Origin;
  match: string;
  flags?: string;
  severity: Severity;
  summary: string | LocalizedText;
  threshold?: number;
  windowSec?: number;
  visibility?: Visibility;
}

export interface CompiledRule extends Omit<Rule, "summary"> {
  re: RegExp;
  summary: LocalizedText;
  visibility: Visibility;
  threshold: number;
  windowSec: number;
}

export function compileRule(r: Rule): CompiledRule {
  const summary: LocalizedText =
    typeof r.summary === "string" ? { tr: r.summary, en: r.summary } : r.summary;
  const flags = (r.flags ?? "").replace(/[gy]/g, "");
  return {
    ...r,
    summary,
    re: new RegExp(r.match, flags),
    visibility: r.visibility ?? "public",
    threshold: r.threshold ?? 1,
    windowSec: r.windowSec ?? 60,
  };
}

export function loadRuleDir(dir: string): CompiledRule[] {
  let files: string[];
  try {
    files = readdirSync(dir).filter((f) => f.endsWith(".json"));
  } catch {
    return [];
  }
  const out: CompiledRule[] = [];
  for (const f of files) {
    const raw = JSON.parse(readFileSync(join(dir, f), "utf8")) as Rule[] | Rule;
    const list = Array.isArray(raw) ? raw : [raw];
    for (const r of list) out.push(compileRule(r));
  }
  return out;
}
