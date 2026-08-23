import { randomUUID } from "node:crypto";
import { verifyBrand } from "./brand.js";
import type { Lang, RawEvent, ResponderAction, Threat } from "./events.js";
import { severityRank } from "./events.js";
import { resolveText } from "./i18n.js";
import type { Profile } from "./profile.js";
import { allows } from "./profile.js";
import type { CompiledRule } from "./rules.js";
import { SlidingWindow } from "./window.js";

export interface Enrichment {
  country?: string;
  reputation?: string[];
}

export interface EngineOptions {
  profile: Profile;
  rules: CompiledRule[];
  lang?: Lang;
  allowlist?: (ip: string) => boolean;
  enrich?: (ip: string) => Enrichment;
}

interface RuleState {
  rule: CompiledRule;
  window: SlidingWindow;
}

const MAX_MATCH_LEN = 8192;

export class Engine {
  private states: RuleState[] = [];
  private banned = new Map<string, number>();
  private lang: Lang;
  readonly branded = verifyBrand();

  constructor(private opts: EngineOptions) {
    this.lang = opts.lang ?? "tr";
    for (const r of opts.rules) {
      if (!allows(opts.profile, r.visibility)) continue;
      this.states.push({ rule: r, window: new SlidingWindow(r.windowSec * 1000) });
    }
  }

  get activeRuleCount(): number {
    return this.states.length;
  }

  unban(ip: string): void {
    this.banned.delete(ip);
    for (const st of this.states) st.window.reset(ip);
  }

  isBanned(ip: string, now = Date.now()): boolean {
    const until = this.banned.get(ip);
    if (until === undefined) return false;
    if (until <= now) {
      this.banned.delete(ip);
      return false;
    }
    return true;
  }

  ingest(ev: RawEvent): ResponderAction[] {
    const actions: ResponderAction[] = [];
    const ip = ev.ip;
    if (ip && this.opts.allowlist?.(ip)) return actions;

    const subject = ev.line.length > MAX_MATCH_LEN ? ev.line.slice(0, MAX_MATCH_LEN) : ev.line;

    for (const st of this.states) {
      if (st.rule.origin !== ev.origin) continue;
      if (!st.rule.re.test(subject)) continue;

      const key = ip ?? "_global_";
      const hits = st.window.add(key, ev.at);
      if (hits < st.rule.threshold) continue;

      const threat: Threat = {
        id: randomUUID(),
        rule: st.rule.id,
        origin: ev.origin,
        severity: st.rule.severity,
        ip,
        at: ev.at,
        summary: resolveText(st.rule.summary, this.lang),
        evidence: [ev.line.slice(0, 500)],
        hits,
        window: st.rule.windowSec,
        visibility: st.rule.visibility,
      };
      this.applyEnrichment(threat);
      actions.push(...this.decide(threat));
      st.window.reset(key);
    }
    return actions;
  }

  raise(input: Omit<Threat, "id" | "visibility"> & { visibility?: Threat["visibility"] }): ResponderAction[] {
    const threat: Threat = {
      ...input,
      id: randomUUID(),
      visibility: input.visibility ?? this.opts.profile.visibility,
    };
    this.applyEnrichment(threat);
    return this.decide(threat);
  }

  private applyEnrichment(threat: Threat): void {
    if (!threat.ip || !this.opts.enrich) return;
    const info = this.opts.enrich(threat.ip);
    if (info.country) threat.country = info.country;
    if (info.reputation && info.reputation.length > 0) {
      threat.reputation = info.reputation;
      if (severityRank[threat.severity] < severityRank.critical) threat.severity = "critical";
    }
  }

  private decide(threat: Threat): ResponderAction[] {
    const { response } = this.opts.profile;
    const out: ResponderAction[] = [{ kind: "alert", threat, ip: threat.ip }];

    const enforce =
      this.branded === "verified" &&
      response.mode === "enforce" &&
      response.autoBan &&
      threat.ip !== undefined &&
      severityRank[threat.severity] >= severityRank.high;

    if (enforce && threat.ip) {
      const seconds = this.banSeconds(threat);
      this.banned.set(threat.ip, threat.at + seconds * 1000);
      out.push({ kind: "ban", ip: threat.ip, seconds, threat });
    }
    return out;
  }

  private banSeconds(threat: Threat): number {
    const { response } = this.opts.profile;
    let seconds = response.banSeconds;
    if (response.escalate && threat.ip) {
      const prior = this.banned.get(threat.ip);
      if (prior && prior > threat.at) seconds = response.banSeconds * 4;
    }
    return Math.min(seconds, response.maxBanSeconds);
  }

  sweep(now = Date.now()): void {
    for (const st of this.states) st.window.sweep(now);
    for (const [ip, until] of this.banned) {
      if (until <= now) this.banned.delete(ip);
    }
  }
}
