import {
  Engine,
  brandTag,
  loadProfile,
  loadRuleDir,
  normalizeRequestLine,
  type CompiledRule,
  type Lang,
  type Profile,
} from "@tlk-sentinel/core";

export interface GuardVerdict {
  action: "allow" | "block" | "challenge";
  status: number;
  reason?: string;
  headers: Record<string, string>;
}

export interface GuardInit {
  profilePath: string;
  rulesPublicDir: string;
  rulesPrivateDir?: string;
  lang?: Lang;
  allowlist?: string[];
  trustedProxy?: boolean;
}

const BASE_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "geolocation=(), microphone=(), camera=()",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-secured-by": brandTag(),
};

export class WebGuard {
  private engine: Engine;
  private profile: Profile;
  private allow: Set<string>;

  constructor(init: GuardInit) {
    this.profile = loadProfile(init.profilePath);
    const rules: CompiledRule[] = loadRuleDir(init.rulesPublicDir).filter(
      (r) => r.origin === "web-middleware",
    );
    if (this.profile.detectors.loadPrivateRules && init.rulesPrivateDir) {
      rules.push(
        ...loadRuleDir(init.rulesPrivateDir).filter((r) => r.origin === "web-middleware"),
      );
    }
    this.allow = new Set(init.allowlist ?? ["127.0.0.1", "::1"]);
    this.engine = new Engine({
      profile: this.profile,
      rules,
      lang: init.lang ?? "tr",
      allowlist: (ip) => this.allow.has(ip),
    });
  }

  clientIp(req: Request, trustProxy: boolean): string | undefined {
    if (trustProxy) {
      const xff = req.headers.get("x-forwarded-for");
      if (xff) return xff.split(",")[0]?.trim();
    }
    return undefined;
  }

  async inspect(req: Request, opts?: { trustProxy?: boolean }): Promise<GuardVerdict> {
    const ip = this.clientIp(req, opts?.trustProxy ?? false);
    if (ip && this.engine.isBanned(ip)) {
      return { action: "block", status: 429, reason: "temp-ban", headers: BASE_HEADERS };
    }

    const url = new URL(req.url);
    const line = normalizeRequestLine(
      `${req.method} ${url.pathname}${url.search} ua=${req.headers.get("user-agent") ?? ""}`,
    );
    const actions = this.engine.ingest({ origin: "web-middleware", at: Date.now(), ip, line });

    const worst = actions.find((a) => a.kind === "ban" || a.kind === "alert");
    if (worst) {
      const enforce = this.profile.response.mode === "enforce";
      const banned = actions.some((a) => a.kind === "ban");
      const severe = worst.threat.severity === "high" || worst.threat.severity === "critical";
      if (enforce && (banned || severe)) {
        return { action: "block", status: 403, reason: worst.threat.rule, headers: BASE_HEADERS };
      }
    }
    return { action: "allow", status: 200, headers: BASE_HEADERS };
  }
}

export function securityHeaders(): Record<string, string> {
  return { ...BASE_HEADERS };
}
