import { resolve } from "node:path";
import type { Lang } from "@tlk-sentinel/core";

export interface AgentConfig {
  lang: Lang;
  profilePath: string;
  rulesPublicDir: string;
  rulesPrivateDir: string;
  sources: {
    sshdLog: string | null;
    nginxAccessLog: string | null;
  };
  firewall: {
    backend: "nft" | "ipset" | "none";
    dryRun: boolean;
    chain: string;
  };
  discordWebhook: string | null;
  allowlist: string[];
  integrityTargets: string[];
  sweepMs: number;
  dbPath: string;
  reputationDir: string;
  countryFile: string | null;
  anomaly: boolean;
  panel: { enabled: boolean; host: string; port: number; token: string | null };
  activedef: { set: string; criticalToPermanent: number };
}

function env(name: string, fallback: string): string {
  const v = process.env[name];
  return v === undefined || v === "" ? fallback : v;
}

function envOrNull(name: string): string | null {
  const v = process.env[name];
  return v === undefined || v === "" ? null : v;
}

export function loadConfig(root: string): AgentConfig {
  const profile = env("TLK_PROFILE", "public");
  const lang: Lang = env("TLK_LANG", "tr") === "en" ? "en" : "tr";
  const explicitProfile = envOrNull("TLK_PROFILE_PATH");
  return {
    lang,
    profilePath: explicitProfile
      ? resolve(explicitProfile)
      : resolve(root, "profiles", `${profile}.json`),
    rulesPublicDir: resolve(root, "rules", "public"),
    rulesPrivateDir: resolve(root, "rules", "private"),
    sources: {
      sshdLog: envOrNull("TLK_SSHD_LOG") ?? defaultAuthLog(),
      nginxAccessLog: envOrNull("TLK_NGINX_LOG"),
    },
    firewall: {
      backend: env("TLK_FW_BACKEND", "nft") as AgentConfig["firewall"]["backend"],
      dryRun: env("TLK_FW_DRYRUN", "1") !== "0",
      chain: env("TLK_FW_CHAIN", "tlk_sentinel"),
    },
    discordWebhook: envOrNull("TLK_DISCORD_WEBHOOK"),
    allowlist: env("TLK_ALLOWLIST", "127.0.0.1,::1")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    integrityTargets: env("TLK_INTEGRITY", "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    sweepMs: Number(env("TLK_SWEEP_MS", "30000")),
    dbPath: envOrNull("TLK_DB") ?? resolve(root, "data", "sentinel.db"),
    reputationDir: envOrNull("TLK_REPUTATION_DIR") ?? resolve(root, "data", "reputation"),
    countryFile: envOrNull("TLK_COUNTRY_FILE"),
    anomaly: env("TLK_ANOMALY", "1") !== "0",
    panel: {
      enabled: env("TLK_PANEL", "1") !== "0",
      host: env("TLK_PANEL_HOST", "127.0.0.1"),
      port: Number(env("TLK_PANEL_PORT", "8787")),
      token: envOrNull("TLK_PANEL_TOKEN"),
    },
    activedef: {
      set: env("TLK_ACTIVEDEF_SET", "tlk_perma"),
      criticalToPermanent: Number(env("TLK_ACTIVEDEF_CRITS", "2")),
    },
  };
}

function defaultAuthLog(): string | null {
  return process.platform === "linux" ? "/var/log/auth.log" : null;
}
