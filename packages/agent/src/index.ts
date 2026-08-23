import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  Anomaly,
  Engine,
  Reputation,
  brandBanner,
  loadProfile,
  loadRuleDir,
  t,
  type CompiledRule,
  type Enrichment,
  type ResponderAction,
} from "@tlk-sentinel/core";
import { loadConfig } from "./config.js";
import { Tailer } from "./sources/tail.js";
import { toEvent, nginxObservation } from "./sources/parse.js";
import { Firewall } from "./responders/firewall.js";
import { StdoutAlerter, DiscordAlerter, type Alerter } from "./responders/alert.js";
import { ActiveDefense } from "./responders/activedef.js";
import { IntegrityWatch } from "./detectors/integrity.js";
import { Store } from "./store.js";
import { Panel } from "./panel.js";

const root = resolve(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "..");
const cfg = loadConfig(root);
const profile = loadProfile(cfg.profilePath);
const lang = cfg.lang;

const reputation = new Reputation();
const repCount = reputation.addBlocklistDir(cfg.reputationDir);
if (cfg.countryFile) reputation.addCountryFile(cfg.countryFile);
const enrich = (ip: string): Enrichment => {
  const info = reputation.lookup(ip);
  return { country: info.country, reputation: info.tags };
};

const rules: CompiledRule[] = loadRuleDir(cfg.rulesPublicDir);
if (profile.detectors.loadPrivateRules) {
  rules.push(...loadRuleDir(cfg.rulesPrivateDir));
}

const allow = new Set(cfg.allowlist);
const engine = new Engine({
  profile,
  rules,
  lang,
  allowlist: (ip) => allow.has(ip),
  enrich,
});

const store = new Store(cfg.dbPath);
const firewall = new Firewall(cfg.firewall, lang);
const anomaly = cfg.anomaly ? new Anomaly() : null;
const activedef = new ActiveDefense({
  enabled: profile.detectors.activeDeception && engine.branded === "verified",
  dryRun: cfg.firewall.dryRun,
  backend: cfg.firewall.backend,
  set: cfg.activedef.set,
  criticalToPermanent: cfg.activedef.criticalToPermanent,
});

const alerters: Alerter[] = [new StdoutAlerter(lang)];
if (profile.alerts.channels.includes("discord") && cfg.discordWebhook) {
  alerters.push(new DiscordAlerter(cfg.discordWebhook, lang));
}

const panel = cfg.panel.enabled
  ? new Panel({
      store,
      host: cfg.panel.host,
      port: cfg.panel.port,
      token: cfg.panel.token,
      lang,
      onUnban: (ip) => {
        engine.unban(ip);
        void firewall.unban(ip);
      },
      onBan: (ip, seconds) => {
        void firewall.ban(ip, seconds);
        store.recordBan(ip, Date.now() + seconds * 1000, "manual");
      },
    })
  : null;

async function apply(actions: ResponderAction[]): Promise<void> {
  const banned = new Set(actions.filter((a) => a.kind === "ban").map((a) => a.threat.id));
  for (const a of actions) {
    if (a.kind === "ban" && a.ip) {
      await firewall.ban(a.ip, a.seconds ?? profile.response.banSeconds);
      store.recordBan(a.ip, a.threat.at + (a.seconds ?? 0) * 1000, a.threat.rule);
    }
  }
  for (const a of actions) {
    if (a.kind !== "alert") continue;
    const wasBanned = banned.has(a.threat.id);
    store.recordThreat(a.threat, wasBanned);
    panel?.push(a.threat, wasBanned);
    for (const al of alerters) await al.send(a.threat, wasBanned);
    if (await activedef.consider(a.threat)) {
      store.recordBan(a.threat.ip!, 0, `${a.threat.rule}:permanent`, true);
    }
  }
}

function wireTail(path: string, origin: "sshd" | "nginx"): void {
  const tail = new Tailer(path);
  tail.on("line", (line: string) => {
    void apply(engine.ingest(toEvent(origin, line)));
    if (origin === "nginx" && anomaly) feedAnomaly(line);
  });
  tail.on("error", (e: Error) => process.stderr.write(`[${origin}] ${e.message}\n`));
  tail.start(true);
  log(`${t("sourceBound", lang)}: ${origin} <- ${path}`);
}

function feedAnomaly(line: string): void {
  if (!anomaly) return;
  const obs = nginxObservation(line);
  if (!obs || allow.has(obs.ip)) return;
  const s = anomaly.observe(obs);
  if (!anomaly.triggered(s)) return;
  void apply(
    engine.raise({
      rule: "behavioral-anomaly",
      origin: "nginx",
      severity: "high",
      ip: obs.ip,
      at: obs.at,
      summary: lang === "en" ? "Behavioral anomaly" : "Davranışsal anomali",
      evidence: [s.reasons.join(" ")],
      hits: s.score,
      score: s.score,
    }),
  );
}

const integrity =
  profile.detectors.loadPrivateRules && cfg.integrityTargets.length > 0
    ? new IntegrityWatch(cfg.integrityTargets)
    : null;

async function main(): Promise<void> {
  log(brandBanner());
  log(`${t("startProfile", lang)}=${profile.profile} mode=${profile.response.mode} rules=${engine.activeRuleCount} rep=${repCount} anomaly=${anomaly ? "on" : "off"} activedef=${activedef.active ? "on" : "off"}`);
  await firewall.ensureChain();
  if (panel) {
    const loopback = cfg.panel.host === "127.0.0.1" || cfg.panel.host === "::1" || cfg.panel.host === "localhost";
    if (!loopback && !cfg.panel.token) {
      log(`panel DISABLED: non-loopback host ${cfg.panel.host} requires TLK_PANEL_TOKEN`);
    } else {
      panel.start();
      log(`panel: http://${cfg.panel.host}:${cfg.panel.port}${cfg.panel.token ? "?token=***" : ""}`);
    }
  }

  if (cfg.sources.sshdLog) wireTail(cfg.sources.sshdLog, "sshd");
  if (cfg.sources.nginxAccessLog) wireTail(cfg.sources.nginxAccessLog, "nginx");
  if (!cfg.sources.sshdLog && !cfg.sources.nginxAccessLog) log(t("noSource", lang));
  if (integrity) log(`${t("integrityWatch", lang)}: ${integrity.watched}`);

  setInterval(() => {
    engine.sweep();
    anomaly?.sweep(Date.now());
    if (integrity) {
      for (const ev of integrity.scan()) void apply(engine.ingest(ev));
    }
  }, cfg.sweepMs).unref();
}

function log(msg: string): void {
  process.stdout.write(`[sentinel] ${msg}\n`);
}

process.on("SIGINT", () => {
  store.close();
  process.exit(0);
});
process.on("SIGTERM", () => {
  store.close();
  process.exit(0);
});

void main();
