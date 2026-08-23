import { brandTag, t, type Lang, type Threat } from "@tlk-sentinel/core";

const color: Record<Threat["severity"], number> = {
  info: 0x8899a6,
  low: 0x3498db,
  medium: 0xf1c40f,
  high: 0xe67e22,
  critical: 0xe74c3c,
};

export interface Alerter {
  send(threat: Threat, banned: boolean): Promise<void> | void;
}

export class StdoutAlerter implements Alerter {
  constructor(private lang: Lang = "tr") {}

  send(threat: Threat, banned: boolean): void {
    const tag = banned ? t("alertBan", this.lang) : t("alertWarn", this.lang);
    process.stdout.write(
      `[${tag}] ${threat.severity.toUpperCase()} ${threat.rule} ip=${threat.ip ?? "-"} hits=${threat.hits} :: ${threat.summary}\n`,
    );
  }
}

export class DiscordAlerter implements Alerter {
  constructor(
    private webhook: string,
    private lang: Lang = "tr",
  ) {}

  async send(threat: Threat, banned: boolean): Promise<void> {
    const head = banned ? t("alertBan", this.lang) : t("alertWarn", this.lang);
    const embed = {
      title: `[${head}] ${threat.summary}`,
      color: color[threat.severity],
      fields: [
        { name: "rule", value: threat.rule, inline: true },
        { name: "severity", value: threat.severity, inline: true },
        { name: "ip", value: threat.ip ?? "unknown", inline: true },
        { name: "hits", value: `${threat.hits}/${threat.window ?? "?"}s`, inline: true },
        { name: "origin", value: threat.origin, inline: true },
      ],
      description: "```\n" + threat.evidence[0]?.slice(0, 400) + "\n```",
      timestamp: new Date(threat.at).toISOString(),
      footer: { text: brandTag() },
    };
    try {
      await fetch(this.webhook, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: "tlk-sentinel", embeds: [embed] }),
      });
    } catch (e) {
      process.stderr.write(`[discord] ${(e as Error).message}\n`);
    }
  }
}
