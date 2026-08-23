import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { isValidIp, t, type Lang } from "@tlk-sentinel/core";
import type { AgentConfig } from "../config.js";

const run = promisify(execFile);

export class Firewall {
  private timers = new Map<string, NodeJS.Timeout>();

  constructor(
    private cfg: AgentConfig["firewall"],
    private lang: Lang = "tr",
  ) {}

  async ensureChain(): Promise<void> {
    if (this.cfg.backend === "none" || this.cfg.dryRun) return;
    if (this.cfg.backend === "ipset") {
      await this.exec("ipset", ["create", this.cfg.chain, "hash:ip", "timeout", "0", "-exist"]);
    }
  }

  async ban(ip: string, seconds: number): Promise<void> {
    if (!isValidIp(ip)) {
      log(`rejected malformed ip: ${JSON.stringify(ip).slice(0, 64)}`);
      return;
    }
    if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 31536000) {
      log(`rejected ban duration for ${ip}: ${seconds}`);
      return;
    }
    if (this.cfg.dryRun || this.cfg.backend === "none") {
      log(`${t("dryPrefix", this.lang)} ${t("banAction", this.lang)} ${ip} ${seconds}s (${this.cfg.backend})`);
      this.scheduleUnban(ip, seconds, true);
      return;
    }
    try {
      if (this.cfg.backend === "ipset") {
        await this.exec("ipset", ["add", this.cfg.chain, ip, "timeout", String(seconds), "-exist"]);
      } else {
        await this.exec("nft", [
          "add", "element", "inet", "filter", this.cfg.chain,
          `{ ${ip} timeout ${seconds}s }`,
        ]);
      }
      log(`${t("banAction", this.lang)} ${ip} ${seconds}s`);
    } catch (e) {
      log(`${t("banAction", this.lang)} FAIL ${ip}: ${(e as Error).message}`);
    }
  }

  async unban(ip: string): Promise<void> {
    if (!isValidIp(ip)) {
      log(`rejected malformed ip: ${JSON.stringify(ip).slice(0, 64)}`);
      return;
    }
    const old = this.timers.get(ip);
    if (old) {
      clearTimeout(old);
      this.timers.delete(ip);
    }
    if (this.cfg.dryRun || this.cfg.backend === "none") {
      log(`${t("dryPrefix", this.lang)} ${t("unbanAction", this.lang)} ${ip}`);
      return;
    }
    try {
      if (this.cfg.backend === "ipset") {
        await this.exec("ipset", ["del", this.cfg.chain, ip, "-exist"]);
      } else {
        await this.exec("nft", ["delete", "element", "inet", "filter", this.cfg.chain, `{ ${ip} }`]);
      }
      log(`${t("unbanAction", this.lang)} ${ip}`);
    } catch (e) {
      log(`${t("unbanAction", this.lang)} FAIL ${ip}: ${(e as Error).message}`);
    }
  }

  private scheduleUnban(ip: string, seconds: number, dry: boolean): void {
    const old = this.timers.get(ip);
    if (old) clearTimeout(old);
    const timer = setTimeout(() => {
      this.timers.delete(ip);
      if (dry) log(`${t("dryPrefix", this.lang)} ${t("unbanAction", this.lang)} ${ip}`);
    }, seconds * 1000);
    timer.unref?.();
    this.timers.set(ip, timer);
  }

  private async exec(cmd: string, args: string[]): Promise<void> {
    await run(cmd, args, { timeout: 5000 });
  }
}

function log(msg: string): void {
  process.stdout.write(`[firewall] ${msg}\n`);
}
