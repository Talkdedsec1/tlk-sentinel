import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { isValidIp, type Threat } from "@tlk-sentinel/core";

const run = promisify(execFile);

export interface ActiveDefenseOptions {
  enabled: boolean;
  dryRun: boolean;
  backend: "nft" | "ipset" | "none";
  set: string;
  criticalToPermanent: number;
}

export class ActiveDefense {
  private crits = new Map<string, number>();

  constructor(private opt: ActiveDefenseOptions) {}

  get active(): boolean {
    return this.opt.enabled;
  }

  async consider(threat: Threat): Promise<boolean> {
    if (!this.opt.enabled || !isValidIp(threat.ip)) return false;
    const isCrit =
      threat.severity === "critical" || (threat.reputation?.length ?? 0) > 0;
    if (!isCrit) return false;

    const n = (this.crits.get(threat.ip) ?? 0) + 1;
    this.crits.set(threat.ip, n);
    if (n < this.opt.criticalToPermanent) return false;

    await this.permaBan(threat.ip);
    return true;
  }

  private async permaBan(ip: string): Promise<void> {
    if (this.opt.dryRun || this.opt.backend === "none") {
      process.stdout.write(`[activedef] [dry-run] permanent ban ${ip}\n`);
      return;
    }
    try {
      if (this.opt.backend === "ipset") {
        await run("ipset", ["add", this.opt.set, ip, "-exist"], { timeout: 5000 });
      } else {
        await run(
          "nft",
          ["add", "element", "inet", "filter", this.opt.set, `{ ${ip} }`],
          { timeout: 5000 },
        );
      }
      process.stdout.write(`[activedef] permanent ban ${ip}\n`);
    } catch (e) {
      process.stdout.write(`[activedef] FAIL ${ip}: ${(e as Error).message}\n`);
    }
  }
}
