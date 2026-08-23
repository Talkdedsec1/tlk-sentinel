import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import type { RawEvent } from "@tlk-sentinel/core";

export class IntegrityWatch {
  private baseline = new Map<string, string>();

  constructor(private targets: string[]) {
    for (const p of targets) {
      const h = this.hash(p);
      if (h) this.baseline.set(p, h);
    }
  }

  get watched(): number {
    return this.baseline.size;
  }

  scan(): RawEvent[] {
    const out: RawEvent[] = [];
    for (const p of this.targets) {
      const now = this.hash(p);
      const prev = this.baseline.get(p);
      if (now && prev && now !== prev) {
        out.push({
          origin: "integrity",
          at: Date.now(),
          line: `INTEGRITY-BREACH ${p} ${prev.slice(0, 12)} -> ${now.slice(0, 12)}`,
        });
        this.baseline.set(p, now);
      } else if (now && !prev) {
        this.baseline.set(p, now);
      }
    }
    return out;
  }

  private hash(p: string): string | null {
    try {
      statSync(p);
      return createHash("sha256").update(readFileSync(p)).digest("hex");
    } catch {
      return null;
    }
  }
}
