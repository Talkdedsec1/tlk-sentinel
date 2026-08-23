import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

export interface IpInfo {
  blocked: boolean;
  tags: string[];
  country?: string;
}

interface Range {
  start: number;
  end: number;
  tag: string;
  country?: string;
}

function ip4ToInt(ip: string): number | null {
  const p = ip.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const part of p) {
    const b = Number(part);
    if (!Number.isInteger(b) || b < 0 || b > 255) return null;
    n = (n << 8) | b;
  }
  return n >>> 0;
}

function parseCidr(cidr: string): [number, number] | null {
  const [addr, bitsRaw] = cidr.split("/");
  const base = ip4ToInt(addr ?? "");
  if (base === null) return null;
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const start = (base & mask) >>> 0;
  const end = (start | (~mask >>> 0)) >>> 0;
  return [start, end];
}

export class Reputation {
  private ranges: Range[] = [];
  private sorted = false;

  addBlocklistDir(dir: string): number {
    let files: string[];
    try {
      files = readdirSync(dir).filter((f) => f.endsWith(".txt") || f.endsWith(".list"));
    } catch {
      return 0;
    }
    let added = 0;
    for (const f of files) {
      const tag = f.replace(/\.(txt|list)$/, "");
      const text = readFileSync(join(dir, f), "utf8");
      for (const raw of text.split("\n")) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        const token = line.split(/\s+/)[0]!;
        const r = parseCidr(token.includes("/") ? token : `${token}/32`);
        if (r) {
          this.ranges.push({ start: r[0], end: r[1], tag });
          added++;
        }
      }
    }
    this.sorted = false;
    return added;
  }

  addCountryFile(path: string): number {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch {
      return 0;
    }
    let added = 0;
    for (const raw of text.split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const parts = line.split(",");
      const cc = parts[parts.length - 1]?.trim();
      const netPart = parts[0]?.trim() ?? "";
      const r = netPart.includes("/") ? parseCidr(netPart) : null;
      if (r && cc) {
        this.ranges.push({ start: r[0], end: r[1], tag: "geo", country: cc });
        added++;
      }
    }
    this.sorted = false;
    return added;
  }

  lookup(ip: string): IpInfo {
    if (!this.sorted) {
      this.ranges.sort((a, b) => a.start - b.start);
      this.sorted = true;
    }
    const n = ip4ToInt(ip);
    const info: IpInfo = { blocked: false, tags: [] };
    if (n === null) return info;
    for (const r of this.ranges) {
      if (r.start > n) break;
      if (n <= r.end) {
        if (r.country) info.country = r.country;
        else {
          info.tags.push(r.tag);
          info.blocked = true;
        }
      }
    }
    return info;
  }

  get size(): number {
    return this.ranges.length;
  }
}
