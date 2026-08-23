import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Threat } from "@tlk-sentinel/core";

export interface BanRow {
  ip: string;
  until: number;
  rule: string;
  createdAt: number;
}

export class Store {
  private db: DatabaseSync;

  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS threats (
        id TEXT PRIMARY KEY, at INTEGER, rule TEXT, origin TEXT,
        severity TEXT, ip TEXT, summary TEXT, hits INTEGER,
        country TEXT, reputation TEXT, score INTEGER, banned INTEGER
      );
      CREATE INDEX IF NOT EXISTS ix_threats_at ON threats(at);
      CREATE INDEX IF NOT EXISTS ix_threats_ip ON threats(ip);
      CREATE TABLE IF NOT EXISTS bans (
        ip TEXT PRIMARY KEY, until INTEGER, rule TEXT, createdAt INTEGER, permanent INTEGER DEFAULT 0
      );
    `);
  }

  recordThreat(t: Threat, banned: boolean): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO threats
         (id, at, rule, origin, severity, ip, summary, hits, country, reputation, score, banned)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      )
      .run(
        t.id, t.at, t.rule, t.origin, t.severity, t.ip ?? null, t.summary, t.hits,
        t.country ?? null, t.reputation ? t.reputation.join(",") : null, t.score ?? null,
        banned ? 1 : 0,
      );
  }

  recordBan(ip: string, until: number, rule: string, permanent = false): void {
    this.db
      .prepare(
        `INSERT OR REPLACE INTO bans (ip, until, rule, createdAt, permanent) VALUES (?,?,?,?,?)`,
      )
      .run(ip, until, rule, Date.now(), permanent ? 1 : 0);
  }

  removeBan(ip: string): void {
    this.db.prepare(`DELETE FROM bans WHERE ip = ?`).run(ip);
  }

  activeBans(now = Date.now()): BanRow[] {
    return this.db
      .prepare(`SELECT ip, until, rule, createdAt FROM bans WHERE permanent = 1 OR until > ? ORDER BY createdAt DESC`)
      .all(now) as unknown as BanRow[];
  }

  recentThreats(limit = 100): Record<string, unknown>[] {
    return this.db
      .prepare(`SELECT * FROM threats ORDER BY at DESC LIMIT ?`)
      .all(limit) as unknown as Record<string, unknown>[];
  }

  stats(sinceMs: number): Record<string, unknown> {
    const since = Date.now() - sinceMs;
    const total = this.db.prepare(`SELECT COUNT(*) c FROM threats WHERE at > ?`).get(since) as { c: number };
    const banned = this.db.prepare(`SELECT COUNT(*) c FROM threats WHERE at > ? AND banned = 1`).get(since) as { c: number };
    const bySeverity = this.db
      .prepare(`SELECT severity, COUNT(*) c FROM threats WHERE at > ? GROUP BY severity`)
      .all(since);
    const topIps = this.db
      .prepare(`SELECT ip, COUNT(*) c FROM threats WHERE at > ? AND ip IS NOT NULL GROUP BY ip ORDER BY c DESC LIMIT 10`)
      .all(since);
    return { total: total.c, banned: banned.c, bySeverity, topIps, activeBans: this.activeBans().length };
  }

  close(): void {
    this.db.close();
  }
}
