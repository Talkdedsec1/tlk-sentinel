export interface Observation {
  ip: string;
  at: number;
  path?: string;
  status?: number;
  ua?: string;
  method?: string;
}

export interface AnomalyScore {
  score: number;
  reasons: string[];
  ip?: string;
  at?: number;
}

interface Track {
  times: number[];
  paths: Set<string>;
  uas: Set<string>;
  errors: number;
  total: number;
}

export interface AnomalyOptions {
  windowMs?: number;
  rateTrigger?: number;
  pathTrigger?: number;
  uaTrigger?: number;
  errorRatioTrigger?: number;
  scoreTrigger?: number;
  cooldownMs?: number;
}

export class Anomaly {
  private tracks = new Map<string, Track>();
  private firedAt = new Map<string, number>();
  private windowMs: number;
  private opt: Required<AnomalyOptions>;

  constructor(options: AnomalyOptions = {}) {
    this.windowMs = options.windowMs ?? 60000;
    this.opt = {
      windowMs: this.windowMs,
      rateTrigger: options.rateTrigger ?? 120,
      pathTrigger: options.pathTrigger ?? 40,
      uaTrigger: options.uaTrigger ?? 4,
      errorRatioTrigger: options.errorRatioTrigger ?? 0.6,
      scoreTrigger: options.scoreTrigger ?? 100,
      cooldownMs: options.cooldownMs ?? 300000,
    };
  }

  observe(o: Observation): AnomalyScore {
    const t = this.tracks.get(o.ip) ?? {
      times: [],
      paths: new Set<string>(),
      uas: new Set<string>(),
      errors: 0,
      total: 0,
    };
    const cutoff = o.at - this.windowMs;
    t.times = t.times.filter((x) => x >= cutoff);
    t.times.push(o.at);
    t.total = t.times.length;
    if (o.path) t.paths.add(o.path);
    if (o.ua) t.uas.add(o.ua);
    if (o.status && o.status >= 400) t.errors++;
    this.tracks.set(o.ip, t);

    const rate = t.times.length;
    const pathN = t.paths.size;
    const uaN = t.uas.size;
    const errRatio = t.total > 0 ? t.errors / t.total : 0;

    let score = 0;
    const reasons: string[] = [];
    if (rate >= this.opt.rateTrigger) {
      score += 40 + Math.min(40, rate - this.opt.rateTrigger);
      reasons.push(`rate=${rate}`);
    }
    if (pathN >= this.opt.pathTrigger) {
      score += 40;
      reasons.push(`paths=${pathN}`);
    }
    if (uaN >= this.opt.uaTrigger) {
      score += 30;
      reasons.push(`ua-churn=${uaN}`);
    }
    if (t.total >= 10 && errRatio >= this.opt.errorRatioTrigger) {
      score += 30;
      reasons.push(`err-ratio=${errRatio.toFixed(2)}`);
    }
    return { score, reasons, ip: o.ip, at: o.at };
  }

  triggered(s: AnomalyScore): boolean {
    if (s.score < this.opt.scoreTrigger) return false;
    if (s.ip === undefined) return true;
    const last = this.firedAt.get(s.ip);
    const at = s.at ?? Date.now();
    if (last !== undefined && at - last < this.opt.cooldownMs) return false;
    this.firedAt.set(s.ip, at);
    return true;
  }

  sweep(now: number): void {
    const cutoff = now - this.windowMs * 2;
    for (const [ip, t] of this.tracks) {
      if (t.times.length === 0 || t.times[t.times.length - 1]! < cutoff) {
        this.tracks.delete(ip);
      }
    }
    for (const [ip, at] of this.firedAt) {
      if (now - at > this.opt.cooldownMs) this.firedAt.delete(ip);
    }
  }
}
