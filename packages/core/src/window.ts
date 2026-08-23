export class SlidingWindow {
  private hits = new Map<string, number[]>();

  constructor(private windowMs: number) {}

  add(key: string, at: number): number {
    const arr = this.hits.get(key) ?? [];
    const cutoff = at - this.windowMs;
    const kept = arr.filter((t) => t >= cutoff);
    kept.push(at);
    this.hits.set(key, kept);
    return kept.length;
  }

  count(key: string, now: number): number {
    const arr = this.hits.get(key);
    if (!arr) return 0;
    return arr.filter((t) => t >= now - this.windowMs).length;
  }

  reset(key: string): void {
    this.hits.delete(key);
  }

  sweep(now: number): void {
    const cutoff = now - this.windowMs;
    for (const [key, arr] of this.hits) {
      const kept = arr.filter((t) => t >= cutoff);
      if (kept.length === 0) this.hits.delete(key);
      else this.hits.set(key, kept);
    }
  }
}
