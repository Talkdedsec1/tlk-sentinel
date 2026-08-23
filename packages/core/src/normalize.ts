export function decodeLayers(input: string, passes = 2): string {
  let out = input;
  for (let i = 0; i < passes; i++) {
    let next: string;
    try {
      next = decodeURIComponent(out.replace(/\+/g, " "));
    } catch {
      next = out.replace(/%25/gi, "%").replace(/\+/g, " ");
    }
    if (next === out) break;
    out = next;
  }
  return out;
}

export function normalizeRequestLine(raw: string): string {
  const decoded = decodeLayers(raw);
  if (decoded === raw) return raw;
  return `${raw} ${decoded}`;
}
