const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6 = /^[0-9a-fA-F:]{2,45}$/;

export function isValidIp(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 45) return false;
  if (IPV4.test(value)) return true;
  if (!value.includes(":")) return false;
  if (!IPV6.test(value)) return false;
  return value.split(":").length <= 9 && !value.includes(":::");
}

export function ipFamily(ip: string): 4 | 6 | null {
  if (IPV4.test(ip)) return 4;
  return isValidIp(ip) ? 6 : null;
}
