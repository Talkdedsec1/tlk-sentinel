import { normalizeRequestLine, type Observation, type Origin, type RawEvent } from "@tlk-sentinel/core";

const IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
const NGINX_HEAD = /^(\d{1,3}(?:\.\d{1,3}){3})\s/;
const NGINX_LINE =
  /^(\d{1,3}(?:\.\d{1,3}){3}).*?"(\w+)\s+(\S+)[^"]*"\s+(\d{3})\s+\d+\s+"[^"]*"\s+"([^"]*)"/;

export function toEvent(origin: Origin, line: string): RawEvent {
  let ip: string | undefined;
  if (origin === "nginx") {
    ip = NGINX_HEAD.exec(line)?.[1] ?? IPV4.exec(line)?.[1];
    return { origin, at: Date.now(), ip, line: normalizeRequestLine(line) };
  }
  ip = IPV4.exec(line)?.[1];
  return { origin, at: Date.now(), ip, line };
}

export function nginxObservation(line: string): Observation | null {
  const m = NGINX_LINE.exec(line);
  if (!m) return null;
  return {
    ip: m[1]!,
    at: Date.now(),
    method: m[2],
    path: m[3],
    status: Number(m[4]),
    ua: m[5],
  };
}
