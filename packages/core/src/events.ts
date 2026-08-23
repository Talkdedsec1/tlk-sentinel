export type Lang = "tr" | "en";

export interface LocalizedText {
  tr: string;
  en: string;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type Origin =
  | "sshd"
  | "nginx"
  | "web-middleware"
  | "integrity"
  | "firewall"
  | "manual";

export interface RawEvent {
  origin: Origin;
  at: number;
  ip?: string;
  line: string;
  fields?: Record<string, string | number>;
}

export interface Threat {
  id: string;
  rule: string;
  origin: Origin;
  severity: Severity;
  ip?: string;
  at: number;
  summary: string;
  evidence: string[];
  hits: number;
  window?: number;
  visibility: Visibility;
  country?: string;
  reputation?: string[];
  score?: number;
}

export type Visibility = "public" | "self";

export type ResponseMode = "monitor" | "enforce";

export interface ResponderAction {
  kind: "ban" | "alert" | "log" | "throttle" | "deceive";
  ip?: string;
  seconds?: number;
  threat: Threat;
}
