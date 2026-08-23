import { readFileSync } from "node:fs";
import type { ResponseMode, Visibility } from "./events.js";

export interface Profile {
  profile: "self" | "public";
  label: string;
  visibility: Visibility;
  response: {
    mode: ResponseMode;
    autoBan: boolean;
    banSeconds: number;
    maxBanSeconds: number;
    escalate?: boolean;
  };
  detectors: {
    loadPrivateRules: boolean;
    counterScan: boolean;
    activeDeception: boolean;
  };
  alerts: { channels: string[] };
}

export function loadProfile(path: string): Profile {
  const p = JSON.parse(readFileSync(path, "utf8")) as Profile;
  if (p.profile !== "self" && p.profile !== "public") {
    throw new Error(`invalid profile: ${String(p.profile)}`);
  }
  return p;
}

export function allows(profile: Profile, need: Visibility): boolean {
  if (need === "public") return true;
  return profile.visibility === "self";
}
