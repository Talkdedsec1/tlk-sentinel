import { verify, createPublicKey } from "node:crypto";

export const BRAND = "tlk-sentinel — made by talkdedsec (talkdedsec@proton.me)";

const BRAND_SIG =
  "jqyQBLnQTQ+QHRuDiYXpDKIXSCHI4w9s8DDqQAa8O+gyjjlzYRu+f0kcdy3gXYp57TdJqUaimdW5roGdArdCAA==";

const BRAND_PUBKEY =
  "-----BEGIN PUBLIC KEY-----\n" +
  "MCowBQYDK2VwAyEAfIbQOlGFnUD4/flJXJLMdw8rnB/dXmxdUnkq3LZMYcE=\n" +
  "-----END PUBLIC KEY-----\n";

export type BrandState = "verified" | "tampered";

let cached: BrandState | null = null;

export function verifyBrand(): BrandState {
  if (cached) return cached;
  try {
    const ok = verify(
      null,
      Buffer.from(BRAND, "utf8"),
      createPublicKey(BRAND_PUBKEY),
      Buffer.from(BRAND_SIG, "base64"),
    );
    cached = ok ? "verified" : "tampered";
  } catch {
    cached = "tampered";
  }
  return cached;
}

export function brandBanner(): string {
  const st = verifyBrand();
  const seal = st === "verified" ? "signature ok" : "SIGNATURE TAMPERED";
  return `== ${BRAND} == [${seal}]`;
}

export function brandTag(): string {
  return verifyBrand() === "verified"
    ? "tlk-sentinel · made by talkdedsec"
    : "tlk-sentinel · UNLICENSED-COPY";
}
