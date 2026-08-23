import type { Lang, LocalizedText } from "./events.js";

export function resolveText(text: string | LocalizedText, lang: Lang): string {
  if (typeof text === "string") return text;
  return text[lang] ?? text.tr ?? text.en;
}

type Key =
  | "signatureOk"
  | "signatureTampered"
  | "alertBan"
  | "alertWarn"
  | "blocked"
  | "startProfile"
  | "sourceBound"
  | "noSource"
  | "integrityWatch"
  | "banAction"
  | "unbanAction"
  | "dryPrefix";

const CATALOG: Record<Key, LocalizedText> = {
  signatureOk: { tr: "imza doğrulandı", en: "signature ok" },
  signatureTampered: { tr: "İMZA DEĞİŞTİRİLMİŞ", en: "SIGNATURE TAMPERED" },
  alertBan: { tr: "BAN", en: "BAN" },
  alertWarn: { tr: "UYARI", en: "WARN" },
  blocked: { tr: "engellendi", en: "blocked" },
  startProfile: { tr: "profil", en: "profile" },
  sourceBound: { tr: "kaynak bağlandı", en: "source bound" },
  noSource: { tr: "hiçbir log kaynağı ayarlı değil", en: "no log source configured" },
  integrityWatch: { tr: "bütünlük izleme", en: "integrity watch" },
  banAction: { tr: "ban", en: "ban" },
  unbanAction: { tr: "ban kalktı", en: "unban" },
  dryPrefix: { tr: "[deneme]", en: "[dry-run]" },
};

export function t(key: Key, lang: Lang): string {
  return CATALOG[key][lang];
}
