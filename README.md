# tlk-sentinel

A security engine that unifies the server and application layers on a single event
pipeline. It tails SSH/nginx logs, catches attack patterns, bans IPs, checks the
integrity of critical files, and reports to Discord. The same rule engine also runs
as middleware inside Next/Prisma apps. Zero external dependencies — it runs on Node's
built-in `node:sqlite` and `node:http`, so a single `npm install` is enough.

## Modules

- **Rule engine** — JSON regex with threshold/window; SSH brute-force, nginx scanning,
  SQLi/XSS, request floods.
- **Event DB + live panel** — SQLite history and a real-time dashboard at `/` (SSE):
  threat feed, ban list, one-click unban, 24h stats. Token protected.
- **GeoIP + reputation** — offline CIDR blocklists (Tor exits, known bad networks) and
  an optional country table; a blocklisted IP escalates its threat straight to critical.
- **Behavioral anomaly** — per-IP request rate / path diversity / UA churn / 4xx ratio is
  scored, catching attacks that no fixed signature would match.
- **Active defense (self only)** — permanent nft ban set for repeat critical offenders.
  Fully disabled in the public build, and disabled if the brand signature is broken.

## Two builds, one codebase

Behaviour is driven by JSON under `profiles/` — the code never forks.

| | `public` (community) | `self` (internal) |
|---|---|---|
| Mode | `monitor` | `enforce` |
| Auto-ban | off | on, escalating |
| Private rules (`rules/private`) | not loaded | loaded |
| Honeypot / integrity / active defense | off | on |
| Alerts | stdout | stdout + Discord |

The `self` profile, private rules, and secrets **never enter the repo** (`.gitignore`).
The shippable build is produced with `npm run dist:public`; the script strips every
self-only trace, scans the output for leaks, and verifies the public default is passive —
if any check fails, the build is rejected.

## License

Source-available (see `LICENSE`): **you may use and modify it; you may not sell or
redistribute it.** For commercial use: talkdedsec@proton.me

## Install (server agent)

```bash
git clone <repo> /opt/tlk-sentinel && cd /opt/tlk-sentinel
npm install
npm run build
cp .env.example .env          # TLK_PROFILE, log paths, panel token, webhook
npm run agent
```

systemd:

```bash
cp deploy/tlk-sentinel.service /etc/systemd/system/
systemctl enable --now tlk-sentinel
```

The firewall defaults to **dry-run** (writes no real rule, logs what it would do).
Set `TLK_FW_DRYRUN=0` in `.env` when going live.

### nftables setup (enforce)

```bash
nft add table inet filter
nft add set inet filter tlk_sentinel { type ipv4_addr\; flags timeout\; }
nft add set inet filter tlk_perma { type ipv4_addr\; }
nft add chain inet filter input { type filter hook input priority 0\; }
nft add rule inet filter input ip saddr @tlk_sentinel drop
nft add rule inet filter input ip saddr @tlk_perma drop
```

## Tests

```bash
npm test
```

42 tests on Node's built-in runner, no test framework: engine thresholds and ban
escalation, profile gating, WAF bypass resistance (percent, double-percent and plus
encoding), reputation CIDR matching, anomaly scoring and cooldown, log tailing across
truncation and logrotate, integrity baselines, SQLite store, panel HTML, plus two
integration tests that boot the real agent end to end and assert the public build
rejects anything unsafe.

## Panel

Defaults to `127.0.0.1:8787`. To expose it, `TLK_PANEL_TOKEN` is required; access via
`http://host:8787/?token=...`. Put it behind nginx with an IP allowlist in production.
Disable with `TLK_PANEL=0`.

## Reputation lists

`data/reputation/*.txt` — one IP or CIDR per line (the file name becomes the tag).
Trailing text and `#` comments are ignored. For a country table, point
`TLK_COUNTRY_FILE` at a file of `CIDR,CC` lines.

## Application layer (Next/Prisma)

```ts
import { WebGuard } from "@tlk-sentinel/web";

const guard = new WebGuard({
  profilePath: "profiles/public.json",
  rulesPublicDir: "rules/public",
  lang: "en",
  trustedProxy: true,
});

const v = await guard.inspect(request, { trustProxy: true });
if (v.action === "block") return new Response("blocked", { status: v.status });
```

## Language

TR + EN, switched with `TLK_LANG=tr|en`. Rule summaries carry `{tr,en}`; UI strings live
in the `i18n` catalog.

## Layout

```
packages/core   event schema + profile gate + engine + reputation + anomaly + brand
packages/agent  server agent: log tail, ban, integrity, event DB, panel, active defense
packages/web    application middleware (same engine)
rules/public    public rules (ssh brute, nginx scan, sqli/xss)
rules/private   self-only: honeypot, license recon, integrity   [git-ignored]
profiles/       behaviour profiles
data/           event DB + reputation lists   [git-ignored]
scripts/        public build (leak-checked) + brand signing
```

---

<details>
<summary><b>Türkçe</b></summary>

### tlk-sentinel

Sunucu ve uygulama katmanını tek olay hattında birleştiren güvenlik motoru. SSH/nginx
loglarını izler, saldırı kalıplarını yakalar, IP banlar, kritik dosya bütünlüğünü
kontrol eder, Discord'a bildirir. Aynı kural motoru Next/Prisma uygulamalarında
middleware olarak da çalışır. Sıfır dış bağımlılık — Node'un yerleşik `node:sqlite` ve
`node:http`'si ile çalışır, tek `npm install` yeter.

### Modüller

- **Kural motoru** — JSON regex + eşik/pencere; ssh brute, nginx tarama, sqli/xss, flood.
- **Olay DB + canlı panel** — SQLite geçmiş, `/` altında gerçek zamanlı dashboard (SSE):
  tehdit akışı, ban listesi, tek tıkla ban kaldırma, 24s istatistik. Token korumalı.
- **GeoIP + itibar** — offline CIDR blocklist'ler (tor exit, bilinen kötü ağlar) ve
  isteğe bağlı ülke tablosu; kara listedeki IP tehdidi doğrudan kritik yapar.
- **Davranışsal anomali** — IP başına istek ritmi / yol çeşitliliği / UA değişimi / 404
  oranı skorlanır; sabit imzaya uymayan saldırıları da yakalar.
- **Aktif savunma (yalnız self)** — tekrarlayan kritik saldırgana kalıcı nft ban seti.
  Public sürümde tamamen kapalı, marka imzası düşerse de kapanır.

### İki sürüm, tek kod

Davranış `profiles/` içindeki JSON ile belirlenir; kod çatallanmaz. `public` =
izle-uyar, otomatik ban kapalı, özel kural yok. `self` = zorla-banla, kademeli ban,
özel kurallar + honeypot + bütünlük + aktif savunma, Discord bildirimi. `self` profili,
özel kurallar ve sırlar repoya girmez. Yayın sürümü `npm run dist:public` ile üretilir;
script self izlerini çıkarır, sızıntı tarar, public varsayılanın pasif olduğunu doğrular
— biri düşerse build reddedilir.

### Lisans

Kaynak-erişilebilir (`LICENSE`): kullanabilir ve değiştirebilirsin; satamaz, yeniden
dağıtamazsın. Ticari kullanım için: talkdedsec@proton.me

### Kurulum

`npm install && npm run build`, `.env` doldur (`TLK_PROFILE`, log yolları, panel token),
`npm run agent`. Güvenlik duvarı varsayılan dry-run; canlıda `TLK_FW_DRYRUN=0` + nft
tabloları (yukarıdaki komutlar). Panel varsayılan `127.0.0.1:8787`, dışarı açarsan
`TLK_PANEL_TOKEN` zorunlu (tokensiz loopback dışına açılmayı ajan reddeder). Dil
`TLK_LANG=tr|en`. Test: `npm test` (42 test, dış çatı yok).

</details>
