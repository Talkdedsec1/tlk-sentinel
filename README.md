<p align="center">
  <img src="assets/banner.svg" alt="tlk-sentinel" width="100%">
</p>

<p align="center">
  <a href="https://github.com/Talkdedsec/tlk-sentinel/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/Talkdedsec/tlk-sentinel/ci.yml?branch=main&style=flat-square&labelColor=0d1220&color=3ddc97"></a>
  <img alt="tests" src="https://img.shields.io/badge/tests-60%20passing-3ddc97?style=flat-square&labelColor=0d1220">
  <img alt="dependencies" src="https://img.shields.io/badge/runtime%20deps-0-5b8cff?style=flat-square&labelColor=0d1220">
  <img alt="node" src="https://img.shields.io/badge/node-%E2%89%A522.5-5b8cff?style=flat-square&labelColor=0d1220">
  <img alt="license" src="https://img.shields.io/badge/license-source--available-ffd43b?style=flat-square&labelColor=0d1220">
</p>

<p align="center">
  <b>Detects attacks in your logs, bans the source, and shows you what happened — in one process.</b><br>
  <sub>SSH · nginx · Next.js middleware · offline reputation · behavioural scoring · live dashboard</sub>
</p>

<p align="center">
  <sub><b>This is the community build.</b> It runs the <code>public</code> profile: it watches, scores
  and reports, and it never bans. The firewall responder also starts in dry-run, so a fresh clone
  touches nothing on your host until you turn both on deliberately.</sub>
</p>

---

## Why

Most small fleets run `fail2ban` for SSH, nothing for the application, and find out
about an incident from a customer. tlk-sentinel closes that gap with one agent: the
same rule engine reads your server logs **and** runs inside your app, so a scanner
probing `/.env` and the same IP hammering your login endpoint are one story, not two.

It ships two behaviours from one codebase. The community build watches and reports.
The internal build enforces. Nothing about that is a code fork — it is a JSON profile.

```
              ┌──────────────┐
  auth.log ──▶│              │──▶ nft / ipset       ban, escalating on repeat
              │              │
access.log ──▶│    engine    │──▶ SQLite            queryable event history
              │              │
Next.js    ──▶│  rules +     │──▶ live panel        SSE dashboard, one-click unban
middleware    │  reputation  │
              │  + anomaly   │──▶ Discord           embed per threat
  files    ──▶│              │
 (sha256)     └──────────────┘
```

## What it catches

| | Detection | How |
|---|---|---|
| **SSH** | brute-force, invalid users, direct root login | threshold windows per IP |
| **HTTP** | SQLi, XSS, path traversal, `.env` / `wp-admin` / `phpmyadmin` probing, request floods | regex rules on normalized requests |
| **Tooling** | sqlmap, nikto, nuclei, gobuster, masscan and friends | User-Agent signatures |
| **Unknown attacks** | scans that match no signature | behavioural score: request rate, path diversity, UA churn, 4xx ratio |
| **Known-bad sources** | Tor exits, abusive networks | offline CIDR reputation, escalates the threat to critical |
| **Tampering** | changes to `.env`, configs, binaries | sha256 baseline, re-checked on a timer; set `TLK_INTEGRITY` |

Encoded payloads do not slip through: requests are decoded (percent, double-percent
and `+`) before matching, so `?id=1%2520union%2520select%25201` is caught exactly like
its plain form. There are regression tests for each of those encodings.

## Install

Requires Node 22.5+ (for the built-in SQLite). No other runtime dependency.

```bash
git clone https://github.com/Talkdedsec/tlk-sentinel /opt/tlk-sentinel
cd /opt/tlk-sentinel
npm install
npm run build
cp .env.example .env
npm run agent
```

```bash
sudo cp deploy/tlk-sentinel.service /etc/systemd/system/
sudo systemctl enable --now tlk-sentinel
```

The firewall starts in **dry-run**: it logs the ban it would apply and touches nothing.
Watch it for a day, confirm the decisions look right, then set `TLK_FW_DRYRUN=0`.

<details>
<summary>nftables sets for enforcing mode</summary>

```bash
nft add table inet filter
nft add set inet filter tlk_sentinel { type ipv4_addr\; flags timeout\; }
nft add set inet filter tlk_perma  { type ipv4_addr\; }
nft add chain inet filter input { type filter hook input priority 0\; }
nft add rule inet filter input ip saddr @tlk_sentinel drop
nft add rule inet filter input ip saddr @tlk_perma  drop
```
</details>

## Two builds, one codebase

|  | `public` — community | `self` — internal |
|---|---|---|
| Mode | `monitor`, reports only | `enforce`, bans |
| Auto-ban | off | on, ×4 on repeat offenders |
| Private rules | not loaded | loaded |
| Honeypot paths, active defense | off | on |
| Integrity watching | available, opt-in | available, opt-in |
| Alerts | stdout | stdout + Discord |

`npm run dist:public` produces the shippable tree. It strips the internal profile,
private rules and signing key, scans the output for secrets, and asserts the public
default is still passive. **If any check fails the build is rejected**, so an
enforcing default can never reach a release by accident.

## Live panel

<p align="center">
  <img src="assets/panel.png" alt="tlk-sentinel dashboard: live threat feed, severity split and ban list" width="100%">
</p>

Bound to `127.0.0.1:8787` by default. Exposing it on another interface **requires**
`TLK_PANEL_TOKEN` — without one the agent refuses to bind and says so on startup.
Behind nginx, add an IP allowlist too. `TLK_PANEL=0` turns it off.

Every write endpoint validates its input: an IP that is not an IP never reaches `nft`.

## Application layer

```ts
import { WebGuard } from "@tlk-sentinel/web";

const guard = new WebGuard({
  profilePath: "profiles/public.json",
  rulesPublicDir: "rules/public",
  lang: "en",
  trustedProxy: true,
});

export async function middleware(request: Request) {
  const verdict = await guard.inspect(request, { trustProxy: true });
  if (verdict.action === "block") {
    return new Response("blocked", { status: verdict.status, headers: verdict.headers });
  }
}
```

Verdicts carry hardened response headers (`nosniff`, `DENY`, HSTS, a locked-down
`Permissions-Policy`), so you can apply them to allowed responses as well.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `TLK_PROFILE` | `public` | which profile in `profiles/` to load |
| `TLK_PROFILE_PATH` | – | explicit profile file, overrides the above |
| `TLK_LANG` | `tr` | `tr` or `en`, applies to logs, alerts and panel |
| `TLK_SSHD_LOG` | `/var/log/auth.log` | empty disables the source |
| `TLK_NGINX_LOG` | – | nginx access log |
| `TLK_FW_BACKEND` | `nft` | `nft`, `ipset` or `none` |
| `TLK_FW_DRYRUN` | `1` | `0` to actually write firewall rules |
| `TLK_FW_CHAIN` | `tlk_sentinel` | nft set / ipset name used for timed bans |
| `TLK_ALLOWLIST` | `127.0.0.1,::1` | never banned |
| `TLK_PANEL` / `_HOST` / `_PORT` / `_TOKEN` | `1` / `127.0.0.1` / `8787` / – | dashboard |
| `TLK_DISCORD_WEBHOOK` | – | alert channel |
| `TLK_DB` | `data/sentinel.db` | SQLite event store |
| `TLK_REPUTATION_DIR` | `data/reputation` | CIDR blocklists, filename becomes the tag |
| `TLK_COUNTRY_FILE` | – | `CIDR,CC` table for country attribution |
| `TLK_ANOMALY` | `1` | behavioural scoring |
| `TLK_INTEGRITY` | – | comma-separated files to checksum |
| `TLK_SWEEP_MS` | `30000` | how often counters expire and files are re-checked |
| `TLK_ACTIVEDEF_SET` | `tlk_perma` | nft set for permanent bans (internal build) |
| `TLK_ACTIVEDEF_CRITS` | `2` | criticals from one IP before a permanent ban |

Reputation feeds are not bundled — see [`data/reputation/README.md`](data/reputation/README.md)
for the format and where to fetch Tor exit lists, Spamhaus DROP and FireHOL.

## Tests

```bash
npm test
```

60 tests on Node's built-in runner, no test framework. They cover ban thresholds and
escalation, profile gating, WAF bypass resistance across three encodings, reputation
CIDR matching and country tables, anomaly scoring and its cooldown, log tailing across
truncation **and logrotate**, integrity baselines, the SQLite store, alert payloads,
firewall input validation, and config defaults. Four are integration tests that boot
the real agent, drive it through a live log file and assert against the panel API; two
more assert that a build with the attribution removed fails its signature check and
**refuses to enforce bans**. CI runs the suite on Linux and Windows, Node 22 and 24.

## Layout

```
packages/core    events · profile gate · engine · reputation · anomaly · normalization · brand
packages/agent   log tailing · firewall · integrity · SQLite store · panel · active defense
packages/web     application middleware, same engine
rules/public     shipped rules (ssh, nginx, web)
profiles/        behaviour profiles
tests/           60 tests, no framework
scripts/         community build with leak and structural checks
docs/            architecture and threat model
```

[`docs/architecture.md`](docs/architecture.md) traces one log line from the file to the firewall.
[`docs/threat-model.md`](docs/threat-model.md) is the one to read before deploying it: what it does
not catch, and the four ways the tool itself can be turned against you.

## License

Source-available, see [LICENSE](LICENSE). The short version:

| | |
|:--|:--|
| Run it on your own machines, including your company's | yes |
| Run it commercially for your own business | yes |
| Read and modify the source for your own installation | yes |
| Send me a patch or a vulnerability report with code in it | yes |
| Redistribute it, publish it or mirror it | no |
| Sell it, rent it, or ship it inside a paid product | no |
| Host it as a service for someone else | no |
| Strip the attribution or the licence text | no |

The table is a summary; [LICENSE](LICENSE) is what governs, and its English text is
authoritative over the Turkish translation inside it. Anything in the "no" column can be
bought: talkdedsec@proton.me

Made by [talkdedsec](https://github.com/Talkdedsec). The attribution is signed with
Ed25519 and verified at runtime — a build that strips it disables its own enforcement.

---

<details>
<summary><b>Türkçe</b></summary>

**Bu depo topluluk sürümü.** `public` profiliyle çalışıyor: izler, puanlar, raporlar —
ban atmaz. Güvenlik duvarı yanıtlayıcısı da dry-run başlıyor, yani taze bir klon sen
ikisini de bilerek açana kadar sunucunda hiçbir şeye dokunmuyor.

### Neden

Küçük sunucu filoları SSH için `fail2ban` çalıştırır, uygulama tarafında hiçbir şey
yoktur ve olaydan müşteri arayınca haberdar olunur. tlk-sentinel bu boşluğu tek ajanla
kapatıyor: aynı kural motoru hem sunucu loglarını okuyor **hem de** uygulamanın içinde
çalışıyor. Böylece `/.env` yoklayan tarayıcı ile giriş ucunu döven aynı IP tek bir
olay hikâyesi oluyor.

Tek koddan iki davranış çıkıyor. Topluluk sürümü izler ve raporlar, iç sürüm uygular.
Bu bir kod çatallanması değil, sadece bir JSON profili.

### Neleri yakalıyor

- **SSH**: parola deneme, geçersiz kullanıcı, doğrudan root girişi
- **HTTP**: SQLi, XSS, dizin atlama, `.env`/`wp-admin`/`phpmyadmin` yoklaması, istek seli
- **Araçlar**: sqlmap, nikto, nuclei, gobuster, masscan imzaları
- **Bilinmeyen saldırılar**: hiçbir imzaya uymayan taramalar — istek ritmi, yol
  çeşitliliği, UA değişimi ve 404 oranından davranış skoru
- **Bilinen kötü kaynaklar**: offline CIDR itibar listeleri, tehdidi kritiğe çıkarır
- **Kurcalama**: `.env`, config ve binary dosyalarının sha256 tabanı

Kodlanmış yükler kaçamıyor: istekler eşleştirmeden önce çözülüyor (yüzde, çift yüzde
ve `+`), yani `?id=1%2520union%2520select%25201` düz hâliyle aynı şekilde yakalanıyor.
Her kodlama için regresyon testi var.

### Kurulum

Node 22.5+ gerekiyor (yerleşik SQLite için), başka çalışma zamanı bağımlılığı yok.

```bash
git clone https://github.com/Talkdedsec/tlk-sentinel /opt/tlk-sentinel
cd /opt/tlk-sentinel && npm install && npm run build
cp .env.example .env && npm run agent
```

Güvenlik duvarı **dry-run** başlıyor: uygulayacağı banı loglar, hiçbir şeye dokunmaz.
Bir gün izle, kararlar doğru görünüyorsa `TLK_FW_DRYRUN=0` yap. nft set komutları
yukarıdaki açılır bölümde.

### İki sürüm

`public` = izle-raporla, otomatik ban kapalı, özel kurallar yok, sadece stdout.
`self` = zorla-banla, tekrarlayanda ×4 süre, özel kurallar + bal kabı + bütünlük +
aktif savunma, Discord bildirimi.

`npm run dist:public` dağıtılacak ağacı üretir: iç profili, özel kuralları ve imza
anahtarını çıkarır, çıktıyı sır taramasından geçirir, public varsayılanın hâlâ pasif
olduğunu doğrular. **Kontrollerden biri düşerse build reddedilir** — yani zorlayıcı
bir varsayılan kazara yayına çıkamaz.

### Panel

Varsayılan `127.0.0.1:8787`. Başka bir arayüze açmak **`TLK_PANEL_TOKEN` zorunlu
kılar**; token yoksa ajan bağlanmayı reddeder ve bunu açılışta söyler. nginx arkasında
ayrıca IP kısıtı koy. Kapatmak için `TLK_PANEL=0`. Yazan tüm uçlar girdisini doğrular:
IP olmayan bir değer asla `nft`'ye ulaşmaz.

### Testler

`npm test` — 60 test, dış çatı yok. Ban eşikleri ve kademeli süre, profil geçidi, üç
kodlamada WAF bypass direnci, itibar ve ülke tabloları, anomali skoru ve soğuması, log
takibinin truncate **ve logrotate** altında sağ kalması, bütünlük tabanı, SQLite
deposu, uyarı gövdeleri, firewall girdi doğrulaması ve config varsayılanları. Dördü
gerçek ajanı ayağa kaldırıp panel API'sine karşı doğrulama yapan entegrasyon testi;
ikisi de imzası bozulmuş bir build'in **ban uygulamayı reddettiğini** doğruluyor. CI
Linux ve Windows'ta, Node 22 ve 24 ile çalışıyor.

### Belgeler

[`docs/architecture.md`](docs/architecture.md) tek bir log satırını dosyadan güvenlik
duvarına kadar takip ediyor. [`docs/threat-model.md`](docs/threat-model.md) ise kurmadan
önce okunması gereken: neyi yakalamadığı ve aracın kendisinin sana karşı nasıl
kullanılabileceği.

### Lisans

Kaynak-erişilebilir ([LICENSE](LICENSE)). Kısa hâli:

| | |
|:--|:--|
| Kendi makinelerinde çalıştırmak, şirketinin makineleri dahil | evet |
| Kendi işin için ticari olarak çalıştırmak | evet |
| Kendi kurulumun için kaynağı okumak ve değiştirmek | evet |
| Yama ya da içinde kod olan bir güvenlik bildirimi göndermek | evet |
| Yeniden dağıtmak, yayınlamak, aynalamak | hayır |
| Satmak, kiralamak, ücretli bir ürünün içinde vermek | hayır |
| Başkası için servis olarak barındırmak | hayır |
| Marka atfını ya da lisans metnini sökmek | hayır |

Tablo özet; bağlayıcı olan [LICENSE](LICENSE) ve içindeki İngilizce metin Türkçe
çevirinin üstünde. "Hayır" sütunundaki her şey satın alınabilir: talkdedsec@proton.me

Marka Ed25519 ile imzalı ve çalışma anında doğrulanıyor — imzayı söken bir build kendi
zorlama yeteneğini kapatır.

</details>
