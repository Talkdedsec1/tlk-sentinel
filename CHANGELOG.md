# Changelog

## 1.1.0 — 2026-08-24

No change to detection or response. Everything here is about being able to check the
claims rather than take them on trust.

- `docs/architecture.md` follows one log line from the file through the engine to the
  firewall, including why the community build cannot ban even with the profile edited.
- `docs/threat-model.md` states what it does not catch — distributed low-and-slow
  traffic and IPv6 rotation walk past it — and the four ways the tool can be turned
  against you: a spoofed proxy header, log injection, locking yourself out, and a
  poisoned reputation feed.
- `SECURITY.md` with a disclosure address, scope and response window. The issue chooser
  points at it before anyone reaches a text field.
- A licence permission table in the README, in both languages, matching clauses 1 and 2
  of `LICENSE`.
- Releases now carry a tarball and its SHA-256. The workflow refuses to publish unless
  the suite passes, the README's test count still matches it, and the public build comes
  out monitor-only.
- CI fails if any of the four places the README claims a test count drifts from the
  suite.
- Dependabot on the dev dependencies and the workflow actions.

## 1.0.0 — 2026-08-23

First public release of the community build.

### Detection

- Rule engine with per-IP threshold windows over SSH and nginx logs: brute-force,
  invalid users, direct root login, SQLi, XSS, path traversal, sensitive-file probing
  (`.env`, `wp-admin`, `phpmyadmin`), request floods and known scanner User-Agents.
- Requests are normalized before matching — percent, double-percent and `+` encodings
  are decoded, so an encoded payload is caught exactly like its plain form.
- Behavioural scoring for attacks that match no signature: request rate, path
  diversity, User-Agent churn and 4xx ratio, with a per-IP cooldown so one scanner
  cannot flood the alert channel.
- Offline CIDR reputation lists. A match escalates the threat to critical. Optional
  `CIDR,CC` country table for attribution.
- File integrity watching against a sha256 baseline, re-checked on a timer.

### Response

- Bans through nftables or ipset, escalating to ×4 for repeat offenders, capped by the
  profile. **Dry-run is the default** — the agent logs the ban it would apply and
  writes no firewall rule until `TLK_FW_DRYRUN=0`.
- Alerts to stdout and Discord.
- SQLite event store using Node's built-in driver.
- Live dashboard over SSE: threat feed, severity split, ban list, one-click unban and
  24h statistics. Bound to loopback by default; exposing it elsewhere requires a token
  or the agent refuses to bind.

### Application layer

- `WebGuard` runs the same engine as middleware inside Next.js or any fetch-based
  runtime, with hardened response headers.

### Packaging

- Two behaviours from one codebase, selected by a JSON profile. The community build
  monitors and never bans; the internal build enforces.
- `npm run dist:public` stages the shippable tree, scans it for secrets, verifies no
  internal artefacts are present and asserts the public default is still passive. A
  rejected build writes nothing at all.
- Turkish and English throughout — logs, alerts and dashboard, via `TLK_LANG`.
- Zero runtime dependencies. Node 22.5+.

### Verification

- 60 tests on Node's built-in runner. Four boot the real agent against a live log file
  and assert against the panel API; two confirm that a build with the attribution
  stripped fails its signature check and refuses to enforce bans.
- CI on Linux and Windows, Node 22 and 24.
