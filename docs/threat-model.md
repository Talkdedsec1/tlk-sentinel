# Threat model

What this defends, what it does not, and where it can be made to work against you. If you are
deciding whether to put it on a server, read the second half first — the limits are the honest part.

## What it assumes

- The host is not already compromised. Everything here reads logs the host wrote and trusts them.
  An attacker with root can write whatever they like into `auth.log`.
- The clock is roughly right. Every window and every ban expiry is wall-clock arithmetic.
- The person running it can read the source. This is a source-available product on purpose; the
  detection logic is not the secret, the internal rule set is.

## What it defends against

| Threat | How |
|:--|:--|
| SSH brute force and user enumeration | threshold windows per address on `auth.log` |
| Web scanners and exploit probes | signature rules on normalized request lines |
| Encoded payloads that evade naive matching | percent, double-percent and `+` decoded before matching, with a regression test per encoding |
| Attack tooling | User-Agent signatures for sqlmap, nikto, nuclei, gobuster, masscan and similar |
| Scans that match nothing | behavioural score on rate, path diversity, UA churn and 4xx ratio |
| Known-bad sources | offline CIDR reputation; a match promotes the threat to critical |
| Quiet tampering with your own files | sha256 baseline re-checked on a timer |
| Repeat offenders | ban duration quadruples inside an unexpired ban, capped |

## What it does not defend against

Say these out loud before deploying it, because a security tool that lets you believe otherwise is
worse than no tool.

- **A compromised host.** If the attacker can write your logs, they can make this ban anyone.
- **Anything that never touches a log line.** Attacks on services you did not point it at are
  invisible to it. It knows what you configured, nothing else.
- **Encrypted or application-internal abuse** — a valid login used maliciously, a business-logic
  flaw, an insider. There is no signature for "this authenticated user should not be doing that".
- **Distributed low-and-slow attacks.** Every window is keyed by address. One request per minute
  from ten thousand addresses is, to this engine, ten thousand quiet visitors.
- **IPv6 rotation.** A /64 is 18 quintillion addresses and the engine bans single addresses.
  Per-prefix banning is not implemented.
- **Zero-day payloads.** The anomaly scorer notices enumeration; it does not recognise an exploit it
  has no signature for.
- **Availability.** It is not a DDoS mitigation and it will not save a server that is out of CPU.

## Where it can be turned against you

These are the ways the tool itself is the risk, which is the part most security READMEs skip.

**Spoofed source addresses.** In web-middleware mode with `trustedProxy: true`, the client address
is read from a proxy header. If the request can reach your app without passing the proxy that sets
that header, an attacker chooses which address gets banned — including yours. Only enable
`trustedProxy` when every path to the application goes through a proxy that overwrites the header,
and keep the allowlist populated.

**Log injection.** A field an attacker controls — a User-Agent, a URL, a username — ends up in a log
line and is then matched. Crafting a line that reads as another address's misbehaviour is the
classic way to make an IDS ban a third party. This is why dry-run is the default: you are meant to
read a day of decisions before letting them reach the firewall.

**Locking yourself out.** Enforcing mode plus an SSH rule plus a fat-fingered password is exactly
how it goes. Put your own addresses in the allowlist before turning `TLK_FW_DRYRUN=0`, and keep a
console session open the first time.

**The panel.** It exposes an unban endpoint and the threat history. It refuses to bind a
non-loopback host without a token, but a token in a URL query string ends up in the proxy's own
access log. Put it behind a reverse proxy with real authentication, or keep it on loopback and
tunnel to it.

**The database.** `data/sentinel.db` records evidence lines from your logs, which means it contains
whatever your logs contain — paths, user agents, sometimes usernames. Treat it as data with the same
sensitivity as the logs it was built from. There is no retention policy; it grows until you rotate
it.

**Reputation feeds.** They are yours to supply, and they are trusted completely — an address in a
feed is escalated to critical without a second opinion. A bad or poisoned feed is a way to make you
ban customers. Prefer the well-known sources and read what you install.

## Deliberate design decisions

- **The community build cannot ban.** Not by policy, by construction: `profiles/public.json` is
  monitor-only, the build script refuses to publish otherwise, and enforcement additionally requires
  a signature check to pass.
- **Firewall calls take an argument array, never a shell string.** The address is validated and the
  duration range-checked first. There is no path from a log line to a shell.
- **Match input is truncated to 8 KB.** A megabyte-long log line cannot be used to stall the engine
  in a regex.
- **The webhook is never logged.** It is read from the environment and used; it does not appear in
  alert output or in the panel.
- **One process, zero runtime dependencies.** Nothing to audit but this repository and Node itself.
  It is also the reason there is no supply chain to attack.

## Reporting

Vulnerabilities go to talkdedsec@proton.me, not to a public issue. Scope, timelines and what counts
as in-scope are in [SECURITY.md](../SECURITY.md).
