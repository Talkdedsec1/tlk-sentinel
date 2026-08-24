# Architecture

One process, one rule engine, three ways in. This is what happens between a line landing in a log
file and an address disappearing from your server.

## The shape of it

```
  sources                     core                          responders
  ─────────                   ────                          ──────────
  auth.log      ─┐                                     ┌─→  firewall    nft / ipset
  access.log    ─┤   toEvent  ┌──────────────┐         ├─→  alert       stdout, Discord
  sha256 timer  ─┼──────────→ │    Engine    │ ──────→ ┤─→  active def  permanent set
  Next.js req   ─┘            └──────────────┘         └─→  store       SQLite → panel
                                 ▲        ▲
                                 │        │
                            profile    rules + reputation + anomaly
```

Everything above the engine turns something into a `RawEvent`: an origin, a timestamp, an IP and one
line of text. Everything below it consumes a `ResponderAction`, which is either `alert` or `ban`.
The engine itself never touches the network, the filesystem or the firewall — which is why the same
class runs inside the agent and inside a Next.js middleware without changing.

## The engine

`packages/core/src/engine.ts`. It holds one sliding window per compiled rule and does four things
per event.

1. **Allowlist.** An address in the allowlist returns immediately, before any rule runs.
2. **Match.** Each rule whose `origin` matches gets its regex tested against the line, truncated to
   8 KB so a hostile log line cannot turn into a regex denial of service.
3. **Threshold.** A match adds a hit to that rule's window, keyed by IP. Below `threshold`, nothing
   happens — the window remembers and the event is over. At or above it, a `Threat` is raised and
   that key's window resets, so one burst produces one threat rather than one per line.
4. **Decide.** Every threat produces an `alert`. It produces a `ban` only if *all* of these hold:
   the attribution signature verifies, the profile is in `enforce` mode, `autoBan` is on, the threat
   has an IP, and its severity is `high` or `critical`.

Before deciding, enrichment runs: if the address is in a reputation feed, the threat is promoted to
`critical` regardless of what the rule said. A Tor exit probing for a dotfile is not the same event
as a home connection doing it once.

Ban duration comes from the profile and quadruples if the address is already inside an unexpired
ban, capped at `maxBanSeconds`.

## Profiles are the whole product difference

`packages/core/src/profile.ts` is 34 lines and it is the only thing separating the community build
from the internal one. A profile declares a `visibility` (`public` or `self`), a response mode, and
which detectors may load.

Rules carry a visibility too. At construction the engine drops every rule the profile does not
allow, so a `self` rule inside a `public` deployment is not merely inert — it is never compiled.
`profiles/public.json` ships with `mode: monitor` and `autoBan: false`, and
`scripts/build-public.mjs` refuses to produce a public build if that is ever untrue.

The same gate runs a second time at decision time. Flipping the JSON is not enough by itself: the
attribution signature has to verify as well.

## Sources

- **Log tailing** (`sources/tail.ts`) follows a file across rotation, so a logrotate that moves the
  file out from under it picks up the new one instead of silently going quiet. Truncation is
  detected by the size going backwards.
- **Integrity** (`detectors/integrity.ts`) takes a sha256 baseline of the paths in
  `TLK_INTEGRITY` and re-hashes them on the sweep timer. A changed digest is fed in as an event like
  any other, so it flows through the same rules and responders.
- **Web middleware** (`packages/web`) constructs an `Engine` with only the `web-middleware` rules
  and returns a verdict per request. It is the same engine class, so a rule change applies to the
  application and the server logs at once.

## Normalisation, and why the encodings matter

`normalizeRequestLine` decodes percent-encoding, double percent-encoding and `+` before matching.
Without it, `?id=1%2520union%2520select` is a different string to `?id=1 union select` and a
signature written for one misses the other. The tests assert each of those encodings separately,
because this is exactly the kind of thing that quietly rots.

## Anomaly scoring

`packages/core/src/anomaly.ts` is what catches the attacks no signature describes. Per address, in a
60-second window, it tracks request rate, distinct paths, distinct user agents and the 4xx ratio.
Crossing the score trigger raises a `behavioral-anomaly` threat at `high` severity, then a
five-minute cooldown per address keeps a scan from producing a threat per second.

It is deliberately crude. It exists to notice that something is enumerating your site, not to
classify what.

## Responders

- **Firewall** (`responders/firewall.ts`) calls `nft` or `ipset` through `execFile` with an argument
  array — no shell, so there is no quoting to get wrong. The address is validated against
  `isValidIp` and the duration is range-checked before either is passed to anything. It starts in
  dry-run, where it logs the ban it would have applied and schedules the matching unban, so you can
  read the timeline you would have got.
- **Alerts** go to stdout always and to Discord if a webhook is configured. The webhook is read from
  the environment and never written to a log line.
- **Store** (`store.ts`) writes threats and bans into SQLite through `node:sqlite`, which is why
  Node 22.5 is the floor. That module ships with Node, which is how the runtime dependency count
  stays at zero.
- **Panel** (`panel.ts`) serves the dashboard and an SSE stream. It refuses to start on a
  non-loopback host without `TLK_PANEL_TOKEN` — a mistake in a config file cannot expose the unban
  endpoint to the internet by accident.

## The attribution signature

`packages/core/src/brand.ts` holds a string, an Ed25519 public key and a signature over that string.
It is verified once and cached. A build with the attribution edited out fails verification, and a
failed verification disables enforcement and active defence while leaving detection running.

The private key is not in this repository and is excluded from the public build by name. The point
is not that the signature cannot be removed — anyone with the source can delete the check. The point
is that a copy which merely strips the credit stops enforcing, and stops loudly enough to notice.

## What runs on a timer

One interval, `TLK_SWEEP_MS`, does everything periodic: expires sliding windows, expires the
in-memory ban map, ages out anomaly tracks and re-hashes the integrity targets. There is no
scheduler and no second process.
