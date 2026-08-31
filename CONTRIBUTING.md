# Contributing

## Read this part first

This repository is a build, not the working tree. The agent is developed in a private
repository and the public tree here is generated from it — `BUILD-INFO.txt` records when.
That has one consequence worth knowing before you spend an evening on a patch: a pull
request against this repository cannot be merged as a commit. It is read, and the change is
applied upstream with you credited in `CHANGELOG.md`.

So a patch is welcome, but keep it small and legible. For anything larger than a bug fix,
open an issue first and we will agree on the shape before you write it.

## Running it from source

```bash
npm install
npm run build
npm test
```

Node 22.5 or newer. There are no runtime dependencies — everything under `node_modules` is
a build or type dependency and none of it ships. If a change introduces a runtime
dependency, that is the change to justify, before anything else in the diff.

```bash
npm run agent:dev     # run the agent from TypeScript without building
npm run agent         # run the built agent
```

## Before you send anything

```bash
npm run typecheck
npm test
node scripts/check-test-count.mjs
node scripts/build-public.mjs
```

CI runs exactly these, on Node 22 and 24, on Linux and Windows. `check-test-count.mjs`
fails if the README's test count no longer matches the suite, so a new test means updating
that number. `build-public.mjs` fails if a change would leak something that is not meant to
be published.

## Rules

Detection rules live in `rules/` as JSON, and the public set is the one in `rules/public`.
A rule earns its place by being specific enough to ban on:

- **A rule that can fire on legitimate traffic is a bug, not a trade-off.** Every rule needs
  a fixture line that must match and one that must not. `tests/fixtures` holds both.
- **Score before you ban.** A pattern that is suspicious but not conclusive raises the
  reputation score and lets the threshold do the deciding. Reserve immediate bans for
  patterns that have no innocent reading.
- **Say what the log line means, not what the regex does.** The `description` field ends up
  in the panel, in front of somebody at three in the morning.

## What the code expects of you

- **No runtime dependencies.** The zero-dependency claim on the README is checked, and it is
  the reason this can be dropped on a server without an audit.
- **The agent has to survive its own inputs.** Log files rotate mid-read, get truncated, and
  contain bytes that are not UTF-8. A parser that throws takes the whole watcher down.
- **A ban is a destructive action.** Anything that writes a firewall rule needs a test that
  proves the rule is removed again — when the agent stops cleanly, and when it dies without
  warning.
- **Comments explain constraints, not mechanics.** If the code says what it does, let it.

## Reporting a bug

Use the bug report template and paste the raw log line. A described log line is not a
reproduction. Redact the source address if you would rather not publish it.

Security problems do not go in an issue — `SECURITY.md` has the address.

## Licence

The project is source-available, not open source; `LICENSE` has the terms. By sending a
patch you agree that it can be published under those same terms.
