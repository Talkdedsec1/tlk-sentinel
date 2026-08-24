# Security policy

tlk-sentinel is a security product. A flaw in it is worth more to an attacker than a
flaw in most software, so please do not report one in a public issue.

## Reporting a vulnerability

Mail **talkdedsec@proton.me** with `tlk-sentinel` in the subject. Include the version or
commit, the profile you were running (`public` or `self`), and enough detail to
reproduce — a log line that bypasses a rule is usually enough.

You get an acknowledgement within 72 hours and an assessment within 7 days. If a fix is
warranted I aim to ship it inside 30 days and credit you in the release notes unless you
ask me not to. If I disagree that it is a vulnerability, you get the reasoning, not
silence.

Please give me those 30 days before publishing.

## In scope

- Rules that can be bypassed by an encoding, a header or a request shape the normalizer
  misses.
- Anything that lets an unauthenticated request reach the dashboard, the unban endpoint
  or the SSE stream.
- Firewall command construction — an IP-shaped input that reaches a shell.
- Ban evasion through proxy or `X-Forwarded-For` handling.
- Anything that makes the agent ban an address it should not have banned, at will.
- Signature verification of the attribution block.

## Out of scope

- Missing detections for attack classes the README does not claim to catch. Those are
  feature requests; open an issue.
- Findings against a build with `TLK_FW_DRYRUN=0` on a host you do not control.
- Denial of service by writing a very large log file to a machine you already own.
- Reports produced by a scanner with no evidence that the finding is reachable.

## Supported versions

| Version | Supported |
|:--|:--|
| 1.0.x | yes |
| < 1.0 | no |

Only the latest patch of the newest minor gets fixes. There is no long-term branch.

## What this repository is

This is the community build, produced by `scripts/build-public.mjs` from a private
source tree. It ships the `public` profile, which monitors and never bans, and the
public rule set. The internal rules and the enforcing profile are not in this
repository — a vulnerability report about them still belongs in the same mailbox.
