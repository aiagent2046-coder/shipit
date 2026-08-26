# Security Policy

Drydock audits other people's code for production-readiness risks. A security
policy that cannot be acted on would be an odd thing for this project to ship,
so this one is written to be used rather than to be present.

## Reporting a vulnerability

Email **security@drydock.co**. Please include:

- what you did, in enough detail to repeat it;
- what happened, and what you expected instead;
- the affected host or path (`drydock.co`, `api.drydock.co`, or a file in this
  repository), and the release it was seen on — `GET /version` on any host
  returns the exact running commit.

**Do not open a public issue for a vulnerability.** Everything else — bugs,
wrong findings, false positives — belongs in an issue and is better off there.

If a report contains a secret you found leaked (ours or a third party's), say
that it exists and where; do not paste the value. Our own scanner stores
`AKIA****(20 chars)` rather than the key, for the same reason.

## What to expect

This is a small project. One person reads that mailbox, so the honest numbers
are:

| | |
| --- | --- |
| First reply | within 3 working days |
| Assessment (is it real, how bad) | within 10 working days |
| Fix for something exploitable against live customer data | as fast as we can, and you will be told when it ships |

If you have not heard back in a week, assume the mail was lost rather than
ignored, and try `support@drydock.co` or `email@drydock.co`, which reaches the
developer directly.

We will tell you what we concluded, including when we conclude it is not a
vulnerability and why. Credit in the release notes if you want it, anonymity if
you prefer. **There is no bug bounty** — we would rather say so than imply one.

## Supported versions

There is no version matrix. The hosted service runs exactly one release at a
time, tagged CalVer (`vYYYY.MM.DD-N`), and the only supported version is the
one currently deployed. `GET /version` on `api.drydock.co` returns its commit
and a link to the corresponding tree.

Self-hosting from this repository under the AGPL is entirely allowed, and no
older commit is supported: if you run your own, run `main`.

## Scope

**In scope**

- `drydock.co` and `api.drydock.co`
- this repository, including the deploy scripts and systemd units
- the Drydock GitHub App and the pull requests it opens
- the Telegram bot (`@SyndiAI_bot`)

**Out of scope**

- `45-10-40-169.sslip.io` — a legacy host kept alive only so that absolute
  links inside already-delivered reports keep resolving
- third-party services we depend on (GitHub, ЮKassa, Vercel, Timeweb) — report
  those to their own programmes
- scanner output alone. A tool that reports a missing header is not a finding
  here; show what an attacker gets.

## Testing rules

Two of these are not politeness — they are the difference between research and
an incident.

1. **Use your own accounts, repositories and databases.** Do not read another
   customer's audit, Fix Pack, or payment. If a flaw would let you, stop at the
   point where it is demonstrated and say so; you do not need the data to prove
   the hole.
2. **Do not point the live RLS check at a database you do not own.** The
   product itself will not run it without explicit consent, and that consent
   has no default value (`app/proof/rls_probe.py`) — for exactly this reason.
3. No denial of service, no load testing, no spam through the notification
   channels, no social engineering of the operator or of customers.

Stay inside those and we will treat your report as research and will not pursue
you for it.

## Things we already know

Saves you the trouble, and us the reply:

- audit reports and Fix Pack jobs are authorised by a per-row `access_token`,
  not by the id — a leaked UUID alone reads nothing;
- ЮKassa notifications are unsigned by design, so a notification is treated as
  a hint and every fact acted on is re-fetched from ЮKassa with our own
  credentials;
- the audit intake is public and rate-limited per client, and an anonymous LLM
  budget bounds spend per day.
