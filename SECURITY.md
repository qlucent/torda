# Security Policy

`torda` is a security tool — it watches a host's process, network, and
file activity and correlates that into attack-chain findings. If it has a
vulnerability, that is a serious matter, and we want to hear about it
privately before it's public.

## Supported versions

This project is **pre-1.0**. There are no numbered releases yet — only
`main`. Security fixes land against the tip of `main`; there is no backport
policy to older commits.

## Reporting a vulnerability

**Please do NOT open a public GitHub issue for a security vulnerability.**
A public issue on a security agent's own tracker is itself a disclosure.

Instead, report privately using one of these channels:

1. **GitHub private vulnerability reporting** (preferred): open this repo's
   **Security** tab → **"Report a vulnerability"**. This creates a private
   advisory visible only to maintainers and works even before the project has
   any other infrastructure set up.
2. **Backup contact:** `info@qlucent.com`.

Please include:
- What you found and why it's a vulnerability (impact, not just a diff).
- Steps to reproduce, or a minimal PoC if you have one.
- The commit/version you tested against.
- Whether the issue is in the agent (`crates/*`), the backend (`server/*`),
  or the deploy tooling (`deploy/*`).

### In scope

Anything that would let an attacker do more than the agent's own design
intends — e.g. a module that could be tricked into touching the OS outside
the substrate, a Remediation Bridge safety gate (sign/dry-run/canary/
rollback/kill-switch/audit) that can be bypassed, a Findings Engine score
that can be forged or hidden, or an OCSF envelope that isn't safely parsed
by downstream consumers.

### Out of scope

The dev-preview collector bundle (`deploy/collector/`) is **documented and
intentionally insecure by default** — no TLS, no auth, localhost-only. That's
a known, called-out limitation (see its README and `docs/DEPLOY.md`), not a
vulnerability to report.

## What to expect

This is a pre-1.0, best-effort open-source project. **We do not currently
promise a response-time SLA.** We will make a genuine effort to acknowledge
reports promptly and fix real issues, but there is no committed turnaround
and no bug-bounty program.

## Reporting a detection gap or false negative

If the agent *should* have detected something and didn't — that's a
detection-quality bug, not necessarily a vulnerability, but if the gap is
security-sensitive (e.g. a rule that's trivially bypassed, a substrate signal
that's silently dropped) please report it through the same private channel
above rather than a public issue, so it can be assessed first.
