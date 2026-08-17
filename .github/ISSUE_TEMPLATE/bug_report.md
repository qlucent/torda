---
name: Bug report
about: Something in the agent, a module, or the backend is broken
title: "[bug] "
labels: bug
assignees: ''
---

**Do not use this template for a security vulnerability.** See
[`SECURITY.md`](../../SECURITY.md) and use GitHub's private vulnerability
reporting instead.

## What's broken

A clear description of what happened vs. what you expected.

## Where

- [ ] `crates/agent` (the binary / wiring)
- [ ] `crates/core` (traits / `ModuleManager`)
- [ ] `crates/substrate` (stub / `linux-ebpf` / `windows-etw`)
- [ ] `crates/modules/*` — which module: `______`
- [ ] `crates/ocsf`
- [ ] `server/*` — which crate: `______`
- [ ] `deploy/*` (collector bundle, systemd unit, config)
- [ ] something else: `______`

## How to reproduce

1.
2.
3.

Include the exact command you ran (e.g.
`cargo run --features linux-ebpf --bin corr-triple-demo`) and, if relevant,
whether you were running with the privilege the feature needs (root / an
elevated eBPF or ETW build) or the default stub build.

## Environment

- OS + version:
- Rust toolchain (`rustc --version`):
- Build features used (default stub, `linux-ebpf`, `windows-etw`):
- Commit / branch:

## Logs / output

```
paste relevant stderr / OCSF NDJSON output here
```

## Additional context

Anything else that would help — e.g. whether this is a detection false
positive/negative, a build failure, or a runtime crash.
