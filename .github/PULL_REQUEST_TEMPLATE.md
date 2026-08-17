## Summary

What does this change, and why?

## Where

- [ ] `crates/agent` / `crates/core` / `crates/substrate`
- [ ] `crates/modules/*` — which module: `______`
- [ ] `crates/ocsf`
- [ ] `server/*` — which crate: `______`
- [ ] `deploy/*` / docs only

## Definition of done

- [ ] `cargo build` and `cargo test` are green (run from the repo root).
- [ ] `cargo fmt` and `cargo clippy --all-targets` are clean.
- [ ] New behavior is covered by a test vector (golden-vector / integration /
      unit — whichever fits the change).
- [ ] Public traits are documented; safety-relevant code has an audit log
      line.

## Architecture invariants this PR does NOT violate

- [ ] **No module reaches outside the substrate.** A module only subscribes
      to `EventBus` or reads `SnapshotProvider` — it never opens a kernel
      probe or queries the OS directly.
- [ ] **OCSF on the wire.** Any new emitted data is a `torda_ocsf::OcsfEnvelope`;
      the backend doesn't get handed an ad-hoc format.
- [ ] **Findings: recompute, never trust a source's severity label.** If this
      touches the Findings Engine, every score input is persisted so the
      score stays explainable.
- [ ] **Remediation is a bridge, never a decider.** If this touches
      remediation, no code path applies a fix the user didn't author and
      trigger, and the safety gates (sign, dry-run, canary, rollback, kill
      switch, audit) are intact.
- [ ] N/A — this PR doesn't touch modules, OCSF, findings, or remediation
      (e.g. docs/CI/tooling only).

## How was this tested

Describe the test vectors added/updated, and — if this touches a real
kernel-probe path (`linux-ebpf` / `windows-etw`) — whether you validated it
live (root / Administrator) or only against the stub substrate.

## Deferred / follow-ups

Anything consciously left out of scope for this PR.
