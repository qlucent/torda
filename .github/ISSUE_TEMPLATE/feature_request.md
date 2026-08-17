---
name: Feature request
about: Propose new detection, a new module, or another improvement
title: "[feature] "
labels: enhancement
assignees: ''
---

## What problem does this solve

Describe the real gap — e.g. a signal the substrate doesn't capture yet, a
detection rule that's missing, a Findings Engine scoring gap, or a
Remediation Bridge capability.

## Proposed approach

Sketch how this fits the existing architecture:

- Does it need a new **substrate** signal (kernel probe / snapshot table), or
  can it be built from signals the substrate already exposes? Remember: **no
  module opens a kernel probe or queries the OS directly** — the substrate is
  the only door.
- Is this a new **module** (subscribes to `EventBus` / reads
  `SnapshotProvider`, emits `torda_ocsf::OcsfEnvelope`), a **Findings Engine**
  change (recompute logic, scoring, group-by-fix), or a **Remediation
  Bridge** change (must stay a safety-gated bridge, never an auto-decider)?

## Alternatives considered

Other ways to solve this, and why this approach is preferred.

## Additional context

Anything else — links to prior art, related issues, or a partial
implementation.
