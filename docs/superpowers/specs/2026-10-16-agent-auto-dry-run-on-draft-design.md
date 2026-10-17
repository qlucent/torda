# Agent auto-dry-run on Draft — design (PUBLIC, Apache-2.0)

Date: 2026-10-16. Repo: qlucent/torda (public agent/protocol). Public-safe: no
private cloud orchestration details. This is the one public prerequisite that
makes cloud-driven real remediation apply reach the agent's executor.

## Problem
The agent `Bridge` lifecycle is `draft → dry_run → submit_for_approval →
approve → run_canary`. `run_canary` guards `&[ActionState::Approved]`. Reaching
`Approved` requires the agent to pass through `DryRun` (so `submit_for_approval`,
which requires `DryRun`, can fire). But **no `CommandKind` triggers the agent's
`dry_run`**: `dispatch(CommandKind::Draft)` calls `bridge.draft` only (→
`Drafted`), and the control loop performs no further advance. So an action can
never leave `Drafted` via the protocol, `submit_for_approval` can never fire,
and a later `Canary` is always rejected. (The downstream cloud that drives
`Submit`/`Approve`/`Canary` is out of scope here; this spec fixes only the
missing `dry_run` step.)

## Goal
Handling a `Draft` command advances the agent `Drafted → DryRun` by running the
operator's dry-run through the agent's configured executor, and the `Draft`
`CommandResult` reflects that real dry-run outcome. Default (non-apply) agents
keep today's safe behavior.

## Decision (locked)
**Auto-dry-run on `Draft`** (vs. a new `CommandKind::DryRun` primitive). Chosen
for the smallest protocol surface (no new command, no extra round-trip) and
because it makes the already-assumed "a received+dry-run draft is ready for the
approval lifecycle" semantics true in one step.

## Design
- In the control dispatch for `CommandKind::Draft`, after `bridge.draft(action,
  actor)` succeeds, immediately call `bridge.dry_run(&action_id, executor,
  actor)` so the action lands in `DryRun`. The executor is the SAME one the loop
  already selects for execution (`select_executor(&apply)` →
  `DryRunExecutor` by default, `RealExecutor` when `apply.enabled`).
  - This requires the `Draft` branch to have access to the executor. Today
    lifecycle dispatch (`dispatch`) has no executor while execution dispatch
    (`dispatch_execution_fresh`) does. The implementation threads the loop's
    executor into the `Draft` handling (the control loop owns it per
    connection), or routes `Draft` through a path that carries the executor.
    No change to how `Canary`/`Rollout`/`Rollback` obtain their executor.
- `Bridge::dry_run` already exists: it transitions `Drafted|Mapped → DryRun` and
  calls `Executor::preview` (or the dry-run apply) over the action. `preview`
  is **non-mutating** (returns a human-readable string; it must not spawn a real
  process). The plan verifies this for `RealExecutor::preview`.
- The `Draft` `CommandResult` is produced as today (`Applied` + `detail` from the
  draft/dry-run), now genuinely reflecting the dry-run. `stage` stays `None`
  for `Draft` (unchanged; it is not an execution kind).
- **Default behavior preserved:** with no `apply` config (or `enabled=false`),
  `select_executor` returns `DryRunExecutor`, whose `preview`/dry-run is a no-op
  that mutates nothing — so a default agent's `Draft` still produces the benign
  result it does today, only now the bridge is at `DryRun` instead of `Drafted`.
- **Four-eyes is unaffected** — `dry_run` is not an approval; the agent's
  `approve` gate is untouched. (The agent does not enforce author≠approver; the
  driving cloud enforces human four-eyes before issuing the lifecycle commands —
  out of scope here.)

## Safety
- Dry-run is preview-only: no host mutation, no process spawn, bounded like any
  executor call. A `RealExecutor` that is apply-enabled still only previews here
  — real application happens exclusively in `run_canary`/`run_rollout`.
- No gate is relaxed: signature, replay, role, and state checks on the `Draft`
  command are unchanged; this only adds the `Drafted → DryRun` transition after a
  successful `draft`.
- If `dry_run` fails (executor preview errors), the `Draft` result is `Rejected`
  with the error detail; the action does not advance — the cloud will not see a
  dry-run-verified action, so no apply can proceed. Fail-closed.

## Testing
- A `Draft` against a default (dry-run) agent leaves the bridge at `DryRun` and
  returns the benign `Applied` result; nothing is executed on the host.
- A `Draft` against an apply-enabled agent runs `RealExecutor::preview` (asserted
  non-mutating — e.g. a payload that would create a file is NOT run during
  preview) and lands at `DryRun`.
- After the `Draft`, `submit_for_approval` succeeds (proving `DryRun` was
  reached), where before it failed from `Drafted`.
- A dry-run that errors → `Rejected`, bridge stays `Drafted` (fail-closed).
- Existing Draft/dispatch tests updated for the new post-Draft state.
- Gates: `cargo fmt --all --check`; `cargo clippy --all-targets --locked -- -D
  warnings`; `cargo test --locked` (fall back to `-p torda-remediation -p
  torda-control-plane --locked -j 1` if the full workspace hits LNK1104 on the
  ~96%-full D: drive; never delete other repos' build output).

## Boundaries
PUBLIC (Apache). Touches only the agent lifecycle dispatch + its tests
(`server/remediation/src/control.rs` and/or `crates/agent` wiring,
`server/remediation/src/bridge.rs` only if the dry_run call site needs it). NO
new `CommandKind`, NO cloud code, NO change to execution (`Canary`/`Rollout`/
`Rollback`) semantics. The private cloud lifecycle-drive that issues
`Submit`/`Approve`/`Canary` consumes this and is specified separately in
torda-cloud.
