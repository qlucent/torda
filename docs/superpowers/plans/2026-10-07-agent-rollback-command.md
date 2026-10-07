# Agent `CommandKind::Rollback` primitive — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a first-class, signed, gated `CommandKind::Rollback` to the agent control protocol so the control plane can command rollback of an already-applied action on an agent (none exists today — `Executor::rollback` only fires inside a failing canary).

**Architecture:** Mirror the existing `Canary`/`Rollout` execution path. New `CommandKind::Rollback` is an execution command (needs an `Executor`); a new `Bridge::run_rollback` accepts it from the applied states (`Closed`/`Verify`/`Rollout`), calls `Executor::rollback` over the action's applied targets, moves state to `RolledBack`, and returns a new `StageOutcome::RolledBackByOperator`. It routes through the same signed → replay → role → state gate as Canary/Rollout.

**Tech Stack:** Rust (`torda-remediation`, `torda-control-plane`); serde already present.

**Spec:** public prerequisite of the private SP-D2b fleet-apply design; self-contained and public-safe.

## Global Constraints
- PUBLIC repo `qlucent/torda` (`D:/Torda/torda-public`), Apache-2.0. Branch off `main` (currently `e60d030`, SP-D2a merged).
- NO new crate dependencies.
- Rollback is remote code execution (runs the operator's `action.rollback` script via the SP-D1 real executor) → it MUST stay behind the full gate stack (ed25519 signature → `ReplayGuard` freshness → `RolePolicy` authorization → Bridge state guard) exactly like `Canary`/`Rollout`; it is `is_execution()` and routes ONLY through `dispatch_execution_fresh`, never plain `dispatch`. The agent still runs the no-op `DryRunExecutor` unless opted into real apply (SP-D1 `apply.enabled`), so this changes nothing for default agents.
- Touch only `server/remediation/src/{bridge.rs,control.rs}` and, if its `execute_fresh` matches on `CommandKind` directly, `server/control-plane/src/lib.rs` (+ any `CommandKind`/`StageOutcome` match arms elsewhere in these crates' tests/examples that `clippy --all-targets` flags as non-exhaustive). Do NOT change the agent crate wiring or add cloud code.
- Gates (from repo root): `cargo fmt --all --check`; `cargo clippy --all-targets --locked -- -D warnings`; `cargo test --locked`. D: is ~96% full — if full-workspace `cargo test` hits `LNK1104`, retry once, then fall back to `cargo test --locked -p torda-remediation -p torda-control-plane -j 1` and report; NEVER delete another repo's build output.
- Commit footer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_019se5tFub9ydymgLV9XwdHs`.

## Review Focus
- **State gate:** `run_rollback` must be accepted ONLY from applied states (`Closed`/`Verify`/`Rollout`) and audited-rejected from any other (e.g. `Drafted`/`Approved`/`RolledBack`) — never roll back an action that was never applied. → Task 1 test `run_rollback_only_from_applied_states`.
- **Executes real rollback over applied targets:** `run_rollback` calls `Executor::rollback` for each applied target and ends in `RolledBack` returning `RolledBackByOperator`. → Task 1 test `run_rollback_reverts_applied_and_reports_operator_outcome`.
- **Lost-applied fallback:** if the in-memory `applied` set is empty (agent restarted) but the action has targets, roll back over the action's full `targets.asset_ids` (host-scoped; rollback scripts are idempotent) rather than silently no-opping. → Task 1 test `run_rollback_falls_back_to_full_targets_when_applied_empty`.
- **Authorization + routing:** `Rollback` is `is_execution()`, is permitted for `Operator`/`Admin` (not `Approver`/`Responder`), and `dispatch` (non-execution path) refuses it. → Task 2 tests `rollback_is_execution_and_operator_permitted` + `dispatch_refuses_rollback`.
- **Signed stage round-trips:** `StageOutcome::RolledBackByOperator` serializes/verifies in `CommandResult.stage` (SP-D2a payload fold). → Task 2 test `rolledbackbyoperator_stage_signs_and_roundtrips` (or covered via an execution-result assertion).

---

### Task 1: `StageOutcome::RolledBackByOperator` + `Bridge::run_rollback`

**Files:**
- Modify: `server/remediation/src/bridge.rs` (`StageOutcome` enum ~line 47; add `run_rollback` near `run_rollout` ~line 411; reuse `rollback_applied`/`set_state`/`log`)
- Test: inline `#[cfg(test)]` in `server/remediation/src/bridge.rs`

**Interfaces:**
- Produces: `StageOutcome::RolledBackByOperator`; `Bridge::run_rollback(&mut self, id: &str, executor: &mut dyn Executor, actor: &str) -> anyhow::Result<StageOutcome>`.

- [ ] **Step 1: Write failing tests** (inline in bridge.rs tests; mirror existing bridge tests that drive an action to Closed/Canary via the public Bridge API + a stub Executor that records `apply`/`rollback` calls):

```rust
#[test]
fn run_rollback_only_from_applied_states() {
    // From a non-applied state (e.g. freshly Drafted/Approved), run_rollback must bail + not touch the executor.
    // Build a Bridge with an action in Approved (not yet applied); assert run_rollback(..) is Err and the stub executor saw no rollback calls.
}
#[test]
fn run_rollback_reverts_applied_and_reports_operator_outcome() {
    // Drive an action to Closed via run_canary -> run_rollout with a stub executor + Verifier::Fixed.
    // Then run_rollback: assert Ok(StageOutcome::RolledBackByOperator), state == RolledBack, and the stub's rollback was called for each previously-applied target.
}
#[test]
fn run_rollback_falls_back_to_full_targets_when_applied_empty() {
    // Construct a Bridge record in an applied state (Verify/Closed) whose `applied` vec is empty but action.targets has ["h1"].
    // run_rollback -> rollback called for h1 (full-targets fallback), Ok(RolledBackByOperator), state RolledBack.
}
```
(Use the crate's actual bridge test harness + a local `struct RecordingExecutor { applied: Vec<String>, rolled_back: Vec<String> }` impl of `Executor`. If existing bridge tests already define such a stub, reuse it.)

- [ ] **Step 2: Run to verify fail** — `cargo test -p torda-remediation --locked run_rollback` → FAIL (undefined).

- [ ] **Step 3: Add the variant** to `StageOutcome` (bridge.rs:47), after `AppliedUnverified`:
```rust
    /// Rollback explicitly commanded by an operator (via `CommandKind::Rollback`) on an
    /// already-applied action — distinct from the internal canary-failure `RolledBack`.
    RolledBackByOperator,
```

- [ ] **Step 4: Implement `run_rollback`** (add after `run_rollout`, ~line 411):
```rust
    /// Operator-commanded rollback of an already-applied action. Accepted only from the
    /// applied states (`Closed`, `Verify` = applied-but-unverified, or a promoted
    /// `Rollout`); runs `Executor::rollback` over the applied targets and moves to
    /// `RolledBack`. If the in-memory applied set was lost (agent restart), falls back to
    /// the action's full target list (host-scoped; rollback scripts must be idempotent).
    pub fn run_rollback(
        &mut self,
        id: &str,
        executor: &mut dyn Executor,
        actor: &str,
    ) -> anyhow::Result<StageOutcome> {
        let rec = self
            .actions
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("no action {id}"))?;
        if !matches!(
            rec.state,
            ActionState::Closed | ActionState::Verify | ActionState::Rollout
        ) {
            self.log(
                id,
                Some(rec.state),
                ActionState::RolledBack,
                actor,
                Outcome::Rejected,
                "rollback requires an applied action",
            );
            anyhow::bail!("action {id} not in an applied state");
        }
        // Fallback: if the applied set was lost (restart), roll back the full target set.
        if self.actions.get(id).unwrap().applied.is_empty() {
            let targets = self.actions.get(id).unwrap().action.targets.asset_ids.clone();
            self.actions.get_mut(id).unwrap().applied = targets;
        }
        self.rollback_applied(id, executor, actor); // reverts each applied target, clears `applied`
        self.set_state(id, ActionState::RolledBack, actor, "operator-commanded rollback");
        Ok(StageOutcome::RolledBackByOperator)
    }
```

- [ ] **Step 5: Run tests** — `cargo test -p torda-remediation --locked run_rollback` → PASS.

- [ ] **Step 6: fmt + clippy + commit**
```bash
cargo fmt --all --check && cargo clippy -p torda-remediation --all-targets --locked -- -D warnings
git add server/remediation/src/bridge.rs
git commit -m "feat(remediation): StageOutcome::RolledBackByOperator + Bridge::run_rollback"
```

---

### Task 2: `CommandKind::Rollback` + authorization + dispatch routing

**Files:**
- Modify: `server/remediation/src/control.rs` (`CommandKind` enum ~99, `label` ~116, `is_execution` ~133, `Role::permits` ~55, `dispatch_execution_fresh` match ~535)
- Possibly modify: `server/control-plane/src/lib.rs` (ONLY if its `execute_fresh` matches `CommandKind` directly rather than delegating to `dispatch_execution_fresh`)
- Test: inline `#[cfg(test)]` in `server/remediation/src/control.rs`

**Interfaces:**
- Consumes: `Bridge::run_rollback` + `StageOutcome::RolledBackByOperator` (Task 1).
- Produces: `CommandKind::Rollback` (unit variant); `is_execution()` true for it; `Operator`/`Admin` may issue it.

- [ ] **Step 1: Write failing tests** (inline in control.rs tests; mirror existing CommandKind/dispatch tests):
```rust
#[test]
fn rollback_is_execution_and_operator_permitted() {
    assert!(CommandKind::Rollback.is_execution());
    assert!(Role::Operator.permits(&CommandKind::Rollback));   // permits is private to the module -> ok in-module test
    assert!(Role::Admin.permits(&CommandKind::Rollback));
    assert!(!Role::Approver.permits(&CommandKind::Rollback));
    assert!(!Role::Responder.permits(&CommandKind::Rollback));
}
#[test]
fn dispatch_refuses_rollback() {
    // A Rollback routed through plain `dispatch` (the lifecycle path) must be refused
    // (defense in depth) — only dispatch_execution_fresh runs it. Mirror the existing
    // "dispatch refuses Canary/Rollout" test if present.
}
```
Also add, in whichever crate signs results, a test `rolledbackbyoperator_stage_signs_and_roundtrips` asserting a `CommandResult` with `stage: Some(StageOutcome::RolledBackByOperator)` has the stage in `payload()` and round-trips (mirror SP-D2a's `some_stage_...` test). If control-plane is the natural home, put it there.

- [ ] **Step 2: Run to verify fail** — `cargo test -p torda-remediation --locked rollback` → FAIL.

- [ ] **Step 3: Add the variant + wiring** in control.rs:
  - `CommandKind` (after `Rollout`, line 112):
    ```rust
        /// Operator-commanded rollback of an already-applied action (execution — needs an
        /// executor; runs the action's rollback script via the real executor).
        Rollback,
    ```
  - `label` (add arm): `CommandKind::Rollback => "Rollback",`
  - `is_execution`: `matches!(self, CommandKind::Canary | CommandKind::Rollout | CommandKind::Rollback)`
  - `Role::permits` Operator arm: add `| CommandKind::Rollback` to the Operator `matches!(...)`.
  - `dispatch_execution_fresh` match (line 535): add
    ```rust
        CommandKind::Rollback => bridge.run_rollback(&cmd.action_id, executor, &cmd.actor),
    ```
    (note: `run_rollback` takes no `verifier` — a rollback is not verified.)

- [ ] **Step 4: Check control-plane `execute_fresh`.** Read `server/control-plane/src/lib.rs` `execute_fresh`: if it just calls `dispatch_execution_fresh(...)`, NO change is needed (Rollback flows through automatically, and the `Ok(stage)` branch already sets `stage: Some(RolledBackByOperator)` via SP-D2a's `sign_outcome`). If instead it matches on `CommandKind` itself, add a `Rollback` arm mirroring Canary/Rollout. Also fix any other non-exhaustive `CommandKind` match the compiler/`clippy --all-targets` flags across these crates' src/tests/examples (add a `Rollback` arm).

- [ ] **Step 5: Run tests** — `cargo test -p torda-remediation -p torda-control-plane --locked` → PASS (new + existing).

- [ ] **Step 6: fmt + clippy + commit**
```bash
cargo fmt --all --check && cargo clippy --all-targets --locked -- -D warnings
git add -A
git commit -m "feat(remediation): CommandKind::Rollback (execution, operator-authorized) + dispatch"
```

---

### Task 3: Full-slice gates

**Files:** none unless `--all-targets` surfaced a `CommandKind`/`StageOutcome` match arm in another crate's test/example that must handle the new variants — fix minimally.

- [ ] **Step 1: Full gates** (repo root): `cargo fmt --all --check`; `cargo clippy --all-targets --locked -- -D warnings`; `cargo test --locked` (disk fallback to `-p torda-remediation -p torda-control-plane -j 1` if `LNK1104`, report).
- [ ] **Step 2:** Commit any residual match-arm fixes (same footer), else no commit.
- [ ] **Step 3:** Hand off to in-window Codex review (`codex review --base main -c model_reasoning_effort="medium"`), fix findings, then push + open PR (CI: Linux/macOS/Windows + eBPF/ETW/cargo-deny) → user merges.
