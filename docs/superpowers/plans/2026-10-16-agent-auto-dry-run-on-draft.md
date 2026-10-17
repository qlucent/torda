# Agent Auto-Dry-Run on Draft — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Handling a `Draft` command advances the agent `Drafted → DryRun` by running the operator's dry-run preview through the control loop's executor, so the agent is ready for the `Submit`/`Approve` lifecycle and the `Draft` result reflects a real dry-run.

**Architecture:** Add one executor-holding handler method `handle_draft_fresh` on `AgentControlHandler` (control-plane) that runs the replay-guarded Draft dispatch, then `bridge.dry_run` on success; route `CommandKind::Draft` to it from `AgentControlLoop::serve_one` (which already owns `self.executor`). No change to `dispatch`/`handle_fresh` (still serve Submit/Approve/Reject/Abort), no change to execution. Preview is non-mutating, so default and apply-enabled agents both stay side-effect-free at Draft.

**Tech Stack:** Rust; `torda-control-plane` (`AgentControlHandler`/`AgentControlLoop`), `torda-remediation` (`Bridge`), `crates/agent` (`RealExecutor`/`DryRunExecutor`).

**Spec:** `docs/superpowers/specs/2026-10-16-agent-auto-dry-run-on-draft-design.md`

## Global Constraints
- PUBLIC repo qlucent/torda, Apache-2.0. Branch `feat/agent-auto-dry-run-on-draft` (off main @ 9ad744a). Public-safe — NO private cloud details.
- NO new `CommandKind`; NO change to `Canary`/`Rollout`/`Rollback` execution semantics; NO cloud code.
- Dry-run is **preview-only, non-mutating** (`Bridge::dry_run` calls `Executor::preview`, which returns a `String` and must spawn no process / touch no host state).
- **Default-agent behavior preserved:** with no `apply` config (or `enabled=false`), the loop's executor is `DryRunExecutor`; a Draft still produces the benign `Applied` result it does today, only now the bridge ends at `DryRun` instead of `Drafted`.
- **Fail-closed:** if the Draft dispatch fails (e.g. duplicate/invalid), the result is `Rejected` and the bridge is unchanged; if `dry_run` returns `Err` (wrong state), the result is `Rejected` and the bridge stays `Drafted` (`dry_run` bails before mutating).
- The Draft `CommandResult` keeps `stage: None` (Draft is not an execution kind) and still echoes the command's `(session, seq)` so the signed ack stays backward-compatible with the cloud reading it as `DraftAccepted`.
- Gates from repo root: `cargo fmt --all --check`; `cargo clippy --all-targets --locked -- -D warnings`; `cargo test --locked`. If the full-workspace `cargo test` hits `LNK1104` (D: ~96% full), fall back to `-p torda-remediation -p torda-control-plane --locked -j 1` and report; NEVER delete another repo's `target/`.

## Review Focus
- **Default (dry-run) agent:** a Draft leaves the bridge at `DryRun`, returns the benign `Applied` result, and executes nothing. → Task 1 test.
- **Duplicate / invalid Draft:** the Draft dispatch fails → `Rejected`, bridge unchanged (fail-closed). → Task 1 test.
- **Lifecycle readiness:** after the auto-dry-run, `submit_for_approval` succeeds (it requires `DryRun`) where before it failed from `Drafted`. → Task 1 test.
- **Signed-ack shape:** the Draft result has `stage: None` and sign→verify round-trips (cloud backward-compat). → Task 1 test.
- **`RealExecutor::preview` non-mutation:** previewing a payload that would create a file spawns no process and creates nothing. → Task 2 test.

---

### Task 1: Auto-dry-run the Draft in the control loop

**Files:**
- Modify: `server/control-plane/src/lib.rs` (add `AgentControlHandler::handle_draft_fresh`; route `CommandKind::Draft` to it in `AgentControlLoop::serve_one`'s lifecycle branch)
- Test: `server/control-plane/src/lib.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `AgentControlHandler::{verifier, authz, sign_outcome}`, free fn `dispatch_fresh(bridge, guard, cmd, verifier, authz) -> anyhow::Result<()>`, `Bridge::dry_run(&mut self, id: &str, executor: &dyn Executor, actor: &str) -> anyhow::Result<DryRunPreview>`, `AgentControlLoop.executor: Box<dyn Executor>`, `AgentControlLoop.guard`.
- Produces: `AgentControlHandler::handle_draft_fresh(&self, bridge: &mut Bridge<A>, guard: &mut ReplayGuard, cmd: ControlCommand, executor: &dyn Executor) -> CommandResult` — gates + drafts the command, then on success runs `dry_run`; signs `Applied` iff both succeed, else `Rejected`; `stage` always `None`.

- [ ] **Step 1: Write the failing test `draft_auto_dry_runs_to_dryrun`**

A fresh `Bridge` + `ReplayGuard` + handler; build a signed `Draft` command (reuse the existing test helpers that construct/sign a `Draft`, e.g. the ones used by the current Draft dispatch tests); call `handler.handle_draft_fresh(&mut bridge, &mut guard, cmd, &PreviewOnly)` where `PreviewOnly` is the existing no-op test executor. Assert: `result.outcome == CommandOutcome::Applied`, `result.stage.is_none()`, `bridge.state("<id>") == Some(ActionState::DryRun)`, and then `bridge.submit_for_approval("<id>", "operator").is_ok()`.

- [ ] **Step 2: Run it, verify it fails**

Run: `cargo test --locked -p torda-control-plane draft_auto_dry_runs_to_dryrun`
Expected: FAIL (`handle_draft_fresh` undefined).

- [ ] **Step 3: Implement `handle_draft_fresh`**

Mirror `execute_fresh`'s shape: capture `action_id`/`actor`/`session`/`seq` before the move; run `dispatch_fresh(bridge, guard, cmd, self.verifier, self.authz)`; on `Ok(())` call `bridge.dry_run(&action_id, executor, &actor)` and map `Ok→(Applied,"dry-run preview")` / `Err(e)→(Rejected, e.to_string())`; on the dispatch `Err(e)` use `(Rejected, e.to_string())` and do NOT call `dry_run`; finish with `self.sign_outcome(action_id, session, seq, outcome, detail, None)`.

- [ ] **Step 4: Route `Draft` to it in `serve_one`**

In the lifecycle (`!cmd.kind.is_execution()`) branch, before the existing `handle_fresh` call, special-case `matches!(cmd.kind, CommandKind::Draft(_))` → `self.handler.handle_draft_fresh(bridge, &mut self.guard, cmd, self.executor.as_ref())`. All other lifecycle kinds (incl. the `Abort` kill-switch scheduler-drop logic) keep the existing `handle_fresh` path unchanged.

- [ ] **Step 5: Add `default_agent_draft_is_benign_and_executes_nothing` + `duplicate_draft_is_rejected_fail_closed`**

Benign: drive a `Draft` through `serve_one` (or `handle_draft_fresh`) with the default `DryRunExecutor`; assert `Applied`, bridge at `DryRun`, and no host effect (DryRunExecutor spawns nothing — assert via its no-op nature). Fail-closed: a second `Draft` for the same `action_id` (or an otherwise-invalid draft) → `Rejected`, `bridge.state` unchanged from its prior value.

- [ ] **Step 6: Run the suite + gates**

Run: `cargo test --locked -p torda-control-plane`; then `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D warnings`.
Expected: PASS / clean. (Update any existing Draft-dispatch test that asserted the post-Draft state is `Drafted` — it is now `DryRun` on the wire path; the un-guarded `dispatch`/`handle` path is unchanged.)

- [ ] **Step 7: Commit**

```bash
git add server/control-plane/src/lib.rs
git commit -m "feat(remediation): auto-dry-run on Draft (Drafted->DryRun) so the agent is approval-ready"
```

---

### Task 2: Pin `RealExecutor::preview` as non-mutating

**Files:**
- Test: `crates/agent/src/apply.rs` (`#[cfg(test)]`) — or `crates/agent/src/lib.rs` tests if `RealExecutor` lives there
- Modify (only if the test fails): `crates/agent/src/apply.rs` `RealExecutor::preview`

**Interfaces:**
- Consumes: `RealExecutor` (apply-enabled executor), `torda_remediation::bridge::Executor::preview(&self, action: &RemediationAction) -> String`.

- [ ] **Step 1: Write the failing/guard test `real_executor_preview_does_not_execute`**

Construct a `RealExecutor` (apply-enabled, the methods allow-listed as the other `apply.rs` tests set one up) and a `RemediationAction` whose `Method::Shell` `payload` would create a sentinel file in a temp dir (e.g. `touch <tempdir>/sentinel`). Call `exec.preview(&action)`; assert the returned value is a non-empty `String` AND the sentinel file does NOT exist (preview spawned nothing).

- [ ] **Step 2: Run it**

Run: `cargo test --locked -p torda-agent real_executor_preview_does_not_execute` (use the crate's actual package name; discover via `cargo pkgid`/`Cargo.toml` if not `torda-agent`).
Expected: PASS if `preview` is already a pure string builder (it should be). If it FAILS (preview spawns), fix `preview` to only describe the action (no `Command::spawn`), then re-run to green.

- [ ] **Step 3: Commit**

```bash
git add crates/agent/src/apply.rs
git commit -m "test(agent): pin RealExecutor::preview as non-mutating (no process spawn)"
```

---

## Notes for the executor
- `dry_run` takes `&dyn Executor` (shared), so `self.executor.as_ref()` is the right borrow in `serve_one`; `self.guard` is borrowed `&mut` and `self.handler` shared — disjoint fields, same pattern `execute_fresh` already uses.
- The `dry_run`-returns-`Err` branch is practically unreachable right after a successful `draft` (the state is `Drafted`, `preview` is infallible), but the `Rejected` mapping MUST still be coded for fail-closed correctness — do not `.unwrap()` the `dry_run` result.
- Default `DryRunExecutor` remains the executor whenever `apply` is absent/`enabled=false` (`select_executor`), so Task 1's wire path is benign by default with no config change.
