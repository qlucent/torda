# CommandResult typed `stage` field — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a typed, signed, backward-compatible `stage: Option<StageOutcome>` to the agent control protocol's `CommandResult`, so a caller can learn a stage's fate (Promoted/Closed/RolledBack/AppliedUnverified) from a field instead of string-parsing `detail`.

**Architecture:** `StageOutcome` gains serde derives; `CommandResult` gains `stage: Option<StageOutcome>`. The field is folded into the signed `payload()` with `#[serde(skip_serializing_if = "Option::is_none")]` so a `None` result serializes byte-identically to today (existing signatures stay valid) while a `Some` result signs the stage (a relay cannot forge it). Execution results carry `Some(stage)`; lifecycle/reject results carry `None`.

**Tech Stack:** Rust (`torda-remediation`, `torda-control-plane`), serde (already a dependency of both).

**Spec:** public prerequisite of the private real-apply design (SP-D2a); this plan is self-contained and public-safe.

## Global Constraints
- PUBLIC repo `qlucent/torda` (`D:/Torda/torda-public`), Apache-2.0. Branch off `main` (currently `55ed03f`).
- NO new crate dependencies (serde is already used by both crates — `RemediationAction`/`CommandResult` derive it).
- **Backward compatibility is the load-bearing invariant:** a `CommandResult` with `stage: None` MUST produce the exact same `payload()` string as before this change (no `stage` key), so results signed by a pre-change agent still verify. This is achieved only by `#[serde(skip_serializing_if = "Option::is_none")]` in the `payload()` `Unsigned` struct — do not omit it.
- Touch only `server/remediation/src/bridge.rs` and `server/control-plane/src/lib.rs` (plus any `CommandResult`/`StageOutcome` literals in their tests/examples that `clippy --all-targets` flags). Do NOT change agent executor logic or add any cloud/orchestration code.
- Gates (from repo root): `cargo fmt --all --check`; `cargo clippy --all-targets --locked -- -D warnings`; `cargo test --locked`. KNOWN: D: ~96% full — if full-workspace `cargo test` hits `LNK1104`, retry that step once, then fall back to `cargo test --locked -p torda-control-plane -p torda-remediation -j 1` and report; NEVER delete another repo's build output.
- Commit messages end with:
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` / `Claude-Session: https://claude.ai/code/session_019se5tFub9ydymgLV9XwdHs`.

## Review Focus
- **Signature backward-compat:** a `None`-stage result's `payload()` must be byte-identical to pre-change (no `stage` key) or every existing signature breaks. → Task 2 test `none_stage_payload_has_no_stage_key_and_roundtrips`.
- **Stage is signed / unforgeable:** tampering `stage` on a `Some` result must invalidate the signature (it's in `payload()`, not just an unsigned sidecar). → Task 2 test `tampering_stage_invalidates_signature`.
- **Old result deserialization:** a JSON `CommandResult` with no `stage` key must deserialize to `stage: None` (the `#[serde(default)]`), not error. → Task 2 test `old_result_json_without_stage_deserializes_to_none`.
- **Execution vs. reject population:** an Applied execution result carries `Some(stage)`; a rejected/lifecycle result carries `None`. → Task 2 test `execution_result_has_some_stage_reject_has_none`.
- **Enum wire stability:** `StageOutcome` serde form stays the variant names (so a future consumer and this signer agree). → Task 1 test `stageoutcome_serde_roundtrips_variant_names`.

---

### Task 1: `StageOutcome` serde derives

**Files:**
- Modify: `server/remediation/src/bridge.rs` (the `StageOutcome` enum, ~line 46)
- Test: inline `#[cfg(test)]` in `server/remediation/src/bridge.rs`

**Interfaces:**
- Produces: `StageOutcome` now implements `serde::Serialize + serde::Deserialize` (variants unchanged: `Promoted, Closed, RolledBack, AppliedUnverified`).

- [ ] **Step 1: Write the failing test** (inline in bridge.rs tests):

```rust
#[test]
fn stageoutcome_serde_roundtrips_variant_names() {
    for v in [StageOutcome::Promoted, StageOutcome::Closed, StageOutcome::RolledBack, StageOutcome::AppliedUnverified] {
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(serde_json::from_str::<StageOutcome>(&s).unwrap(), v);
    }
    // externally-tagged unit variants serialize as their quoted name
    assert_eq!(serde_json::to_string(&StageOutcome::Promoted).unwrap(), "\"Promoted\"");
}
```
(If bridge.rs has no `serde_json` dev-dependency in scope for tests, use the crate's existing test conventions; `serde_json` is a standard dev-dep here — confirm via `server/remediation/Cargo.toml` and use what's present.)

- [ ] **Step 2: Run to verify it fails** — `cargo test -p torda-remediation --locked stageoutcome_serde` → FAIL (StageOutcome: not Serialize/Deserialize).

- [ ] **Step 3: Add the derives.** Change the `StageOutcome` derive line to:
```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StageOutcome {
    Promoted,
    Closed,
    RolledBack,
    AppliedUnverified,
}
```
(Use whatever serde import form the file already uses — if `use serde::{Serialize, Deserialize};` is present, you may write `Serialize, Deserialize`.)

- [ ] **Step 4: Run to verify it passes** — `cargo test -p torda-remediation --locked stageoutcome_serde` → PASS.

- [ ] **Step 5: fmt + clippy + commit**

```bash
cargo fmt --all --check && cargo clippy -p torda-remediation --all-targets --locked -- -D warnings
git add server/remediation/src/bridge.rs
git commit -m "feat(remediation): derive Serialize/Deserialize for StageOutcome"
```

---

### Task 2: `CommandResult.stage` (typed, signed, backward-compatible)

**Files:**
- Modify: `server/control-plane/src/lib.rs` (`CommandResult` struct ~428, `payload()` ~462, `execute_fresh` ~599, `sign_outcome` ~638, and every other `CommandResult` producer/literal in the file + its tests/examples)
- Test: inline `#[cfg(test)]` in `server/control-plane/src/lib.rs`

**Interfaces:**
- Consumes: `torda_remediation::bridge::StageOutcome` (now serde, Task 1).
- Produces: `CommandResult` gains `pub stage: Option<StageOutcome>`; `sign_outcome(&self, action_id, session, seq, outcome, detail, stage: Option<StageOutcome>) -> CommandResult`.

- [ ] **Step 1: Write the failing tests** (inline in control-plane tests). Use the crate's existing `CommandSigner`/`Ed25519Verifier` test helpers (mirror an existing result-signing test):

```rust
#[test]
fn none_stage_payload_has_no_stage_key_and_roundtrips() {
    let r = CommandResult {
        action_id: "a".into(), outcome: CommandOutcome::Applied, detail: "applied".into(),
        agent: "host-1".into(), session: "s".repeat(64), seq: 1, stage: None,
        signature: String::new(),
    };
    let p = r.payload();
    assert!(!p.contains("stage"), "None stage must NOT appear in the signed payload (backward-compat)");
    // sign + verify round-trips
    let signer = CommandSigner::from_seed("host-1", [9u8; 32]);
    let mut signed = r.clone();
    signed.signature = signer.sign_payload(&signed.payload());
    let mut v = Ed25519Verifier::new();
    v.trust("host-1", signer.verifying_key());
    assert!(v.verify(&signed.payload(), &signed.signature, "host-1"));
}

#[test]
fn some_stage_is_in_payload_and_roundtrips_and_tamper_breaks_sig() {
    let r = CommandResult {
        action_id: "a".into(), outcome: CommandOutcome::Applied, detail: "Promoted".into(),
        agent: "host-1".into(), session: "s".repeat(64), seq: 1,
        stage: Some(StageOutcome::Promoted), signature: String::new(),
    };
    assert!(r.payload().contains("Promoted"));
    // serde round-trip of the struct preserves the typed stage
    let j = serde_json::to_string(&r).unwrap();
    assert_eq!(serde_json::from_str::<CommandResult>(&j).unwrap().stage, Some(StageOutcome::Promoted));
    // signature covers stage: tampering it invalidates
    let signer = CommandSigner::from_seed("host-1", [9u8; 32]);
    let mut signed = r.clone();
    signed.signature = signer.sign_payload(&signed.payload());
    let mut v = Ed25519Verifier::new();
    v.trust("host-1", signer.verifying_key());
    let mut tampered = signed.clone();
    tampered.stage = Some(StageOutcome::RolledBack);
    assert!(!v.verify(&tampered.payload(), &signed.signature, "host-1"), "tampered stage must fail verify");
}

#[test]
fn old_result_json_without_stage_deserializes_to_none() {
    let json = r#"{"action_id":"a","outcome":"Applied","detail":"applied","agent":"host-1","session":"s","seq":1,"signature":"ab"}"#;
    let r: CommandResult = serde_json::from_str(json).unwrap();
    assert_eq!(r.stage, None);
}
```
Add an execution-path test that drives `execute_fresh` (reuse the crate's existing execute_fresh/AgentControlLoop test harness — find a test that already exercises a Canary/Rollout command) and asserts the returned `CommandResult.stage.is_some()` for an Applied outcome and `.is_none()` for a rejected one. Name it `execution_result_has_some_stage_reject_has_none`. (Match the existing harness; do not invent a new one.)

- [ ] **Step 2: Run to verify they fail** — `cargo test -p torda-control-plane --locked` (the new tests) → FAIL (no `stage` field).

- [ ] **Step 3: Add the field.** In `CommandResult` (after `seq`, before `signature`):
```rust
    /// Typed stage fate for execution results (Canary/Rollout) — `Promoted`/`Closed`/
    /// `RolledBack`/`AppliedUnverified`. `None` for lifecycle/reject results. Folded into
    /// `payload()` only when `Some`, so a `None` result signs byte-identically to the
    /// pre-`stage` protocol (existing signatures stay valid) while a `Some` stage is signed
    /// and cannot be forged by a relay. `#[serde(default)]` lets older results (no `stage`
    /// key) deserialize as `None`.
    #[serde(default)]
    pub stage: Option<StageOutcome>,
```
Import `StageOutcome`: add `use torda_remediation::bridge::StageOutcome;` (or extend the existing `torda_remediation::bridge::` use).

- [ ] **Step 4: Fold into `payload()`.** In the `Unsigned<'a>` struct inside `payload()`, add as the LAST field:
```rust
            #[serde(skip_serializing_if = "Option::is_none")]
            stage: &'a Option<StageOutcome>,
```
and set `stage: &self.stage,` in the `Unsigned { … }` initializer. (Placing it last + skip-if-none means `None` reproduces the exact current JSON.)

- [ ] **Step 5: Thread the stage through producers.** Change `sign_outcome` to accept `stage: Option<StageOutcome>` (add the param) and set `stage` on the `CommandResult` it builds. Update callers:
  - `execute_fresh`: capture the `StageOutcome` and pass `Some(stage)` on the `Ok(stage)` branch, `None` on the `Err` branch. (Keep the existing `detail = format!("{stage:?}")` on success.)
  - Every other `sign_outcome` caller (lifecycle `handle_fresh`, rejections) passes `None`.
  - Any direct `CommandResult { … }` struct literal in the crate, its tests, or its examples: add `stage: None` (or `Some(...)` where a test intends a stage). Let `clippy --all-targets` find them all.

- [ ] **Step 6: Run the tests** — `cargo test -p torda-control-plane --locked` → the four new tests PASS; existing tests stay green.

- [ ] **Step 7: fmt + clippy + commit**

```bash
cargo fmt --all --check && cargo clippy -p torda-control-plane --all-targets --locked -- -D warnings
git add server/control-plane/src/lib.rs
git commit -m "feat(control-plane): typed signed backward-compatible CommandResult.stage"
```

---

### Task 3: Full-slice gates

**Files:** none (validation only), unless `--all-targets` surfaced a `CommandResult`/`StageOutcome` literal in another crate's example/test that must set `stage` — fix those minimally and note them.

- [ ] **Step 1: Full gates** (from repo root): `cargo fmt --all --check`; `cargo clippy --all-targets --locked -- -D warnings`; `cargo test --locked`. If full-workspace `cargo test` hits `LNK1104` (disk), retry once, then fall back to `cargo test --locked -p torda-control-plane -p torda-remediation -j 1` and record the disk limitation. Do NOT delete other repos' build output.
- [ ] **Step 2:** If any cross-crate literal needed `stage: None`, commit: `fix: set CommandResult.stage in remaining literals` (same attribution footer). Otherwise no commit.
- [ ] **Step 3:** Hand off to in-window Codex review (`codex review --base main -c model_reasoning_effort="medium"` from torda-public), fix findings, then push + open PR (CI runs Linux/macOS/Windows + eBPF/ETW/cargo-deny) → user merges.
