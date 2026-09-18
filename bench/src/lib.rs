//! Framework-anchored benchmark harness for the torda agent.
//!
//! Ground truth is DECLARED in `config/techniques.toml` (each case's ATT&CK
//! technique → OCSF class + torda rule); scoring compares the OCSF NDJSON the
//! agent emits against that declaration — never a tool's own opinion of what it
//! saw. The scoring engine ([`model`]/[`score`]/[`latency`]/[`conformance`]) is
//! pure and links [`torda_ocsf`] for the REAL envelope + class UIDs (no
//! hand-copied table to drift), so it is fully unit-testable with synthetic
//! captures — the "prove the loop works" milestone — with no live agent.
//!
//! Open by design (Apache-2.0): a benchmark is only worth anything if anyone can
//! reproduce it.

pub mod capture;
pub mod conformance;
pub mod latency;
pub mod model;
pub mod peer;
pub mod report;
pub mod score;

pub use model::{load_captures, load_registry, Captures, Case, CaseCapture, Expect};
