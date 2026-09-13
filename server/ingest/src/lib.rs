//! Ingest: the thin agent→engine wiring. Parses OCSF SBOM envelopes, matches
//! components against a (fixture) CVE feed, and composes the findings engine
//! end-to-end into scored findings + remediation items.
pub mod compliance;
pub mod correlation;
pub mod cve_source;
pub mod drift;
pub mod enrichment;
pub mod file_activity;
pub mod fim;
pub mod fixtures;
pub mod matching;
pub mod network;
pub mod nvd_source;
pub mod pipeline;
pub mod process;
pub mod reachability;
pub mod scoring;
pub mod store;
pub mod verify;
pub mod version;
