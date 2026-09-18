//! Capture OCSF records from torda's NDJSON sink, bounded by a time window.
//!
//! The scoring seam (spec §3): torda writes OCSF NDJSON to `--output`; the harness
//! tails THAT file — no SIEM needed. Used by the live `run` subcommand; the pure
//! scorer consumes the captures.json this helps build, so nothing here is needed
//! to unit-test scoring.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Parse every well-formed OCSF record in an NDJSON file. Malformed lines are
/// skipped (honest accounting — a partial write mid-tail is not fatal).
pub fn read_ndjson(path: impl AsRef<Path>) -> Vec<Value> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect()
}

/// Records whose engine `time` falls in `[trigger, trigger + seconds]`. A record
/// with no `time` cannot be excluded, so it is kept.
pub fn window(records: &[Value], trigger_ms: i64, seconds: f64) -> Vec<Value> {
    let end = trigger_ms + (seconds * 1000.0) as i64;
    records
        .iter()
        .filter(|r| match r.get("time").and_then(Value::as_i64) {
            None => true,
            Some(t) => t >= trigger_ms && t <= end,
        })
        .cloned()
        .collect()
}
