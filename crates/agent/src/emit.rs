//! A rotating NDJSON file sink — the on-disk seam a log shipper (Vector /
//! Filebeat / Splunk-UF) tails to carry OCSF events into a SIEM. The agent
//! itself makes NO network call; this file IS the seam,
//! the shipper does the network.
//!
//! `FileEmitter` implements `torda_core::OcsfEmitter` exactly like `StdoutEmitter`
//! in `main.rs`, so swapping the sink changes no module. It is deliberately
//! panic-free: a serialize error, a write error, or even a poisoned mutex (a
//! prior panic while the lock was held) all degrade to an `eprintln!`
//! diagnostic and a dropped line — the agent must never die because its log
//! disk filled or a single record failed to serialize.
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use torda_core::OcsfEmitter;
use torda_ocsf::OcsfEnvelope;

/// Default rotation threshold (MB) when `--rotate-mb`/`$TORDA_ROTATE_MB` is absent
/// or unparsable.
pub const DEFAULT_ROTATE_MB: u64 = 64;
/// Bounded number of rolled files kept alongside the active one
/// (`events.ndjson.1` .. `.{MAX_ROLLS}`); older rolls are dropped.
pub const DEFAULT_MAX_ROLLS: u32 = 3;

struct FileState {
    writer: BufWriter<File>,
    bytes_written: u64,
    base_path: PathBuf,
    rotate_bytes: u64,
    max_rolls: u32,
}

impl FileState {
    /// Roll `base_path` -> `.1`, shifting existing rolls down (`.1` -> `.2`,
    /// ...), dropping anything that would fall past `max_rolls`, then reopen a
    /// fresh, empty `base_path`.
    fn roll(&mut self) -> std::io::Result<()> {
        self.writer.flush()?;
        if self.max_rolls > 0 {
            for i in (1..self.max_rolls).rev() {
                let src = roll_path(&self.base_path, i);
                let dst = roll_path(&self.base_path, i + 1);
                if src.exists() {
                    let _ = fs::rename(&src, &dst);
                }
            }
            let dst1 = roll_path(&self.base_path, 1);
            let _ = fs::rename(&self.base_path, &dst1);
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.base_path)?;
        self.writer = BufWriter::new(file);
        self.bytes_written = 0;
        Ok(())
    }

    /// Append one NDJSON line, rolling first if it would push the active file
    /// past `rotate_bytes`. Flushes so a tailing shipper sees it immediately.
    fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let line_len = line.len() as u64 + 1; // + '\n'
        if self.rotate_bytes > 0
            && self.bytes_written > 0
            && self.bytes_written + line_len > self.rotate_bytes
        {
            self.roll()?;
        }
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        self.bytes_written += line_len;
        Ok(())
    }
}

fn roll_path(base: &Path, n: u32) -> PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// Rotating NDJSON file sink. Thread-safe via `Mutex<FileState>`; never
/// panics out of `emit` — see module docs.
pub struct FileEmitter {
    state: Mutex<FileState>,
}

impl FileEmitter {
    /// Create (or open) the sink at `path`. Creates the parent directory if
    /// missing, opens/creates the base file in append mode, and seeds the
    /// byte count from its current size so rotation stays correct across a
    /// restart. Construction errors are returned as `Err` — the caller
    /// (main.rs) fails closed rather than silently falling back to stdout.
    pub fn new(
        path: impl Into<PathBuf>,
        rotate_bytes: u64,
        max_rolls: u32,
    ) -> std::io::Result<Self> {
        let base_path = path.into();
        if let Some(parent) = base_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&base_path)?;
        let bytes_written = file.metadata()?.len();
        Ok(Self {
            state: Mutex::new(FileState {
                writer: BufWriter::new(file),
                bytes_written,
                base_path,
                rotate_bytes,
                max_rolls,
            }),
        })
    }
}

impl OcsfEmitter for FileEmitter {
    fn emit(&self, rec: OcsfEnvelope) {
        let line = match serde_json::to_string(&rec) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("emit serialize error: {e}");
                return;
            }
        };
        // Never propagate a poisoned lock (a prior panic while the lock was
        // held) — recover the inner state and keep collecting.
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Err(e) = guard.write_line(&line) {
            eprintln!("emit file write error (dropping record): {e}");
        }
    }
}

/// Discover the requested output sink + rotation threshold from CLI flags /
/// env vars, mirroring `main.rs`'s `discover_config_path` pattern:
/// `--output <path>` (or `--output=<path>`) takes precedence, else
/// `$TORDA_OUTPUT`. `None` means no file output was requested — the caller
/// falls back to `StdoutEmitter` (today's byte-identical default).
/// `--rotate-mb <N>` / `$TORDA_ROTATE_MB` (MB) is converted to bytes; an absent
/// or unparsable value falls back to `DEFAULT_ROTATE_MB`, never panics.
pub fn discover_output() -> Option<(PathBuf, u64)> {
    discover_output_from(std::env::args().skip(1), |k| std::env::var(k).ok())
}

/// Testable core of `discover_output`: takes the argument iterator and an env
/// lookup function so tests can supply synthetic args/env without mutating
/// real process state (which would race across parallel tests).
fn discover_output_from(
    args: impl Iterator<Item = String>,
    env: impl Fn(&str) -> Option<String>,
) -> Option<(PathBuf, u64)> {
    let mut path: Option<PathBuf> = None;
    let mut rotate_mb: Option<u64> = None;
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        if let Some(inline) = arg.strip_prefix("--output=") {
            path = Some(PathBuf::from(inline));
            continue;
        }
        if arg == "--output" {
            if let Some(p) = args.next() {
                path = Some(PathBuf::from(p));
            }
            continue;
        }
        if let Some(inline) = arg.strip_prefix("--rotate-mb=") {
            rotate_mb = inline.trim().parse::<u64>().ok();
            continue;
        }
        if arg == "--rotate-mb" {
            if let Some(v) = args.next() {
                rotate_mb = v.trim().parse::<u64>().ok();
            }
            continue;
        }
    }

    let path = path.or_else(|| env("TORDA_OUTPUT").map(PathBuf::from))?;

    let rotate_mb = rotate_mb
        .or_else(|| env("TORDA_ROTATE_MB").and_then(|s| s.trim().parse::<u64>().ok()))
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_ROTATE_MB);

    Some((path, rotate_mb.saturating_mul(1024 * 1024)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    /// A fresh, unique temp dir for one test, under the OS temp dir,
    /// namespaced by pid + an atomic counter (parallel-test-safe).
    fn temp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "torda-emit-test-{}-{}-{}",
            std::process::id(),
            tag,
            n
        ));
        fs::create_dir_all(&dir).expect("create temp test dir");
        dir
    }

    fn sample_record(tag: &str) -> OcsfEnvelope {
        OcsfEnvelope::new(
            torda_ocsf::class::AGENT_HEALTH,
            "Agent Health",
            torda_ocsf::Metadata {
                product: "torda".into(),
                version: "test".into(),
                tenant_id: "tenant-test".into(),
            },
            torda_ocsf::Device {
                hostname: "test-host".into(),
                os: "test-os".into(),
                os_version: "0".into(),
            },
            serde_json::json!({ "tag": tag }),
        )
    }

    fn read_lines(path: &Path) -> Vec<String> {
        let f = File::open(path).expect("open output file");
        BufReader::new(f)
            .lines()
            .map(|l| l.expect("read line"))
            .collect()
    }

    #[test]
    fn one_record_round_trips_as_one_line() {
        let dir = temp_dir("one-record");
        let path = dir.join("events.ndjson");
        let emitter = FileEmitter::new(&path, 64 * 1024 * 1024, 3).expect("construct emitter");

        let rec = sample_record("hello");
        let expected = serde_json::to_value(&rec).unwrap();
        emitter.emit(rec);

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 1, "exactly one line written");
        let got: serde_json::Value = serde_json::from_str(&lines[0]).expect("line is valid JSON");
        assert_eq!(got, expected, "line round-trips to the same JSON");
    }

    #[test]
    fn multiple_records_are_n_lines_in_order() {
        let dir = temp_dir("multi-record");
        let path = dir.join("events.ndjson");
        let emitter = FileEmitter::new(&path, 64 * 1024 * 1024, 3).expect("construct emitter");

        for i in 0..5 {
            emitter.emit(sample_record(&format!("rec-{i}")));
        }

        let lines = read_lines(&path);
        assert_eq!(lines.len(), 5);
        for (i, line) in lines.iter().enumerate() {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            assert_eq!(v["data"]["tag"], format!("rec-{i}"), "lines stay in order");
        }
    }

    #[test]
    fn rotation_rolls_the_base_file_and_bounds_roll_count() {
        let dir = temp_dir("rotation");
        let path = dir.join("events.ndjson");
        // A tiny threshold so a handful of records force several rotations.
        let rotate_bytes = 200u64;
        let max_rolls = 3u32;
        let emitter = FileEmitter::new(&path, rotate_bytes, max_rolls).expect("construct emitter");

        // Emit enough records to roll well past max_rolls worth of files.
        for i in 0..80 {
            emitter.emit(sample_record(&format!("rotation-record-number-{i:04}")));
        }

        assert!(path.exists(), "active base file still present");
        for n in 1..=max_rolls {
            assert!(roll_path(&path, n).exists(), "roll .{n} should exist");
        }
        assert!(
            !roll_path(&path, max_rolls + 1).exists(),
            "roll count must never exceed max_rolls — older rolls are dropped"
        );

        // Every surviving file (base + rolls) must still be valid NDJSON.
        for candidate in
            std::iter::once(path.clone()).chain((1..=max_rolls).map(|n| roll_path(&path, n)))
        {
            for line in read_lines(&candidate) {
                let _: serde_json::Value =
                    serde_json::from_str(&line).expect("rolled file line is valid JSON");
            }
        }
    }

    #[test]
    fn unwritable_target_does_not_panic_construction() {
        let dir = temp_dir("unwritable");
        // Path whose parent component is itself an existing regular file —
        // create_dir_all/open must fail, not panic.
        let blocker = dir.join("blocker-file");
        fs::write(&blocker, b"not a directory").expect("create blocker file");
        let bad_path = blocker.join("events.ndjson");

        let result = std::panic::catch_unwind(|| FileEmitter::new(&bad_path, 1024, 3));
        assert!(result.is_ok(), "construction must not panic");
        assert!(
            result.unwrap().is_err(),
            "an unwritable target must fail closed (Err), not silently succeed"
        );
    }

    #[test]
    fn emit_survives_a_poisoned_lock() {
        // Simulate a prior panic while the internal lock was held (e.g. some
        // unrelated bug elsewhere) and prove `emit` still recovers and keeps
        // writing instead of propagating the poison.
        let dir = temp_dir("poison");
        let path = dir.join("events.ndjson");
        let emitter =
            Arc::new(FileEmitter::new(&path, 64 * 1024 * 1024, 3).expect("construct emitter"));

        let poisoner = emitter.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.state.lock().unwrap();
            panic!("intentionally poison the mutex");
        })
        .join(); // join returns Err (thread panicked) — that's expected, ignored.

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            emitter.emit(sample_record("post-poison"));
        }));
        assert!(result.is_ok(), "emit must not panic on a poisoned lock");

        let lines = read_lines(&path);
        assert_eq!(
            lines.len(),
            1,
            "the record still gets written after recovery"
        );
    }

    #[test]
    fn concurrent_emits_produce_no_torn_lines() {
        let dir = temp_dir("concurrent");
        let path = dir.join("events.ndjson");
        let emitter =
            Arc::new(FileEmitter::new(&path, 8 * 1024 * 1024, 3).expect("construct emitter"));

        let threads_n = 8;
        let per_thread = 50;
        let mut handles = Vec::new();
        for t in 0..threads_n {
            let e = emitter.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..per_thread {
                    e.emit(sample_record(&format!("t{t}-r{i}")));
                }
            }));
        }
        for h in handles {
            h.join().expect("writer thread panicked");
        }

        let lines = read_lines(&path);
        assert_eq!(
            lines.len(),
            threads_n * per_thread,
            "total line count matches all emits"
        );
        for line in &lines {
            let _: serde_json::Value =
                serde_json::from_str(line).expect("every line is valid, non-torn JSON");
        }
    }

    #[test]
    fn discover_output_parses_flag_space_form() {
        let args = vec!["--output".to_string(), "/tmp/out.ndjson".to_string()];
        let got = discover_output_from(args.into_iter(), |_| None);
        assert_eq!(
            got,
            Some((
                PathBuf::from("/tmp/out.ndjson"),
                DEFAULT_ROTATE_MB * 1024 * 1024
            ))
        );
    }

    #[test]
    fn discover_output_parses_flag_equals_form() {
        let args = vec!["--output=/tmp/out2.ndjson".to_string()];
        let got = discover_output_from(args.into_iter(), |_| None);
        assert_eq!(
            got,
            Some((
                PathBuf::from("/tmp/out2.ndjson"),
                DEFAULT_ROTATE_MB * 1024 * 1024
            ))
        );
    }

    #[test]
    fn discover_output_falls_back_to_env_var() {
        let got = discover_output_from(std::iter::empty(), |k| {
            if k == "TORDA_OUTPUT" {
                Some("/var/log/ua/events.ndjson".to_string())
            } else {
                None
            }
        });
        assert_eq!(
            got,
            Some((
                PathBuf::from("/var/log/ua/events.ndjson"),
                DEFAULT_ROTATE_MB * 1024 * 1024
            ))
        );
    }

    #[test]
    fn discover_output_absent_is_none() {
        let got = discover_output_from(std::iter::empty(), |_| None);
        assert_eq!(
            got, None,
            "no --output/$TORDA_OUTPUT means no file sink requested"
        );
    }

    #[test]
    fn discover_output_rotate_mb_flag_and_env_parse() {
        let args = vec![
            "--output".to_string(),
            "/tmp/out.ndjson".to_string(),
            "--rotate-mb".to_string(),
            "10".to_string(),
        ];
        let got = discover_output_from(args.into_iter(), |_| None);
        assert_eq!(
            got,
            Some((PathBuf::from("/tmp/out.ndjson"), 10 * 1024 * 1024))
        );

        let got_env = discover_output_from(std::iter::empty(), |k| match k {
            "TORDA_OUTPUT" => Some("/tmp/out.ndjson".to_string()),
            "TORDA_ROTATE_MB" => Some("5".to_string()),
            _ => None,
        });
        assert_eq!(
            got_env,
            Some((PathBuf::from("/tmp/out.ndjson"), 5 * 1024 * 1024))
        );
    }

    #[test]
    fn discover_output_bad_rotate_mb_falls_back_to_default() {
        let args = vec![
            "--output".to_string(),
            "/tmp/out.ndjson".to_string(),
            "--rotate-mb".to_string(),
            "not-a-number".to_string(),
        ];
        let got = discover_output_from(args.into_iter(), |_| None);
        assert_eq!(
            got,
            Some((
                PathBuf::from("/tmp/out.ndjson"),
                DEFAULT_ROTATE_MB * 1024 * 1024
            )),
            "an unparsable --rotate-mb must degrade to the sane default, never panic"
        );
    }
}
