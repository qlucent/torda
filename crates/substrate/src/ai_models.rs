//! AI model-file discovery for the shared snapshot (the "model integrity" signal).
//!
//! Walks known model directories, finds model weight files by extension, and
//! reports each with its format, a **code-execution risk flag** (pickle-based
//! formats — `.pt`/`.bin`/`.ckpt`/`.pkl` — run arbitrary code on load via
//! `torch.load`/`pickle`, unlike data-only `.gguf`/`.safetensors`/`.onnx`), size,
//! mtime, and a cheap change-detection **fingerprint**. The FS walk lives HERE, in
//! the substrate — the only door to the OS — so the `aimodel` module just reads the
//! resulting `ai_models` snapshot table and emits it.
//!
//! v1 is discovery + risky-format + drift (fingerprint = size + a sampled non-crypto
//! hash; it detects change, it is NOT a cryptographic attestation). Full SHA-256
//! attestation against a known-good digest is a follow-up (pairs with adding a hash
//! dep + real FIM hashing). The walk is bounded (dir set, depth, file count).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// One discovered AI model file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AiModel {
    pub path: String,
    /// Normalized format label (`gguf`, `safetensors`, `pytorch`, `pickle`, …).
    pub format: String,
    /// True for formats that execute code on load (pickle family) — the headline
    /// supply-chain risk of an untrusted model file.
    pub risky: bool,
    pub size: u64,
    /// Last-modified time, epoch seconds (0 if unavailable).
    pub mtime: u64,
    /// Cheap change-detection fingerprint (size + sampled content, non-crypto).
    /// Changes when the file changes; NOT a cryptographic hash. Empty if unreadable.
    pub fingerprint: String,
}

/// Bounds so a stray huge tree can't stall a snapshot.
const MAX_DEPTH: usize = 6;
const MAX_FILES: usize = 512;
const SAMPLE: usize = 64 * 1024; // head + tail bytes fed to the fingerprint

/// Classify a path's extension into a model format + code-execution risk. Returns
/// `None` for anything that isn't a recognized model file. Pickle-family formats
/// (`.pt`/`.pth`/`.bin`/`.ckpt`/`.pkl`) are `risky` — they can run arbitrary code
/// when deserialized; `.gguf`/`.safetensors`/`.onnx`/`.h5` are data-only.
pub fn classify_format(path: &str) -> Option<(&'static str, bool)> {
    let ext = path.rsplit('.').next()?.to_ascii_lowercase();
    match ext.as_str() {
        "gguf" => Some(("gguf", false)),
        "ggml" => Some(("ggml", false)),
        "safetensors" => Some(("safetensors", false)),
        "onnx" => Some(("onnx", false)),
        "h5" | "hdf5" => Some(("keras-h5", false)),
        "npz" => Some(("numpy-npz", false)),
        "pt" | "pth" => Some(("pytorch", true)),
        "bin" => Some(("pytorch-bin", true)),
        "ckpt" => Some(("checkpoint", true)),
        "pkl" | "pickle" => Some(("pickle", true)),
        _ => None,
    }
}

/// A non-cryptographic change-detection fingerprint: hash of (size, head bytes,
/// tail bytes). Cheap (reads at most 2·SAMPLE), stable across runs for an unchanged
/// file, and changes when the file changes. NOT collision-resistant — for drift,
/// not attestation.
fn fingerprint(path: &Path, size: u64) -> String {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return String::new(),
    };
    let mut h = DefaultHasher::new();
    size.hash(&mut h);
    let mut head = vec![0u8; SAMPLE.min(size as usize)];
    if f.read_exact(&mut head).is_ok() {
        head.hash(&mut h);
    }
    if size > SAMPLE as u64 {
        let tail_len = SAMPLE.min(size as usize);
        if f.seek(SeekFrom::End(-(tail_len as i64))).is_ok() {
            let mut tail = vec![0u8; tail_len];
            if f.read_exact(&mut tail).is_ok() {
                tail.hash(&mut h);
            }
        }
    }
    format!("{:016x}", h.finish())
}

/// Read one model file's metadata into an [`AiModel`] if it is a recognized format.
fn model_at(path: &Path) -> Option<AiModel> {
    let path_str = path.to_string_lossy();
    let (format, risky) = classify_format(&path_str)?;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let size = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Some(AiModel {
        path: path_str.to_string(),
        format: format.to_string(),
        risky,
        size,
        mtime,
        fingerprint: fingerprint(path, size),
    })
}

/// Recursively collect model files under `dir`, bounded by depth and the shared
/// `remaining` file budget. Best-effort: unreadable entries are skipped.
fn walk(dir: &Path, depth: usize, remaining: &mut usize, out: &mut Vec<AiModel>) {
    if depth > MAX_DEPTH || *remaining == 0 {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if *remaining == 0 {
            return;
        }
        let path = entry.path();
        // Don't follow symlinks (avoid cycles / escaping the model dir).
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            walk(&path, depth + 1, remaining, out);
        } else if ft.is_file() {
            if let Some(m) = model_at(&path) {
                out.push(m);
                *remaining -= 1;
            }
        }
    }
}

/// The default model directories to scan on this host: the well-known caches of
/// Ollama / Hugging Face / LM Studio / GPT4All / torch / whisper, common shared
/// locations, plus any dirs in `$TORDA_AI_MODEL_DIRS` (`;`-separated).
pub fn default_model_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    if let Some(home) = home {
        let home = PathBuf::from(home);
        for rel in [
            ".ollama/models",
            ".cache/huggingface/hub",
            ".cache/lm-studio/models",
            ".lmstudio/models",
            ".cache/gpt4all",
            ".cache/torch",
            ".cache/whisper",
            "Library/Application Support/nomic.ai/GPT4All", // macOS
        ] {
            dirs.push(home.join(rel));
        }
    }
    for abs in [
        "/usr/share/ollama/.ollama/models",
        "/opt/models",
        "/models",
        "/var/lib/ollama/models",
    ] {
        dirs.push(PathBuf::from(abs));
    }
    if let Some(extra) = std::env::var_os("TORDA_AI_MODEL_DIRS") {
        for d in std::env::split_paths(&extra) {
            if !d.as_os_str().is_empty() {
                dirs.push(d);
            }
        }
    }
    dirs
}

/// Provides the current model-file inventory. Isolated behind a trait (like the
/// package/file/listener providers) so OS access is testable and injectable.
pub trait AiModelProvider: Send + Sync {
    fn models(&self) -> Vec<AiModel>;
}

/// Real provider: walk [`default_model_dirs`], bounded by [`MAX_FILES`].
pub struct FsAiModelProvider;
impl AiModelProvider for FsAiModelProvider {
    fn models(&self) -> Vec<AiModel> {
        let mut out = Vec::new();
        let mut remaining = MAX_FILES;
        for dir in default_model_dirs() {
            if remaining == 0 {
                break;
            }
            walk(&dir, 0, &mut remaining, &mut out);
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        out
    }
}

/// Fallback / test fake: no models (also the default on unsupported hosts).
pub struct EmptyAiModelProvider;
impl AiModelProvider for EmptyAiModelProvider {
    fn models(&self) -> Vec<AiModel> {
        Vec::new()
    }
}

/// Fixed-fixture provider for tests.
pub struct StaticAiModelProvider(pub Vec<AiModel>);
impl AiModelProvider for StaticAiModelProvider {
    fn models(&self) -> Vec<AiModel> {
        self.0.clone()
    }
}

/// The default provider for a real host.
pub fn default_ai_model_provider() -> Box<dyn AiModelProvider> {
    Box::new(FsAiModelProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_marks_pickle_formats_risky_and_safe_formats_safe() {
        assert_eq!(classify_format("/m/llama.gguf"), Some(("gguf", false)));
        assert_eq!(
            classify_format("/m/model.safetensors"),
            Some(("safetensors", false))
        );
        assert_eq!(classify_format("/m/model.onnx"), Some(("onnx", false)));
        // Pickle family → risky (code exec on load).
        assert_eq!(classify_format("/m/model.pt"), Some(("pytorch", true)));
        assert_eq!(
            classify_format("/m/pytorch_model.bin"),
            Some(("pytorch-bin", true))
        );
        assert_eq!(classify_format("/m/sd.ckpt"), Some(("checkpoint", true)));
        assert_eq!(classify_format("/m/x.pkl"), Some(("pickle", true)));
        // Case-insensitive; non-models ignored.
        assert_eq!(
            classify_format("/m/Model.SafeTensors").map(|(f, _)| f),
            Some("safetensors")
        );
        assert_eq!(classify_format("/m/README.md"), None);
        assert_eq!(classify_format("/m/config.json"), None);
        assert_eq!(classify_format("/m/noext"), None);
    }

    #[test]
    fn empty_and_static_providers() {
        assert!(EmptyAiModelProvider.models().is_empty());
        let m = AiModel {
            path: "/m/a.gguf".into(),
            format: "gguf".into(),
            risky: false,
            size: 10,
            mtime: 1,
            fingerprint: "abc".into(),
        };
        assert_eq!(StaticAiModelProvider(vec![m.clone()]).models(), vec![m]);
    }

    #[test]
    fn fs_provider_finds_models_and_fingerprints_change() {
        // A temp "model dir" wired via TORDA_AI_MODEL_DIRS.
        let dir = std::env::temp_dir().join(format!("torda-aimodel-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let risky = dir.join("pytorch_model.bin");
        let safe = dir.join("model.safetensors");
        std::fs::write(&risky, b"pickle-payload").unwrap();
        std::fs::write(&safe, vec![0u8; 1000]).unwrap();
        std::fs::write(dir.join("notes.txt"), b"ignore me").unwrap();

        // Scope assertions to OUR temp dir — the host may have real model dirs too
        // (default_model_dirs also scans ~/.ollama etc.), so don't assert a total.
        let dir_str = dir.to_string_lossy().to_string();
        let ours = |ms: &[AiModel]| -> Vec<AiModel> {
            ms.iter()
                .filter(|m| m.path.starts_with(&dir_str))
                .cloned()
                .collect()
        };

        std::env::set_var("TORDA_AI_MODEL_DIRS", &dir);
        let mine = ours(&FsAiModelProvider.models());
        std::env::remove_var("TORDA_AI_MODEL_DIRS");

        let found: Vec<&str> = mine.iter().map(|m| m.format.as_str()).collect();
        assert!(found.contains(&"pytorch-bin"), "risky .bin discovered");
        assert!(found.contains(&"safetensors"), "safe model discovered");
        assert_eq!(
            mine.len(),
            2,
            "non-model files (notes.txt) ignored in our dir"
        );
        let bin = mine.iter().find(|m| m.format == "pytorch-bin").unwrap();
        assert!(bin.risky);
        let fp1 = bin.fingerprint.clone();
        assert!(!fp1.is_empty());

        // Change the file → fingerprint changes (drift detection).
        std::fs::write(&risky, b"pickle-payload-TAMPERED").unwrap();
        std::env::set_var("TORDA_AI_MODEL_DIRS", &dir);
        let after = ours(&FsAiModelProvider.models());
        std::env::remove_var("TORDA_AI_MODEL_DIRS");
        let bin2 = after.iter().find(|m| m.format == "pytorch-bin").unwrap();
        assert_ne!(bin2.fingerprint, fp1, "fingerprint changes on tamper");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
