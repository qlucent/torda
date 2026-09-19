//! AI-runtime discovery for the shared snapshot.
//!
//! Classifies listening sockets into known AI runtimes (Ollama, LM Studio, …) and,
//! for those exposing a local API, probes them for version and loaded models. The
//! network probe lives HERE, in the substrate — the substrate is the only door to
//! the OS/network, so a module never opens a socket. The `aidiscovery` module just
//! reads the resulting `ai_runtimes` snapshot table and emits it.
//!
//! Probing is best-effort and short-timeout: a runtime that doesn't answer (or
//! isn't Ollama) simply has no `version`/`models`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::listeners::Listener;

const PROBE_TIMEOUT: Duration = Duration::from_millis(400);

/// A discovered AI runtime, enriched with version/models when it could be probed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AiRuntime {
    pub runtime: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub proto: String,
    pub bind_addr: String,
    pub port: u16,
    pub exposed: bool,
    pub version: Option<String>,
    pub models: Vec<String>,
}

/// Map a listener (process name and/or well-known port) to a known AI runtime.
/// Process-name match is primary; a few strongly-unique ports are a fallback for
/// tools that report no process name.
pub fn match_runtime(process: Option<&str>, port: u16) -> Option<&'static str> {
    if let Some(p) = process {
        let p = p.to_ascii_lowercase();
        const NAMES: &[(&str, &str)] = &[
            ("ollama", "Ollama"),
            ("lm-studio", "LM Studio"),
            ("lmstudio", "LM Studio"),
            ("llama-server", "llama.cpp"),
            ("llama.cpp", "llama.cpp"),
            ("llamacpp", "llama.cpp"),
            ("vllm", "vLLM"),
            ("text-generation", "Text Generation WebUI"),
            ("localai", "LocalAI"),
            ("local-ai", "LocalAI"),
            ("koboldcpp", "KoboldCpp"),
            ("kobold", "KoboldCpp"),
            ("gpt4all", "GPT4All"),
            ("tabby", "Tabby"),
            ("open-webui", "Open WebUI"),
            ("openwebui", "Open WebUI"),
            ("llamafile", "llamafile"),
            ("litellm", "LiteLLM"),
            ("sglang", "SGLang"),
            ("ramalama", "RamaLama"),
            ("jan", "Jan"),
        ];
        for (needle, name) in NAMES {
            if p.contains(needle) {
                return Some(name);
            }
        }
    }
    match port {
        11434 => Some("Ollama"),
        1234 => Some("LM Studio"),
        1337 => Some("Jan"),
        _ => None,
    }
}

/// True unless the address is loopback (so `0.0.0.0`, `::`, and any routable
/// address count as exposed).
pub fn is_exposed(addr: &str) -> bool {
    let a = addr.trim();
    !(a == "127.0.0.1"
        || a.starts_with("127.")
        || a == "::1"
        || a.eq_ignore_ascii_case("localhost"))
}

/// Classify listeners into AI runtimes (no probing) — the pure, testable core.
pub fn classify(listeners: &[Listener]) -> Vec<AiRuntime> {
    listeners
        .iter()
        .filter_map(|l| {
            let runtime = match_runtime(l.process.as_deref(), l.port)?;
            Some(AiRuntime {
                runtime: runtime.to_string(),
                process: l.process.clone(),
                pid: l.pid,
                proto: l.proto.clone(),
                bind_addr: l.local_addr.clone(),
                port: l.port,
                exposed: is_exposed(&l.local_addr),
                version: None,
                models: Vec::new(),
            })
        })
        .collect()
}

/// Classify listeners and probe each for details (best-effort network I/O).
pub fn discover_ai_runtimes(listeners: &[Listener]) -> Vec<AiRuntime> {
    let mut runtimes = classify(listeners);
    for r in &mut runtimes {
        // Ollama exposes a stable local HTTP API. Other runtimes: presence only
        // for now (their probes land in follow-ups).
        if r.runtime == "Ollama" {
            if let Some(body) = http_get_json(r.port, "/api/version") {
                r.version = parse_ollama_version(&body);
            }
            if let Some(body) = http_get_json(r.port, "/api/tags") {
                r.models = parse_ollama_tags(&body);
            }
        }
    }
    runtimes
}

/// Minimal HTTP/1.1 GET to a loopback port, returning the JSON body (from the
/// first `{` to the last `}`). No dependency — one short-lived, timed-out socket.
fn http_get_json(port: u16, path: &str) -> Option<String> {
    let sa = format!("127.0.0.1:{port}").parse().ok()?;
    let mut stream = TcpStream::connect_timeout(&sa, PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b)?;
    let start = body.find('{')?;
    let end = body.rfind('}')?;
    if end < start {
        return None;
    }
    Some(body[start..=end].to_string())
}

/// Extract the version string from an Ollama `/api/version` body.
pub fn parse_ollama_version(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v["version"].as_str().map(|s| s.to_string())
}

/// Extract model names from an Ollama `/api/tags` body.
pub fn parse_ollama_tags(body: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    v["models"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m["name"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(local_addr: &str, port: u16, process: Option<&str>) -> Listener {
        Listener {
            proto: "tcp".to_string(),
            local_addr: local_addr.to_string(),
            port,
            pid: Some(1),
            process: process.map(|s| s.to_string()),
        }
    }

    #[test]
    fn classify_matches_and_flags_exposure() {
        let ls = vec![
            listener("127.0.0.1", 11434, Some("ollama")),
            listener("0.0.0.0", 8080, Some("llama-server")),
            listener("0.0.0.0", 22, Some("sshd")),
            listener("0.0.0.0", 1234, None), // LM Studio by port
            listener("0.0.0.0", 4000, Some("litellm")), // newly catalogued runtime
        ];
        let r = classify(&ls);
        assert_eq!(r.len(), 4);
        assert_eq!(r[0].runtime, "Ollama");
        assert!(!r[0].exposed);
        assert!(r[0].models.is_empty()); // classify doesn't probe
        assert_eq!(r[1].runtime, "llama.cpp");
        assert!(r[1].exposed);
        assert_eq!(r[2].runtime, "LM Studio");
        assert_eq!(r[3].runtime, "LiteLLM");
    }

    #[test]
    fn parses_ollama_version_and_tags() {
        assert_eq!(
            parse_ollama_version(r#"{"version":"0.5.7"}"#).as_deref(),
            Some("0.5.7")
        );
        assert_eq!(parse_ollama_version(r#"{"nope":1}"#), None);

        let tags = r#"{"models":[{"name":"llama3:latest","size":1},{"name":"qwen2.5:7b"}]}"#;
        assert_eq!(parse_ollama_tags(tags), vec!["llama3:latest", "qwen2.5:7b"]);
        assert!(parse_ollama_tags(r#"{"models":[]}"#).is_empty());
        assert!(parse_ollama_tags("not json").is_empty());
    }
}
