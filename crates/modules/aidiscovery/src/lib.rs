//! AI-discovery module. Reads the shared snapshot's listening sockets and reports
//! locally-running AI runtimes/servers (Ollama, LM Studio, llama.cpp, vLLM, …) as
//! an OCSF AI Inventory Info record — including whether each one is **exposed**
//! beyond loopback. Like every module it never touches the OS directly; it only
//! reads `snapshot.query("listeners")`.
//!
//! This is *discovery only* (open-source, in the agent). Turning these into
//! scored assets / posture findings — e.g. "an unauthenticated Ollama is exposed
//! on a crown-jewel host" — is the backend's job (the paid platform).
use async_trait::async_trait;
use serde_json::{json, Value};
use torda_core::{Module, ModuleCtx, ModuleHealth, ModuleId};
use torda_ocsf::{class, OcsfEnvelope};

#[derive(Default)]
pub struct AiDiscoveryModule {
    ctx: Option<ModuleCtx>,
}

impl AiDiscoveryModule {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Module for AiDiscoveryModule {
    fn id(&self) -> ModuleId {
        "aidiscovery".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self.ctx.as_ref().expect("init before start");
        let listeners = ctx.snapshot.query("listeners")?.0;
        let servers = detect_ai_servers(&listeners);
        // Nothing to report → stay silent (avoid empty-inventory spam).
        if servers.is_empty() {
            return Ok(());
        }
        let exposed = servers
            .iter()
            .filter(|s| s["exposed"] == json!(true))
            .count();
        let data = json!({
            "ai_servers": servers,
            "count": servers.len(),
            "exposed_count": exposed,
        });
        ctx.emitter.emit(OcsfEnvelope::new(
            class::AI_INVENTORY_INFO,
            "AI Inventory Info",
            ctx.meta(),
            ctx.snapshot.device(),
            data,
        ));
        Ok(())
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "ai discovery ready".to_string(),
        }
    }
}

/// Map a listener (process name and/or well-known port) to an AI runtime, if it
/// looks like one. Process-name match is primary; a few strongly-unique ports are
/// a fallback for tools that report no process name (e.g. Windows `netstat`).
fn match_runtime(process: Option<&str>, port: u16) -> Option<&'static str> {
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
        ];
        for (needle, name) in NAMES {
            if p.contains(needle) {
                return Some(name);
            }
        }
    }
    // Fallback: only ports unique enough to imply the runtime on their own.
    match port {
        11434 => Some("Ollama"),
        1234 => Some("LM Studio"),
        1337 => Some("Jan"),
        _ => None,
    }
}

/// True unless the address is loopback (so `0.0.0.0`, `::`, and any routable
/// address count as exposed).
fn is_exposed(addr: &str) -> bool {
    let a = addr.trim();
    !(a == "127.0.0.1"
        || a.starts_with("127.")
        || a == "::1"
        || a.eq_ignore_ascii_case("localhost"))
}

/// Pick out AI runtimes from the listener rows, as JSON server records.
fn detect_ai_servers(listeners: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    for l in listeners {
        let port = l["port"].as_u64().unwrap_or(0) as u16;
        let process = l["process"].as_str();
        let Some(runtime) = match_runtime(process, port) else {
            continue;
        };
        let addr = l["local_addr"].as_str().unwrap_or_default();
        out.push(json!({
            "runtime": runtime,
            "process": process,
            "pid": l["pid"].clone(),
            "proto": l["proto"].as_str().unwrap_or("tcp"),
            "bind_addr": addr,
            "port": port,
            "exposed": is_exposed(addr),
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(local_addr: &str, port: u16, process: Option<&str>) -> Value {
        json!({
            "proto": "tcp",
            "local_addr": local_addr,
            "port": port,
            "pid": 1234,
            "process": process,
        })
    }

    #[test]
    fn matches_by_process_name() {
        assert_eq!(match_runtime(Some("ollama"), 9999), Some("Ollama"));
        assert_eq!(match_runtime(Some("llama-server"), 8080), Some("llama.cpp"));
        assert_eq!(
            match_runtime(Some("lm-studio-helper"), 4321),
            Some("LM Studio")
        );
        assert_eq!(match_runtime(Some("sshd"), 22), None);
    }

    #[test]
    fn matches_by_unique_port_when_no_process() {
        // Windows netstat gives no process name — the port carries it.
        assert_eq!(match_runtime(None, 11434), Some("Ollama"));
        assert_eq!(match_runtime(None, 1234), Some("LM Studio"));
        // A generic port with no process name is not assumed to be AI.
        assert_eq!(match_runtime(None, 8080), None);
    }

    #[test]
    fn exposure_is_loopback_aware() {
        assert!(!is_exposed("127.0.0.1"));
        assert!(!is_exposed("::1"));
        assert!(is_exposed("0.0.0.0"));
        assert!(is_exposed("::"));
        assert!(is_exposed("192.168.1.10"));
    }

    #[test]
    fn detects_only_ai_listeners_with_exposure() {
        let rows = vec![
            listener("127.0.0.1", 11434, Some("ollama")), // AI, loopback
            listener("0.0.0.0", 8080, Some("llama-server")), // AI, exposed
            listener("0.0.0.0", 22, Some("sshd")),        // not AI
            listener("0.0.0.0", 1234, None),              // AI by port (Windows-style)
        ];
        let found = detect_ai_servers(&rows);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0]["runtime"], "Ollama");
        assert_eq!(found[0]["exposed"], json!(false));
        assert_eq!(found[1]["runtime"], "llama.cpp");
        assert_eq!(found[1]["exposed"], json!(true));
        assert_eq!(found[2]["runtime"], "LM Studio");
    }
}
