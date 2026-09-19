//! AI-usage module — endpoint visibility into AI **developer tools** (CLI + IDE
//! assistants) and their outbound network egress.
//!
//! This is the agent-side, open-source half of the "AI egress / CLI-IDE tool
//! visibility" wedge: the market's structural blind spot is that AI coding tools
//! (Cursor, Claude Code, aider, GitHub Copilot, Codeium, …) talk to model APIs
//! straight off a developer's box, invisible to a network DLP proxy. Torda already
//! sees every process and every connection at the kernel; this module joins the
//! two by process identity — when a *known AI tool* makes an *off-box* connection,
//! it emits an OCSF AI Inventory Info (`9004`) record of kind `ai_tool_egress`.
//!
//! **Discovery only (open-source, in the agent).** It reports *that* an AI tool
//! egressed — it never inspects payloads or TLS content (that's the research bet,
//! not this slice). Deciding whether that egress is *sanctioned* — per host, per
//! owner, against a tenant allowlist — is the backend's job (the paid platform).
//! Discovery is open; the decision is paid.
//!
//! It CONSUMES the shared `NetConnect` bus (the substrate is the only door — it
//! opens no probes of its own) and reuses `torda-mod-netmon`'s single canonical
//! definition of "external" so "off-box egress" means exactly one thing agent-wide.
//!
//! Limitation (documented, v1): detection is by the connecting process's image
//! basename, so a tool that runs *inside* a generic interpreter (an aider or a
//! Copilot LSP launched as `node`/`python3`) is not attributed here. Command-line
//! / parent-chain attribution is a follow-up; the connect event carries only the
//! kernel `comm`/image today.
use async_trait::async_trait;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use torda_core::{EventKind, Module, ModuleCtx, ModuleHealth, ModuleId, SubstrateEvent};
use torda_ocsf::{class, Device, Metadata, OcsfEnvelope};

/// Catalog of AI developer-tool process images → the canonical tool name we
/// report. Matched case-insensitively against the connecting process's image
/// **basename** (see [`match_tool`]). Kept deliberately specific to avoid false
/// positives; it is data, not logic — extend it as the tool landscape moves. The
/// second field is the on-disk/`comm` binary name (or a family prefix); the first
/// is the stable name the backend keys its allowlist on.
const CATALOG: &[(&str, &str)] = &[
    ("cursor", "cursor"),
    ("claude-code", "claude"),
    ("aider", "aider"),
    ("ollama", "ollama"),
    ("github-copilot", "github-copilot-language-server"),
    ("copilot", "copilot"),
    ("cody", "cody"),
    ("codeium", "codeium"),
    ("codeium", "codeium_language_server"),
    ("tabnine", "tabnine"),
    ("windsurf", "windsurf"),
    ("cline", "cline"),
    ("shell-gpt", "sgpt"),
    ("chatgpt", "chatgpt"),
];

/// The last path component of a process image, tolerating both `/` (Linux) and
/// `\` (Windows) separators. A bare name (already a basename, or a kernel `comm`)
/// is returned unchanged.
fn basename(image: &str) -> &str {
    image.rsplit(['/', '\\']).next().unwrap_or(image)
}

/// Classify a connecting process's image against the AI-tool [`CATALOG`],
/// returning the canonical tool name on a match. Case-insensitive on the
/// basename, and **truncation-aware**: the kernel stamps `comm` into a 16-byte
/// buffer (15 usable chars), so a long tool binary (e.g.
/// `github-copilot-language-server`) arrives clipped to 15 chars — a basename of
/// exactly 15 chars is matched as a prefix of a longer catalog entry.
pub fn match_tool(image: &str) -> Option<&'static str> {
    let b = basename(image);
    if b.is_empty() {
        return None;
    }
    for (canonical, needle) in CATALOG {
        if b.eq_ignore_ascii_case(needle) {
            return Some(canonical);
        }
        // Kernel `comm` truncated to 15 chars → match as a prefix of a longer name.
        if b.len() == 15
            && needle.len() > 15
            && needle.as_bytes()[..15].eq_ignore_ascii_case(b.as_bytes())
        {
            return Some(canonical);
        }
    }
    None
}

/// AI-usage module: subscribes to `NetConnect` and emits one `ai_tool_egress`
/// record whenever a known AI developer tool connects off-box.
#[derive(Default)]
pub struct AiUsageModule {
    ctx: Option<ModuleCtx>,
    /// Signals the background task to stop; `true` == please exit.
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    /// Handle to the bus-reading task, awaited (bounded) on `stop`.
    task: Option<tokio::task::JoinHandle<()>>,
}

impl AiUsageModule {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Extract the connection fields from a `NetConnect` event and, IFF the
/// connecting process is a catalogued AI tool making an EXTERNAL (off-box)
/// connection, emit its `ai_tool_egress` record. Everything else is dropped:
///
/// - non-`NetConnect` kind (the stub bus forwards all kinds) → drop,
/// - malformed event (missing/unparseable required field) → drop (never a panic),
/// - process not an AI tool → drop (this is not a generic net sensor; netmon is),
/// - destination not external (loopback/RFC1918/link-local, e.g. a local Ollama)
///   → drop: local use is not off-box egress, which is the whole concern here.
fn handle_event(
    ev: &SubstrateEvent,
    meta: &Metadata,
    device: &Device,
    emitter: &dyn torda_core::OcsfEmitter,
) {
    if ev.kind != EventKind::NetConnect {
        return;
    }
    let image = match ev.fields.get("image").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };
    let tool = match match_tool(image) {
        Some(t) => t,
        None => return,
    };
    let daddr = match ev.fields.get("daddr").and_then(serde_json::Value::as_str) {
        Some(s) => s,
        None => return,
    };
    // Off-box only: a known AI tool talking to a LOCAL runtime (e.g. an editor to
    // a loopback Ollama) is not the egress concern. One definition of "external",
    // shared with netmon.
    if !torda_mod_netmon::is_external(daddr) {
        return;
    }
    let dport: u16 = match ev
        .fields
        .get("dport")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| p.try_into().ok())
    {
        Some(p) => p,
        None => return,
    };
    let pid = match ev.fields.get("pid").and_then(serde_json::Value::as_u64) {
        Some(p) => p,
        None => return,
    };
    let proto = ev
        .fields
        .get("proto")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("tcp");

    // Informational by design: emitting is telemetry/discovery. Whether this
    // egress is unsanctioned is a policy decision the backend makes.
    emitter.emit(OcsfEnvelope::new(
        class::AI_INVENTORY_INFO,
        "AI Inventory Info",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "kind": "ai_tool_egress",
            "tool": tool,
            "process": { "pid": pid, "image": image },
            "connection": { "daddr": daddr, "dport": dport, "proto": proto },
        }),
    ));
}

#[async_trait]
impl Module for AiUsageModule {
    fn id(&self) -> ModuleId {
        "aiusage".to_string()
    }

    async fn init(&mut self, ctx: ModuleCtx) -> anyhow::Result<()> {
        self.ctx = Some(ctx);
        Ok(())
    }

    async fn start(&mut self) -> anyhow::Result<()> {
        let ctx = self
            .ctx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("aiusage: init before start"))?;

        let mut rx = ctx.bus.subscribe(&[EventKind::NetConnect]);
        let meta = ctx.meta();
        let device = ctx.snapshot.device();
        let emitter = ctx.emitter.clone();

        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = stop_rx.changed() => {
                        if *stop_rx.borrow() {
                            break;
                        }
                    }
                    r = rx.recv() => match r {
                        Ok(ev) => handle_event(&ev, &meta, &device, emitter.as_ref()),
                        Err(RecvError::Lagged(_)) => continue, // dropped events; keep reading
                        Err(RecvError::Closed) => break,        // bus gone; exit
                    },
                }
            }
        });

        self.stop_tx = Some(stop_tx);
        self.task = Some(task);
        Ok(())
    }

    async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
        Ok(())
    }

    fn health(&self) -> ModuleHealth {
        ModuleHealth {
            ok: self.ctx.is_some(),
            detail: "ai usage monitor ready".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use torda_core::{EventBus, OcsfEmitter};
    use torda_substrate::StubBus;

    // ---- pure catalog/classification tests (no bus) ----

    #[test]
    fn matches_exact_basename_case_insensitively() {
        assert_eq!(match_tool("cursor"), Some("cursor"));
        assert_eq!(match_tool("/usr/local/bin/cursor"), Some("cursor"));
        assert_eq!(match_tool("Ollama"), Some("ollama"));
        assert_eq!(match_tool("aider"), Some("aider"));
        assert_eq!(match_tool("claude"), Some("claude-code"));
    }

    #[test]
    fn matches_windows_separators() {
        assert_eq!(
            match_tool(r"C:\Users\dev\AppData\Local\Programs\cursor\cursor.exe"),
            None,
            "cursor.exe != cursor — exact basename only (no extension stripping in v1)"
        );
        assert_eq!(match_tool(r"C:\tools\aider"), Some("aider"));
    }

    #[test]
    fn matches_truncated_kernel_comm() {
        // `github-copilot-language-server` clipped by the 16-byte comm buffer.
        assert_eq!(match_tool("github-copilot-"), Some("github-copilot"));
        // `codeium_language_server` → 15-char clip.
        assert_eq!(match_tool("codeium_languag"), Some("codeium"));
        // A 15-char string that is NOT a prefix of any long entry does not match.
        assert_eq!(match_tool("some_other_proc"), None);
    }

    #[test]
    fn does_not_match_unrelated_processes() {
        for p in ["bash", "node", "python3", "curl", "sshd", "systemd", ""] {
            assert_eq!(match_tool(p), None, "{p} must not be an AI tool");
        }
    }

    // ---- end-to-end bus tests ----

    #[derive(Default)]
    struct CapturingEmitter {
        emitted: Mutex<Vec<OcsfEnvelope>>,
    }
    impl OcsfEmitter for CapturingEmitter {
        fn emit(&self, rec: OcsfEnvelope) {
            self.emitted.lock().unwrap().push(rec);
        }
    }

    fn meta() -> Metadata {
        Metadata {
            product: "torda".into(),
            version: "0".into(),
            tenant_id: "t".into(),
        }
    }
    fn device() -> Device {
        Device {
            hostname: "h".into(),
            os: "linux".into(),
            os_version: "6.8".into(),
        }
    }

    fn connect(fields: serde_json::Value) -> SubstrateEvent {
        SubstrateEvent {
            kind: EventKind::NetConnect,
            ts: 0,
            fields,
        }
    }

    #[test]
    fn emits_for_ai_tool_external_egress() {
        let em = CapturingEmitter::default();
        handle_event(
            &connect(serde_json::json!({
                "pid": 4242, "image": "/usr/local/bin/cursor",
                "daddr": "203.0.113.10", "dport": 443, "proto": "tcp"
            })),
            &meta(),
            &device(),
            &em,
        );
        let out = em.emitted.lock().unwrap();
        assert_eq!(out.len(), 1);
        let d = &out[0].data;
        assert_eq!(out[0].class_uid, class::AI_INVENTORY_INFO);
        assert_eq!(
            out[0].severity_id, 1,
            "telemetry — decision is the backend's"
        );
        assert_eq!(d["kind"], "ai_tool_egress");
        assert_eq!(d["tool"], "cursor");
        assert_eq!(d["process"]["pid"], 4242);
        assert_eq!(d["connection"]["daddr"], "203.0.113.10");
        assert_eq!(d["connection"]["dport"], 443);
    }

    #[test]
    fn skips_ai_tool_to_local_runtime() {
        // Editor → loopback Ollama is local use, NOT off-box egress.
        let em = CapturingEmitter::default();
        for local in ["127.0.0.1", "10.0.0.5", "192.168.1.9", "169.254.1.1"] {
            handle_event(
                &connect(serde_json::json!({
                    "pid": 1, "image": "cursor", "daddr": local, "dport": 11434, "proto": "tcp"
                })),
                &meta(),
                &device(),
                &em,
            );
        }
        assert!(
            em.emitted.lock().unwrap().is_empty(),
            "local egress must not emit"
        );
    }

    #[test]
    fn skips_non_ai_process_external_egress() {
        // A normal browser egressing is netmon's business, not ours.
        let em = CapturingEmitter::default();
        handle_event(
            &connect(serde_json::json!({
                "pid": 2, "image": "firefox", "daddr": "203.0.113.10", "dport": 443
            })),
            &meta(),
            &device(),
            &em,
        );
        assert!(em.emitted.lock().unwrap().is_empty());
    }

    #[test]
    fn skips_malformed_and_wrong_kind() {
        let em = CapturingEmitter::default();
        // Missing daddr.
        handle_event(
            &connect(serde_json::json!({ "pid": 1, "image": "cursor", "dport": 443 })),
            &meta(),
            &device(),
            &em,
        );
        // Wrong kind, otherwise valid.
        handle_event(
            &SubstrateEvent {
                kind: EventKind::ProcessExec,
                ts: 0,
                fields: serde_json::json!({
                    "pid": 1, "image": "cursor", "daddr": "203.0.113.10", "dport": 443
                }),
            },
            &meta(),
            &device(),
            &em,
        );
        assert!(em.emitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn end_to_end_over_stub_bus() {
        let bus = StubBus::new(); // already an Arc<StubBus>
        let mut rx_ready = bus.subscribe(&[EventKind::NetConnect]);
        let em = Arc::new(CapturingEmitter::default());

        let meta = meta();
        let device = device();
        let emitter = em.clone();
        let task = tokio::spawn(async move {
            // Read exactly the two published events, then return.
            for _ in 0..2 {
                if let Ok(ev) = rx_ready.recv().await {
                    handle_event(&ev, &meta, &device, emitter.as_ref());
                }
            }
        });

        bus.publish(connect(serde_json::json!({
            "pid": 10, "image": "aider", "daddr": "198.51.100.7", "dport": 443, "proto": "tcp"
        })));
        bus.publish(connect(serde_json::json!({
            "pid": 11, "image": "sshd", "daddr": "198.51.100.7", "dport": 22, "proto": "tcp"
        })));

        task.await.unwrap();
        let out = em.emitted.lock().unwrap();
        assert_eq!(out.len(), 1, "only the AI tool's egress is reported");
        assert_eq!(out[0].data["tool"], "aider");
    }
}
