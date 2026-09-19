//! AI-usage module — endpoint visibility into AI **developer tools** (CLI + IDE
//! assistants) and where they connect.
//!
//! This is the agent-side, open-source half of the "AI egress / CLI-IDE tool
//! visibility" wedge: the market's structural blind spot is that AI coding tools
//! (Cursor, Claude Code, aider, GitHub Copilot, Codeium, …) talk to model APIs
//! straight off a developer's box, invisible to a network DLP proxy. Torda already
//! sees every process and every connection at the kernel; this module joins the
//! two by process identity — when a *known AI tool* makes a connection, it emits
//! an OCSF AI Inventory Info (`9004`) record with the connection's **scope**:
//!
//! - `external` (public dest) → `kind: "ai_tool_egress"` — the shadow-AI-egress
//!   concern: code/context leaving the box to a cloud model API.
//! - `loopback` (`127.0.0.0/8`, `::1`) → `kind: "ai_tool_local"`, `scope: "loopback"`
//!   — the tool is using a model runtime ON this host (e.g. a local Ollama). This
//!   is the *opposite* risk profile: data stays on the box. The backend can join it
//!   with `aidiscovery`'s discovered runtimes (by port) to name the local model.
//! - `private` (RFC1918/link-local/ULA) → `kind: "ai_tool_local"`, `scope: "private"`
//!   — an intra-network AI service (e.g. a self-hosted gateway).
//!
//! Capturing local connections (not just egress) lets the backend show
//! **cloud-vs-local AI usage per host/tool** — local is often the sanctioned,
//! privacy-preserving path, so it is a signal, not noise.
//!
//! **Discovery only (open-source, in the agent).** It reports *that* an AI tool
//! connected and the scope — it never inspects payloads or TLS content (that's the
//! research bet, not this slice). Deciding whether use is *sanctioned* — per host,
//! per owner, against a tenant allowlist — is the backend's job (the paid platform).
//! Discovery is open; the decision is paid.
//!
//! It CONSUMES the shared `NetConnect` bus (the substrate is the only door — it
//! opens no probes of its own) and reuses `torda-mod-netmon`'s single canonical
//! definition of "external" so "off-box" means exactly one thing agent-wide.
//!
//! Limitation (documented, v1): detection is by the connecting process's image
//! basename, so a tool that runs *inside* a generic interpreter (an aider or a
//! Copilot LSP launched as `node`/`python3`) is not attributed here. Command-line
//! / parent-chain attribution is a follow-up; the connect event carries only the
//! kernel `comm`/image today.
use async_trait::async_trait;
use std::net::IpAddr;
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
/// `\` (Windows) separators, with a trailing `.exe` stripped (Windows images are
/// `claude.exe`, not `claude`). A bare name (already a basename, or a kernel
/// `comm`) is returned unchanged apart from the extension.
fn basename(image: &str) -> &str {
    let name = image.rsplit(['/', '\\']).next().unwrap_or(image);
    // Case-insensitive strip of a single trailing `.exe`.
    if name.len() > 4 && name[name.len() - 4..].eq_ignore_ascii_case(".exe") {
        &name[..name.len() - 4]
    } else {
        name
    }
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

/// Classify a connection destination's scope for AI-usage reporting, reusing
/// `netmon`'s single definition of "external". Returns `None` for an address we
/// can't parse (we never guess a scope from an unparseable string). Loopback is
/// checked FIRST so `127.0.0.1`/`::1` never fall through to `private`.
fn classify_scope(daddr: &str) -> Option<&'static str> {
    let ip: IpAddr = daddr.parse().ok()?;
    if ip.is_loopback() {
        return Some("loopback");
    }
    if torda_mod_netmon::is_external(daddr) {
        return Some("external");
    }
    // RFC1918 / link-local / ULA / unspecified — reachable, but not off-box.
    Some("private")
}

/// AI-usage module: subscribes to `NetConnect` and emits one `9004` record per
/// connection a known AI developer tool makes, tagged with the connection scope
/// (external egress vs local/loopback runtime use).
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
/// connecting process is a catalogued AI tool, emit its `9004` record tagged with
/// the connection scope. Dropped only when:
///
/// - non-`NetConnect` kind (the stub bus forwards all kinds) → drop,
/// - malformed event (missing/unparseable required field) → drop (never a panic),
/// - process not an AI tool → drop (this is not a generic net sensor; netmon is),
/// - destination address doesn't parse → drop (we can't classify its scope).
///
/// Emits BOTH off-box egress (`kind: "ai_tool_egress"`, scope `external`) and
/// local/loopback/private connections (`kind: "ai_tool_local"`) — the latter is the
/// "which tools use a LOCAL model runtime" signal, not noise.
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
    // Classify the destination scope (one definition of "external", shared with
    // netmon). An unparseable address can't be classified → drop.
    let scope = match classify_scope(daddr) {
        Some(s) => s,
        None => return,
    };
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

    // `ai_tool_egress` stays the kind for off-box egress (unchanged contract);
    // local/private connections get `ai_tool_local`. `scope` is on both so the
    // backend keys cloud-vs-local off one field.
    let kind = if scope == "external" {
        "ai_tool_egress"
    } else {
        "ai_tool_local"
    };

    // Informational by design: emitting is telemetry/discovery. Whether the usage
    // is sanctioned is a policy decision the backend makes.
    emitter.emit(OcsfEnvelope::new(
        class::AI_INVENTORY_INFO,
        "AI Inventory Info",
        meta.clone(),
        device.clone(),
        serde_json::json!({
            "kind": kind,
            "scope": scope,
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
    fn matches_windows_separators_and_exe_suffix() {
        // Real path observed live: this Claude Code session's own binary.
        assert_eq!(
            match_tool(
                r"C:\Users\pkkar\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe"
            ),
            Some("claude-code"),
        );
        assert_eq!(
            match_tool(r"C:\Users\dev\AppData\Local\Programs\cursor\cursor.exe"),
            Some("cursor"),
        );
        assert_eq!(match_tool(r"C:\tools\aider"), Some("aider"));
        // `.exe` strip is a single trailing extension, not a substring match.
        assert_eq!(match_tool("cursor.exe.bak"), None);
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
        assert_eq!(d["scope"], "external");
        assert_eq!(d["tool"], "cursor");
        assert_eq!(d["process"]["pid"], 4242);
        assert_eq!(d["connection"]["daddr"], "203.0.113.10");
        assert_eq!(d["connection"]["dport"], 443);
    }

    #[test]
    fn emits_for_ai_tool_ipv6_egress() {
        // The exact live scenario: this session's `claude.exe` → the Anthropic API
        // over IPv6. v1 missed this on BOTH counts (.exe suffix + IPv6 external);
        // this pins the fix.
        let em = CapturingEmitter::default();
        handle_event(
            &connect(serde_json::json!({
                "pid": 18536,
                "image": r"C:\Users\pkkar\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe",
                "daddr": "2607:6bc0::10", "dport": 443, "proto": "tcp"
            })),
            &meta(),
            &device(),
            &em,
        );
        let out = em.emitted.lock().unwrap();
        assert_eq!(out.len(), 1, "claude.exe egress over IPv6 must be reported");
        assert_eq!(out[0].data["tool"], "claude-code");
        assert_eq!(out[0].data["scope"], "external");
        assert_eq!(out[0].data["connection"]["daddr"], "2607:6bc0::10");
    }

    #[test]
    fn emits_ai_tool_local_for_loopback_runtime() {
        // Editor → loopback Ollama (:11434) is LOCAL use — now a first-class signal
        // (`ai_tool_local`), not a drop. This is what the backend joins with
        // aidiscovery to say "cursor is backed by a local model runtime".
        for lo in ["127.0.0.1", "::1"] {
            let em = CapturingEmitter::default();
            handle_event(
                &connect(serde_json::json!({
                    "pid": 1, "image": "cursor", "daddr": lo, "dport": 11434, "proto": "tcp"
                })),
                &meta(),
                &device(),
                &em,
            );
            let out = em.emitted.lock().unwrap();
            assert_eq!(out.len(), 1, "{lo}: loopback AI-tool use must emit");
            assert_eq!(out[0].data["kind"], "ai_tool_local");
            assert_eq!(out[0].data["scope"], "loopback", "{lo}");
            assert_eq!(out[0].data["tool"], "cursor");
            assert_eq!(out[0].data["connection"]["dport"], 11434);
        }
    }

    #[test]
    fn emits_ai_tool_local_with_private_scope() {
        // RFC1918 / link-local / ULA → an intra-network AI service: `ai_tool_local`
        // scope `private` (reachable, but not off-box egress).
        for priv_addr in [
            "10.0.0.5",
            "192.168.1.9",
            "169.254.1.1",
            "fe80::1",
            "fd00::1234",
        ] {
            let em = CapturingEmitter::default();
            handle_event(
                &connect(serde_json::json!({
                    "pid": 1, "image": "aider", "daddr": priv_addr, "dport": 8080, "proto": "tcp"
                })),
                &meta(),
                &device(),
                &em,
            );
            let out = em.emitted.lock().unwrap();
            assert_eq!(out.len(), 1, "{priv_addr}: private AI-tool use must emit");
            assert_eq!(out[0].data["kind"], "ai_tool_local");
            assert_eq!(out[0].data["scope"], "private", "{priv_addr}");
        }
    }

    #[test]
    fn skips_unparseable_destination() {
        // We never guess a scope from an address we can't parse → drop, no panic.
        let em = CapturingEmitter::default();
        handle_event(
            &connect(serde_json::json!({
                "pid": 1, "image": "cursor", "daddr": "not-an-ip", "dport": 443
            })),
            &meta(),
            &device(),
            &em,
        );
        assert!(em.emitted.lock().unwrap().is_empty());
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
