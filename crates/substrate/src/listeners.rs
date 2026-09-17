//! Listening-socket inventory for the shared snapshot.
//!
//! A point-in-time list of TCP listeners on the host — enough to discover
//! locally-running network services (the AI-discovery module uses it to find
//! local LLM servers and whether they are exposed beyond loopback). Like the
//! package providers, each OS backend shells out to a standard tool and a **pure**
//! parser turns its output into [`Listener`]s, so the parsing is fully testable
//! without the tool present:
//! - Linux:   `ss -tlnp`
//! - Windows: `netstat -ano -p TCP`
//! - macOS:   `lsof -nP -iTCP -sTCP:LISTEN`
//!
//! Modules never run these themselves — they read `snapshot.query("listeners")`.

use std::collections::HashMap;

/// One listening TCP socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub proto: String,
    /// The bound local address (e.g. `127.0.0.1`, `0.0.0.0`, `::`).
    pub local_addr: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

/// Supplies the host's current listening sockets.
pub trait ListenerProvider: Send + Sync {
    fn listeners(&self) -> Vec<Listener>;
}

/// No listeners — the stub for tests and unsupported platforms.
pub struct EmptyListenerProvider;
impl ListenerProvider for EmptyListenerProvider {
    fn listeners(&self) -> Vec<Listener> {
        Vec::new()
    }
}

/// Parse `addr:port` into `(addr, port)`, normalizing the wildcard `*`/`::` and
/// stripping IPv6 brackets. Returns `None` if there is no valid port.
pub fn parse_addr_port(s: &str) -> Option<(String, u16)> {
    let (addr, port) = if let Some(rest) = s.strip_prefix('[') {
        // Bracketed IPv6: `[::]:8080` / `[::1]:11434`.
        let (a, p) = rest.split_once("]:")?;
        (a.to_string(), p)
    } else {
        let (a, p) = s.rsplit_once(':')?;
        (a.to_string(), p)
    };
    let port: u16 = port.trim().parse().ok()?;
    // `*` (netstat/ss wildcard) means "all IPv4"; keep `::`/`0.0.0.0` as-is.
    let addr = if addr == "*" {
        "0.0.0.0".to_string()
    } else {
        addr
    };
    Some((addr, port))
}

/// Parse Linux `ss -tlnp` output.
pub fn parse_ss(out: &str) -> Vec<Listener> {
    let mut listeners = Vec::new();
    for line in out.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Columns: State Recv-Q Send-Q Local:Port Peer:Port [Process...]
        if fields.first() != Some(&"LISTEN") || fields.len() < 4 {
            continue;
        }
        let Some((local_addr, port)) = parse_addr_port(fields[3]) else {
            continue;
        };
        let (pid, process) = parse_ss_process(&fields[4..].join(" "));
        listeners.push(Listener {
            proto: "tcp".to_string(),
            local_addr,
            port,
            pid,
            process,
        });
    }
    listeners
}

/// Extract `(pid, name)` from an `ss` process column like
/// `users:(("ollama",pid=1234,fd=3))`.
fn parse_ss_process(s: &str) -> (Option<u32>, Option<String>) {
    let name = s
        .split_once("((\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(n, _)| n.to_string());
    let pid = s.split_once("pid=").and_then(|(_, rest)| {
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse::<u32>().ok()
    });
    (pid, name)
}

/// Parse Windows `netstat -ano -p TCP` output. netstat gives the PID but not the
/// process name (that would need a second `tasklist` call).
pub fn parse_netstat(out: &str) -> Vec<Listener> {
    let mut listeners = Vec::new();
    for line in out.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Columns: Proto Local Foreign State PID
        if fields.len() < 5 || !fields[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        if !fields.iter().any(|f| f.eq_ignore_ascii_case("LISTENING")) {
            continue;
        }
        let Some((local_addr, port)) = parse_addr_port(fields[1]) else {
            continue;
        };
        let pid = fields.last().and_then(|p| p.parse::<u32>().ok());
        listeners.push(Listener {
            proto: "tcp".to_string(),
            local_addr,
            port,
            pid,
            process: None,
        });
    }
    listeners
}

/// Parse macOS `lsof -nP -iTCP -sTCP:LISTEN` output.
pub fn parse_lsof(out: &str) -> Vec<Listener> {
    let mut listeners = Vec::new();
    for line in out.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Only listening rows; NAME holds the address just before "(LISTEN)".
        let Some(listen_idx) = fields.iter().position(|f| *f == "(LISTEN)") else {
            continue;
        };
        if listen_idx == 0 {
            continue;
        }
        let Some((local_addr, port)) = parse_addr_port(fields[listen_idx - 1]) else {
            continue;
        };
        let process = fields.first().map(|s| s.to_string());
        let pid = fields.get(1).and_then(|p| p.parse::<u32>().ok());
        listeners.push(Listener {
            proto: "tcp".to_string(),
            local_addr,
            port,
            pid,
            process,
        });
    }
    listeners
}

#[cfg(target_os = "linux")]
pub struct SsProvider;
#[cfg(target_os = "linux")]
impl ListenerProvider for SsProvider {
    fn listeners(&self) -> Vec<Listener> {
        std::process::Command::new("ss")
            .args(["-tlnp"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| parse_ss(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }
}

/// Parse `tasklist /fo csv /nh` into a PID→image-name map. Windows `netstat` only
/// reports the PID; this resolves it to a process name so AI runtimes can be
/// matched by name (not just a well-known port). Fields are quoted CSV; we need
/// only the first two (`"ImageName","PID",…`), and `.exe` is stripped.
pub fn parse_tasklist(out: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in out.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split("\",\"").collect();
        if parts.len() < 2 {
            continue;
        }
        let name = parts[0].trim_start_matches('"');
        let name = name
            .strip_suffix(".exe")
            .or_else(|| name.strip_suffix(".EXE"))
            .unwrap_or(name);
        if let Ok(pid) = parts[1].parse::<u32>() {
            map.insert(pid, name.to_string());
        }
    }
    map
}

#[cfg(target_os = "windows")]
pub struct NetstatProvider;
#[cfg(target_os = "windows")]
impl ListenerProvider for NetstatProvider {
    fn listeners(&self) -> Vec<Listener> {
        let mut listeners = std::process::Command::new("netstat")
            .args(["-ano", "-p", "TCP"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| parse_netstat(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
        // Best-effort PID→name resolution; if tasklist fails, PIDs stand alone.
        let names = std::process::Command::new("tasklist")
            .args(["/fo", "csv", "/nh"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| parse_tasklist(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
        for l in &mut listeners {
            if let Some(pid) = l.pid {
                if let Some(name) = names.get(&pid) {
                    l.process = Some(name.clone());
                }
            }
        }
        listeners
    }
}

#[cfg(target_os = "macos")]
pub struct LsofProvider;
#[cfg(target_os = "macos")]
impl ListenerProvider for LsofProvider {
    fn listeners(&self) -> Vec<Listener> {
        std::process::Command::new("lsof")
            .args(["-nP", "-iTCP", "-sTCP:LISTEN"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| parse_lsof(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    }
}

/// Selects the listener backend for the host OS.
#[cfg(target_os = "linux")]
pub fn default_listener_provider() -> Box<dyn ListenerProvider> {
    Box::new(SsProvider)
}
#[cfg(target_os = "windows")]
pub fn default_listener_provider() -> Box<dyn ListenerProvider> {
    Box::new(NetstatProvider)
}
#[cfg(target_os = "macos")]
pub fn default_listener_provider() -> Box<dyn ListenerProvider> {
    Box::new(LsofProvider)
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn default_listener_provider() -> Box<dyn ListenerProvider> {
    Box::new(EmptyListenerProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_port_forms() {
        assert_eq!(
            parse_addr_port("127.0.0.1:11434"),
            Some(("127.0.0.1".into(), 11434))
        );
        assert_eq!(parse_addr_port("0.0.0.0:22"), Some(("0.0.0.0".into(), 22)));
        assert_eq!(parse_addr_port("*:8080"), Some(("0.0.0.0".into(), 8080)));
        assert_eq!(parse_addr_port("[::]:8080"), Some(("::".into(), 8080)));
        assert_eq!(parse_addr_port("[::1]:11434"), Some(("::1".into(), 11434)));
        assert_eq!(parse_addr_port("nonsense"), None);
    }

    #[test]
    fn ss_parses_listeners_and_process() {
        let out = "\
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      4096   127.0.0.1:11434    0.0.0.0:*         users:((\"ollama\",pid=1234,fd=3))
LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:((\"sshd\",pid=567,fd=3))
LISTEN 0      4096   *:8080             *:*               users:((\"llama-server\",pid=999,fd=6))
";
        let l = parse_ss(out);
        assert_eq!(l.len(), 3);
        assert_eq!(l[0].local_addr, "127.0.0.1");
        assert_eq!(l[0].port, 11434);
        assert_eq!(l[0].pid, Some(1234));
        assert_eq!(l[0].process.as_deref(), Some("ollama"));
        assert_eq!(l[2].local_addr, "0.0.0.0"); // `*` normalized
        assert_eq!(l[2].process.as_deref(), Some("llama-server"));
    }

    #[test]
    fn netstat_parses_listening_tcp() {
        let out = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:11434        0.0.0.0:0              LISTENING       1234
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    [::]:8080              [::]:0                 LISTENING       999
  TCP    10.0.0.5:52000         93.184.216.34:443     ESTABLISHED     8100
";
        let l = parse_netstat(out);
        assert_eq!(l.len(), 3, "only LISTENING rows");
        assert_eq!(l[0].local_addr, "127.0.0.1");
        assert_eq!(l[0].port, 11434);
        assert_eq!(l[0].pid, Some(1234));
        assert_eq!(l[0].process, None); // netstat gives no name
        assert_eq!(l[2].local_addr, "::");
        assert_eq!(l[2].port, 8080);
    }

    #[test]
    fn lsof_parses_listen_rows() {
        let out = "\
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ollama   1234 user    3u  IPv4 0x1234      0t0  TCP 127.0.0.1:11434 (LISTEN)
llama-se  999 user    6u  IPv6 0x5678      0t0  TCP *:8080 (LISTEN)
Dropbox   321 user   20u  IPv4 0x9abc      0t0  TCP 192.168.1.5:17500->1.2.3.4:443 (ESTABLISHED)
";
        let l = parse_lsof(out);
        assert_eq!(l.len(), 2, "only (LISTEN) rows");
        assert_eq!(l[0].process.as_deref(), Some("ollama"));
        assert_eq!(l[0].pid, Some(1234));
        assert_eq!(l[0].local_addr, "127.0.0.1");
        assert_eq!(l[0].port, 11434);
        assert_eq!(l[1].local_addr, "0.0.0.0"); // `*`
        assert_eq!(l[1].port, 8080);
    }

    #[test]
    fn tasklist_maps_pid_to_name() {
        let out = "\
\"ollama.exe\",\"1234\",\"Console\",\"1\",\"120,000 K\"
\"sshd.exe\",\"567\",\"Services\",\"0\",\"5,000 K\"
\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"
";
        let m = parse_tasklist(out);
        assert_eq!(m.get(&1234).map(String::as_str), Some("ollama")); // .exe stripped
        assert_eq!(m.get(&567).map(String::as_str), Some("sshd"));
        assert_eq!(m.get(&0).map(String::as_str), Some("System Idle Process"));
    }

    #[test]
    fn empty_provider_is_empty() {
        assert!(EmptyListenerProvider.listeners().is_empty());
    }
}
