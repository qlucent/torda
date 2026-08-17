# Deploying Torda

This is the "run it -> point a shipper at the file -> see OCSF in your SIEM"
path. The primary way to configure the agent is the unified TOML config
(`--config <path>` / `$TORDA_AGENT_CONFIG=<path>`, see `deploy/torda.toml`
for a commented sample) — `[agent]` sets daemon mode, `[output]` picks the
sink, and an optional `[control]` section opts in to the mTLS remediation
channel. CLI flags/env vars (`--daemon`, `--output`, ...) are OVERRIDES on top
of the config (precedence: flag > env > config > default), so you can ship one
config file and still adjust a value per-host at launch. No config file is
required either — with neither a config nor flags, the agent runs its classic
one-shot-to-stdout cycle. Everything below is run from the `torda/`
workspace directory unless noted.

## 1. Build with the right feature for your OS

The default build has **no** real kernel-event backend — it runs on the stub
event bus, which is safe everywhere but never observes real process/network/
file activity (snapshot modules like asset/vuln/compliance/drift/fim still
work fully). To capture real events, build with the platform feature:

```bash
# Linux — eBPF process/network/file events
cargo build --release --features linux-ebpf

# Windows — ETW process/network/file events
cargo build --release --features windows-etw
```

**Why elevation is required:** opening a kernel eBPF/ETW probe is a
privileged operation.

- Linux: run as **root**, or grant the binary `CAP_BPF`+`CAP_PERFMON`
  (`sudo setcap cap_bpf,cap_perfmon+eip target/release/torda`).
- Windows: run as **Administrator** (ETW session creation requires it).

Without the feature flag, or without the required privilege even with the
feature on, the agent **fails soft** to the stub event bus and keeps running
— it never crashes for lack of privilege, it just collects nothing from the
kernel that cycle.

## 2. Run as a service

### Linux (systemd)

Use the sample unit at `deploy/torda.service` together with the sample
config at `deploy/torda.toml` (the unit runs `--config
/etc/torda/config.toml`; daemon mode + the file sink are set in that
TOML — edit it to taste, and CLI flags still override it):

```bash
sudo cp deploy/torda.service /etc/systemd/system/
sudo mkdir -p /etc/torda /var/log/torda
sudo cp deploy/torda.toml /etc/torda/config.toml   # then edit it
sudo systemctl daemon-reload
sudo systemctl enable --now torda
journalctl -u torda -f   # stderr: startup/health lines
tail -f /var/log/torda/events.ndjson   # stdout-equivalent: OCSF NDJSON
```

For a bounded test run instead of the real service, run directly (flags here
override the config the same way they would against the installed service):

```bash
TORDA_RUN_SECS=60 ./target/release/torda \
  --config deploy/torda.toml --daemon \
  --output /var/log/torda/events.ndjson
```

`TORDA_RUN_SECS=<n>` makes the daemon exit cleanly after `n` seconds instead of
running until `ctrl-c`/`SIGINT` — useful for a canary/smoke deploy or CI.

### Windows

There is no bundled Windows service wrapper yet (tracked in the deferred
backlog). For now, run the agent under a process supervisor of your choice
(NSSM, Task Scheduler "run whether user is logged on or not", a Windows
Service wrapper script) as **Administrator**, pointing at a local output
path:

```powershell
.\target\release\torda.exe --daemon --output C:\ProgramData\torda\events.ndjson
```

## 3. Ship the file to your SIEM

The agent itself makes **no network call** — the NDJSON file is the seam, and
a standard log shipper carries it onward. `deploy/vector.toml` is a minimal
[Vector](https://vector.dev) config: a `file` source tailing
`/var/log/torda/events.ndjson`, with a `console` sink for quick
verification and a commented `elasticsearch`-type sink showing the one-line
switch to a real OpenSearch/ELK endpoint.

```bash
vector --config deploy/vector.toml
```

Uncomment the `[sinks.opensearch]` block in `deploy/vector.toml`, point
`endpoints` at your cluster, and remove/keep the console sink as needed.
Filebeat/Splunk-UF work the same way — any shipper that can tail a file and
parse JSON lines will do; the agent doesn't care which one you use.

## 4. Trigger a detection to see it work

With the agent running in daemon mode (built with `linux-ebpf` as root, or
`windows-etw` as Administrator), generate an attack-chain signal with one of
the self-asserting demo binaries — e.g. the triple-chain correlation demo
(dropper-then-C2: a suspicious connect + a suspicious file write from the same
process):

```bash
# Linux, root, in a second terminal while the daemon runs
cargo run --features linux-ebpf --bin corr-triple-demo

# Windows, Administrator
cargo run --features windows-etw --bin corr-triple-demo
```

Then watch the output file grow with a `class_uid: 9002` ("Correlated
Activity") OCSF record, and see it flow through Vector to your console/SIEM
sink. Other demos (`procmon-ebpf-demo`, `netmon-ebpf-demo`, `filemon-demo`,
`corr-file-demo`, etc. — see `crates/agent/Cargo.toml`'s `[[bin]]` entries)
exercise the other detection paths the same way.

## 5. Current (v1) limits — read this before you rely on it

- **Snapshot modules emit once at startup, not periodically.** `asset`,
  `health`, `vuln`, `compliance`, `drift`, and `fim` collect a point-in-time
  snapshot when the daemon starts and do not re-collect while it keeps
  running. Only the event-driven modules (`procmon`, `netmon`, `filemon`,
  `corr`) stream continuously. Periodic snapshot refresh is a tracked
  fast-follow.
- **Config changes need a restart.** The TOML config (`--config`) is read once
  at startup — there is no hot-reload/SIGHUP yet, so restart the service to
  apply a change.
- **One sink at a time.** `--output` picks a rotating file sink; without it,
  the agent writes NDJSON to stdout (the default, byte-identical to earlier
  releases). There's no "tee to both" option yet.
- **No Windows service wrapper bundled.** See the Windows note in step 2.

## Reference

- `--daemon` / `$TORDA_DAEMON=1` — keep streaming until a shutdown signal
  (`ctrl-c`/`SIGINT`, or `$TORDA_RUN_SECS=<n>` for a bounded run). Without it,
  the agent runs one short collection cycle and exits (today's default).
- `--output <path>` / `$TORDA_OUTPUT=<path>` — write OCSF NDJSON to a rotating
  file instead of stdout. `--rotate-mb <n>` / `$TORDA_ROTATE_MB=<n>` sets the
  rotation threshold in MB (default 64 MB, keeps up to 3 rolled files).
- `--config <path>` / `$TORDA_AGENT_CONFIG=<path>` — load the unified TOML config:
  `[agent]` (daemon), `[output]` (file sink), and the optional `[control]` mTLS
  channel. CLI flags/env OVERRIDE config values (precedence: flag > env > config
  > default). See `deploy/torda.toml` for a commented sample.
