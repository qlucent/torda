# Torda collector quickstart

`docker compose up` stands up the **viewing side** for Torda's OCSF
output: OpenSearch (storage + search) + OpenSearch Dashboards (visualization)
+ Vector (the shipper that tails an OCSF NDJSON file and indexes it). The
agent itself keeps running on the host — it needs eBPF/ETW privilege and
makes no network call of its own (see `docs/DEPLOY.md`) — this stack just
gives you somewhere to *watch* what it emits, with prebuilt dashboards
including an attack-chain view, in about an hour with no cloud account and
no license.

> **DEV-ONLY — read this before you run it.** This compose file disables the
> OpenSearch security plugin (`DISABLE_SECURITY_PLUGIN=true` /
> `DISABLE_SECURITY_DASHBOARDS_PLUGIN=true`): **no TLS, no authentication, no
> authorization.** Anyone who can reach ports `9200`/`5601` has full read/write
> access to every index. This is fine for a laptop demo bound to `localhost`.
> It is **never** acceptable to expose these ports on a network, in a cloud
> security group, or in production. See `docs/DEPLOY.md` for the
> production-shipping path (agent -> your own secured SIEM/shipper). For a
> profile with **TLS + authentication enabled**, use the secure profile below.

## Secure profile (TLS + auth)

`docker-compose.secure.yml` runs the same stack with the **OpenSearch security
plugin enabled** — TLS on the REST API and required authentication — instead of
the security-disabled dev quickstart.

```bash
cp .env.secure.example .env          # then edit .env and set a STRONG password
docker compose -f docker-compose.secure.yml up -d

# verify (self-signed demo cert -> -k):
curl -k -u "admin:$OPENSEARCH_ADMIN_PASSWORD" https://localhost:9200/_cluster/health
# open the UI and log in as admin / your password:
#   https://localhost:5601   (or http://localhost:5601 -> login screen)
```

What it changes vs the dev profile:

- OpenSearch requires auth (unauthenticated requests get `401`) and serves REST
  over **TLS** (plain HTTP is refused). The admin password comes from
  `.env` (`OPENSEARCH_ADMIN_PASSWORD`; must be 8+ chars with upper/lower/digit/
  special or the node won't boot).
- Dashboards authenticates to OpenSearch (`config/opensearch_dashboards.secure.yml`)
  and end users log in as `admin`.
- Vector ships over `https` as a **least-privilege `torda-ingest` user** — write
  access to the `torda-*` indices only, provisioned automatically on first boot by
  `config/security-bootstrap.sh`. The log shipper never holds admin credentials.
- Dashboards authenticates to OpenSearch as the built-in `kibanaserver` demo
  service account (a limited-privilege account — human logins use `admin`).

**Demo-cert / demo-user caveat — harden before production:** TLS here uses
OpenSearch's auto-generated **self-signed demo certificates**, so certificate
verification is relaxed (`vector` `verify_certificate = false`; Dashboards
`opensearch.ssl.verificationMode: none`). Encryption + auth are real, but for a
true production deployment you should: replace the demo certs with your own
CA-issued node/admin certs and turn verification back **on**; **rotate the demo
internal-user passwords** (`kibanaserver`, etc.) via `securityadmin.sh`; and serve
Dashboards itself over HTTPS. The `.env` file is git-ignored — never commit your
passwords.

## Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine + the Compose plugin
  (Linux), able to run `docker compose`.
- **Linux hosts only:** OpenSearch needs a larger virtual memory map limit
  than the Linux default. If the `opensearch` container exits with a
  `max virtual memory areas vm.max_map_count [65530] is too low` error, raise
  it on the **host** (not in the container) before starting:

  ```bash
  sudo sysctl -w vm.max_map_count=262144
  # persist across reboots:
  echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
  ```

  (Docker Desktop on Windows/macOS runs OpenSearch inside its own Linux VM,
  which usually already ships a high enough limit — you only need this on
  bare-metal/native Linux Docker hosts.)

## 1. Start the stack

From `deploy/collector/`:

```bash
docker compose up -d
```

This starts `opensearch` (port 9200), `opensearch-dashboards` (port 5601),
and `vector`. `opensearch-dashboards` and `vector` both wait on OpenSearch's
healthcheck, so give it a minute on first start (image pull + JVM boot).
Confirm it's healthy:

```bash
curl -s http://localhost:9200/_cluster/health | grep -o '"status":"[a-z]*"'
# expect "status":"green" or "status":"yellow"
```

## 2. Apply the ingest pipeline + index templates

Do this once (or whenever a file under `opensearch/` changes) so fields index as
aggregatable keywords/numbers instead of full-text. Apply the **findings MTTR
ingest pipeline first** — the findings template sets it as `default_pipeline`, so
it must exist before any finding is indexed; it derives `mttr_days` (=
`closed_at − first_seen`) for the lifecycle dashboard from the engine's lifecycle
timestamps. Then the three templates: the OCSF events plus the two Findings Engine
outputs (findings + the fix-first remediation queue). Apply everything **before**
data flows so nothing gets dynamically mapped as text:

```bash
curl -XPUT http://localhost:9200/_ingest/pipeline/torda-findings-mttr \
  -H 'Content-Type: application/json' \
  --data-binary @opensearch/findings-mttr-pipeline.json
curl -XPUT http://localhost:9200/_index_template/torda-ocsf \
  -H 'Content-Type: application/json' \
  --data-binary @opensearch/index-template.json
curl -XPUT http://localhost:9200/_index_template/torda-findings \
  -H 'Content-Type: application/json' \
  --data-binary @opensearch/findings-index-template.json
curl -XPUT http://localhost:9200/_index_template/torda-remediation \
  -H 'Content-Type: application/json' \
  --data-binary @opensearch/remediation-index-template.json
```

## 3. Get data flowing

Vector tails `./ingest/events.ndjson` (bind-mounted read-only into the
`vector` container at `/ingest/events.ndjson`). Create that directory and
populate it one of two ways:

**Option A — zero-agent demo (fastest path to a populated dashboard):**

```bash
mkdir -p ingest
cp events.sample.ndjson ingest/events.ndjson
# and the prebuilt Findings Engine outputs, so the fix-first dashboard
# (step 3b / step 5) is populated too — or regenerate them yourself in 3b:
cp findings.sample.ndjson ingest/findings.ndjson
cp remediation.sample.ndjson ingest/remediation.ndjson
```

**Option B — the real agent**, writing its OCSF NDJSON straight into the
same ingest path (run this from wherever `torda` is built, adjusting
the `--output` path to point at `deploy/collector/ingest/events.ndjson` on
this host):

```bash
mkdir -p deploy/collector/ingest
./target/release/torda --daemon \
  --output deploy/collector/ingest/events.ndjson
```

The path after `--output` **must** be the same file Vector tails
(`./ingest/events.ndjson` relative to `deploy/collector/`) — that bind mount
is the entire seam between the agent and the stack.

Either way, Vector picks up new lines as they're appended (`read_from =
"beginning"` on first read) and indexes them into
`torda-ocsf-YYYY.MM.DD`. Confirm docs are landing:

```bash
curl -s http://localhost:9200/torda-ocsf-*/_count
```

## 3b. Produce findings (the fix-first view — the differentiation)

The events index above is a *stream of detections*. The value is what the
**Findings Engine** does with it: recompute one canonical, explainable risk
score per finding (never trusting a source's severity label), dedupe, and
**group by fix** — so N detections collapse into a short, risk-ranked queue of
*actions*, each showing how many findings and assets one fix closes. That queue
is what incumbents' flat per-CVE lists don't give you.

Run the processor (built from `server/ingest`) over the same events file; it
writes two more NDJSON files into the ingest dir that Vector is already
watching (from step 3b onward it ships them to `torda-findings-*` and
`torda-remediation-*`):

```bash
# from the repo's torda/ dir:
cargo run -p torda-ingest --bin findings-from-events -- \
  --input deploy/collector/ingest/events.ndjson \
  --findings-out deploy/collector/ingest/findings.ndjson \
  --remediation-out deploy/collector/ingest/remediation.ndjson
```

It's a one-shot batch — re-run it whenever the events file grows (a continuous
tailing daemon is on the roadmap). Re-running rewrites both NDJSON files from
scratch, so Vector re-indexes every finding: the fix-first queue *table* still
collapses correctly (it aggregates by fix), but the single-number count tiles
can inflate until the daily index rolls or you reset. For a clean re-run, wipe
first with `docker compose down -v` (see **Teardown**) and repeat from step 1.
Confirm the findings landed:

```bash
curl -s http://localhost:9200/torda-findings-*/_count
curl -s http://localhost:9200/torda-remediation-*/_count
```

(Option A already staged `findings.sample.ndjson` / `remediation.sample.ndjson`
for you, so you can skip this step for the zero-agent demo.)

## 3c. Scan for vulnerabilities (real CVE findings from a bundled OSV snapshot)

Step 3b runs the Findings Engine with an empty CVE feed, so an SBOM (`class_uid:
5020`, "Software Inventory Info") envelope in the events file never turns into a
vuln finding by itself. `osv-sample/osv-bundle.json` is a small, committed OSV-
format snapshot covering a few REAL, well-known CVEs for common Debian/Ubuntu
packages (openssl, zlib1g, curl — see the file for the exact ids and fixed
versions). Pass it with `--osv` to match your SBOM against real, range-aware CVE
data instead:

```bash
# from the repo's torda/ dir — same events file, same outputs step 3b uses:
cargo run -p torda-ingest --bin findings-from-events -- \
  --input deploy/collector/ingest/events.ndjson \
  --findings-out deploy/collector/ingest/findings.ndjson \
  --remediation-out deploy/collector/ingest/remediation.ndjson \
  --osv deploy/collector/osv-sample/osv-bundle.json
```

If the agent's SBOM reports (for example) `openssl 3.0.2` on a dpkg host, this
produces an Open finding for `CVE-2022-3602`/`CVE-2022-3786` with remediation
key `upgrade:openssl>=3.0.7` in the fix-first queue (step 5). A host already on
`openssl 3.0.7` (the fixed version) correctly gets no finding for those CVEs —
the matcher is range-aware, not a stale exact-version list. `--osv` also
accepts a directory of `.json` bundle files, merged together. Without `--osv`
the vuln/SBOM path stays exactly as in step 3b (empty feed, no CVE findings) —
fully backward compatible. An unreadable or unparseable `--osv` path is a hard
error, not a silent fallback.

**Honest coverage note:** OSV's practical coverage is Linux OS packages (dpkg/
rpm) — this bundle only helps a Linux SBOM. Windows/registry components have
thin-to-no OSV coverage; a real vuln feed there is NVD, which lands in a later
slice behind the same `CveSource` trait (no pipeline change when it arrives).

## 3d. Enrich the CVE findings (real CVSS/EPSS/KEV → real risk scores)

Step 3c *matches* SBOM components to real CVEs, but with no enrichment every
matched CVE scores `R=0` — the engine recomputes risk from evidence and, given
none, has nothing to score (never a source's severity label).
The `osv-sample/` directory bundles three small, committed, **real, web-verified**
enrichment snapshots so those findings get a real, explainable score:

- `osv-bundle.json` — carries each advisory's real **CVSS v3.1** base score +
  vector (verified against NVD, `nvd.nist.gov`).
- `epss-sample.csv` — real **EPSS** probability + percentile per CVE (FIRST.org
  format; the header notes the score date — EPSS changes daily).
- `kev-sample.json` — a real subset of the **CISA KEV** catalog. Of the bundled
  CVEs only `CVE-2021-3156` (sudo "Baron Samedit") is genuinely KEV-listed; a KEV
  hit is driven straight to **ACT** regardless of score.

Pass `--enrich <dir>` (point it at the same `osv-sample/` dir) alongside `--osv`:

```bash
# from the repo's torda/ dir:
cargo run -p torda-ingest --bin findings-from-events -- \
  --input deploy/collector/ingest/events.ndjson \
  --findings-out deploy/collector/ingest/findings.ndjson \
  --remediation-out deploy/collector/ingest/remediation.ndjson \
  --osv deploy/collector/osv-sample/osv-bundle.json \
  --enrich deploy/collector/osv-sample
```

Now an `openssl 3.0.2` match scores a real `R` (CVSS 7.5 × EPSS-driven
likelihood × asset context), and a `sudo 1.8.31` host gets a KEV finding driven
to ACT — so the fix-first queue (step 5) ranks by real risk instead of a flat
list. Without `--enrich` the scores stay neutral (`R=0`), byte-identical to step
3c — fully backward compatible. An unreadable or unparseable snapshot is a hard
error, not a silent fallback.

**Honest coverage note:** these are a small *bundled* snapshot for the demo, not
a live feed — the values are real as of the dates noted in each file. A real
deployment syncs the full NVD / FIRST.org EPSS / CISA KEV feeds on a schedule;
that sync service lands in a later slice (VD-4) behind the same `EnrichmentSource`
trait, with no pipeline change when it arrives.

## 3e. Windows coverage (NVD community feed)

OSV's coverage is Linux OS packages (dpkg/rpm) — a Windows `registry` SBOM
component matches nothing against it. `osv-sample/nvd-bundle.json` is a small,
committed, date-stamped **NVD community feed** covering a few REAL, well-known
CVEs for common Windows desktop apps (PuTTY, Notepad++, 7-Zip, OpenVPN — CVSS +
version ranges from `nvd.nist.gov`). It maps a Windows Add/Remove-Programs
**DisplayName** to the affected product via a curated alias list. Pass it with
`--nvd` alongside `--osv`; the two compose (OSV resolves dpkg/rpm, NVD resolves
`registry`) with no double counting:

```bash
# from the repo's torda/ dir — Linux (OSV) + Windows (NVD) together:
cargo run -p torda-ingest --bin findings-from-events -- \
  --input deploy/collector/ingest/events.ndjson \
  --findings-out deploy/collector/ingest/findings.ndjson \
  --remediation-out deploy/collector/ingest/remediation.ndjson \
  --osv deploy/collector/osv-sample/osv-bundle.json \
  --nvd deploy/collector/osv-sample/nvd-bundle.json \
  --enrich deploy/collector/osv-sample
```

The sample's `win-01` host reports (for example) `PuTTY release 0.80` and `7-Zip
23.01` — below their fixed versions — so this produces Open findings
`upgrade:putty>=0.81` and `upgrade:7-zip>=24.07` in the fix-first queue, scored
from the same real CVSS/EPSS the `--enrich` dir already supplies (the NVD CVEs'
CVSS lives in `nvd-bundle.json`, their EPSS in `epss-sample.csv`). A host on the
fixed version gets no finding — the matcher is range-aware. Without `--nvd` the
Windows path stays empty (backward compatible).

**Honest coverage note:** this is a *curated common-app* mapping in a
date-stamped **community** snapshot — the DisplayName→product aliases and the CVE
set are hand-picked, and a Windows version that is not a clean ≤3-part number
(e.g. `2.5.9.0`) fails closed (no false positive) until a 4-part-tolerant
comparator lands. A live NVD 2.0 sync with full CPE-dictionary matching is the
**enterprise** feed, behind the same `CveSource` trait — no pipeline change when
it arrives.

## 4. Import the prebuilt dashboards

```bash
curl -X POST http://localhost:5601/api/saved_objects/_import?overwrite=true \
  -H "osd-xsrf: true" \
  --form file=@dashboards/dashboards.ndjson
```

A successful response has `"success":true` and no `errors` entries (dangling
references, if any, would show up here — this bundle's index-pattern and
visualization references are self-contained). Re-running the same import is
safe (`overwrite=true`).

## 5. Open the dashboard

Go to **http://localhost:5601** -> **Dashboards**. The import ships **five**, all
with a 1-year default time range (`timeRestore`) so sample timestamps show up
without adjusting the picker:

**"Vulnerability details"** (the row-level drill-down + export — needs steps 3c +
3d's data):

- One **row per CVE finding** (package × CVE × host): CVE, package, CVSS, KEV,
  EPSS, recomputed risk **R**, engine **decision** (ACT/ATTEND/TRACK), the
  **upgrade** that fixes it, host, and status. Sort any column.
- **Filter** with the select-to-filter dropdowns (decision, package, host,
  exploit maturity) or the search/filter bar — e.g. `decision: ACT` narrows to
  the known-exploited items.
- **Export** the table to CSV: open the **"CVE detail"** saved search in
  **Discover** (or the panel's context menu) → **Reporting → Generate CSV** (the
  `reportsDashboards` plugin ships in the image). (Drill-through to the exact
  installed version — the SBOM row — is a roadmap item; the row carries the CVE,
  the fix target, and the score.)

**"Vulnerability Management"** (real CVE findings — needs steps 3c + 3d's data):

- **Severity boxes** — CVE count by CVSS base score: **Critical / High / Medium /
  Low**. A **Known-Exploited (KEV)** callout counts CVEs in CISA's catalog (these
  are driven to **ACT** regardless of score — patch first).
- **Top vulnerabilities** (CVEs by risk), **Top vulnerable packages** (upgrade
  one, close many), **Top affected hosts**, and **CVEs by decision**.
- **Fix-first: upgrade queue** — the package-upgrade actions that close CVEs,
  ranked by the risk each clears (# CVEs closed, # hosts). Every score is
  recomputed from real CVSS/EPSS/KEV — never a source's own label. (OSV covers
  Linux OS packages; Windows/registry coverage is thin pending NVD.)

**"Findings — fix-first"** (the differentiation — needs step 3b's data):

- **Fix-first remediation queue** — the star panel: every detection collapsed
  into the smallest set of *fixes*, ranked by the risk each clears, showing
  **# findings closed** and **# assets affected** per fix. This is what you
  triage against — not a flat CVE list.
- **Fixes in queue** and **Scored findings** single-number totals (the collapse
  ratio: many findings → few fixes).
- **Findings by status** (open / reopened / closed / suppressed / accepted) and
  **Findings by risk band** (canonical R, recomputed — never a source label).

**"Security posture & agent activity"** (the story, not the counts — laid out
top-to-bottom as four questions):

1. **Is the agent healthy and covering the fleet?** — **hosts covered**, the
   agent's **CPU/mem footprint over time against its 5% budget** (the "one light
   agent" proof), and **last seen per host** (a stale row = an agent that went
   quiet).
2. **What is it catching?** — **detections by category**, **activity over time**
   split by category (spikes and quiet days are visible), attack chains by rule,
   and top process images.
3. **What's the posture now?** — total **events collected** (raw telemetry
   volume) beside the **Scored findings** and **Fixes** tiles that show the real
   findings → fixes collapse; **compliance** pass/fail (CIS controls),
   **file-integrity changes** (FIM), **config drift**, and the findings **risk
   band**.
4. **Is it getting better or worse?** — **attack chains per day** and the
   activity trend.

> The shipped sample spans ~4 weeks (deterministic DEMO data) so the trend and
> posture panels are populated. On a real deployment these fill in live as the
> agent runs day over day.

**"Findings lifecycle — opened vs closed, MTTR"** (are you closing findings
faster than they open?):

- **Open now / Closed / Reopened** tiles + **Avg MTTR (days)**.
- **Findings opened per week** (bucketed on `first_seen`) vs **Findings closed per
  week** (on `closed_at`) — the backlog burndown.
- **Avg MTTR by decision** (ACT fixes should close fastest) and the **status mix**.

The lifecycle timestamps are **engine-generated**: `reconcile` stamps
`first_seen` (when a finding first opened, preserved across recurrence) and
`last_seen` (each run) from event time, so a real deployment running
`findings-from-events --store` day over day produces the **opened-per-week** and
**open-backlog** history for free.

**Honest limitation:** `closed_at` is stamped only when a finding *transitions to
Closed*, which today happens through the Remediation Bridge's verification
(confirming a fix). **Auto-close-on-absence** — closing a finding that simply
stops recurring — is deliberately deferred (it's a policy call: a host offline for
a day shouldn't mark all its findings fixed). So on
real data *without* remediation wired, the **closed-per-week** and **MTTR** panels
stay empty until closes flow; the bundled crafted seed shows the full story so you
can see what those panels look like. `mttr_days` (= `closed_at − first_seen`) is
derived by the collector's ingest pipeline
(`opensearch/findings-mttr-pipeline.json`, step 2), never stored by the engine.
The seed (`findings.sample.ndjson`) uses the identical engine schema (a one-shot
demo run would stamp everything at "now").

## 6. Trigger a real detection

With the agent running in daemon mode against this ingest path (Option B
above, built with `--features linux-ebpf` as root or `--features
windows-etw` as Administrator — see `docs/DEPLOY.md` §1), fire the
self-asserting attack-chain demo in a second terminal:

```bash
# Linux, root
cargo run --features linux-ebpf --bin corr-triple-demo

# Windows, Administrator
cargo run --features windows-etw --bin corr-triple-demo
```

Refresh the dashboard and watch a new `class_uid: 9002`
(`suspicious_process_wrote_file_and_connected`) row land in the attack-chains
table within a few seconds.

## Teardown

```bash
docker compose down -v
```

The `-v` also removes the named `opensearch-data` volume, so the next
`up -d` starts from a clean index — use it whenever you want a fresh demo,
and drop the `-v` if you want the indexed data to survive a restart.

## See also

- `docs/DEPLOY.md` — running the agent itself (build flags, systemd unit,
  config precedence, the production "ship the file to your own SIEM" path).
- `deploy/collector/docker-compose.yml`, `deploy/collector/vector.toml`,
  `deploy/collector/opensearch/*-index-template.json` — the pipeline this
  README drives (OCSF events + findings + remediation).
- `server/ingest` (`findings-from-events`) — the Findings Engine processor
  that turns the OCSF events into the scored, fix-grouped queue in step 3b.
