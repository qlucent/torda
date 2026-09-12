# torda-feed

The open, signed **enrichment feed** format shared by both tiers of Torda's
vulnerability / threat-intel enrichment. Apache-2.0 — deliberately outside the
moat, so anyone can produce, publish, verify, and consume a feed.

A *feed* is the corpus of CVSS / EPSS / KEV / advisory evidence the Findings
Engine recomputes a canonical, explainable score from. This crate owns the
**format, verification, local store, and CLI**; it does not decide scores.

## Bundle format

A bundle is a directory:

```
manifest.json        # FeedManifest: version, created_at, source, tier, entries[]
manifest.json.sig    # detached Ed25519 signature (hex) over the manifest's canonical bytes
osv-bundle.json      # content files named in the manifest, one per FeedEntry
nvd-bundle.json      #   each with a sha256 in the manifest
epss-sample.csv
kev-sample.json
```

`verify_bundle` fails **closed**: it rejects a bundle whose manifest signature is
not made by a trusted key, whose any content digest does not match, that lists
too many entries or an oversized file, or whose entry name is not a plain file
name (no path traversal). Feed data is untrusted external input and is treated
as such.

The manifest **signature** attests content authenticity/integrity. It is a
separate concern from tier **entitlement** — who may fetch the enterprise
source — which the FSL crate `torda-feed-live` enforces with its own issuer key.

## Tiers

Both tiers implement the same `FeedSource` trait and install into the same store
through the same verification:

| Tier | Source | Auth | Cadence |
| --- | --- | --- | --- |
| **Community** | `StaticBundleSource` — a published signed bundle (Apache) | none | periodic snapshot |
| **Enterprise** | `torda-feed-live` (FSL) — a live hosted source | signed entitlement token | near-real-time, curated |

## CLI

```bash
# Install + verify a bundle into the local store (default trust = built-in
# sample key; pass --trust <hex|file> for a real published key).
torda-feed install --from ./sample-bundle --store ./feed-store

# What's installed?
torda-feed status --store ./feed-store

# (dev) regenerate a signed sample bundle from a directory of content files.
torda-feed gen-sample --content deploy/collector/osv-sample --out crates/feed/sample-bundle \
  --tier community --version 2026-09-12T00:00:00Z --source qlucent-community
```

Store precedence: `--store` > `$TORDA_FEED_STORE` > `<temp>/torda-feed-store`.

## Air-gap / offline

The same signed bundle side-loads offline: copy the bundle directory to the
disconnected host and `torda-feed install --from <dir>`. Connected sync and
offline import share one artifact and one verification path.

## Explainability

The store's active `feed_version` is stamped by the ingest `EnrichmentSource`
(`BundledEnrichment::load_from_feed_store`) into every finding it scores — so
"why is this critical?" always cites which feed snapshot supplied the inputs.

## Sample key

`src/sample.rs` ships a **non-production** signing key so the bundled sample
verifies out of the box (like `torda-transport-tls`'s test PKI). It is never a
production trust root; real deployments trust a real published key.
