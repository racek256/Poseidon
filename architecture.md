# Poseidon — Architecture

## Overview

Poseidon is a **phishing detection / message security scoring system** built in Rust for the AT&T Hackathon. It analyzes text messages for security threats — phishing URLs, brand impersonation, secrets leakage, and prompt injection — using multiple detection layers: **local threat intelligence feeds**, **URL enrichment (DNS/WHOIS/HTTP page analysis)**, **offline brand matching (typo detection + brand catalog)**, **online brand identity discovery (page metadata/JSON-LD)**, **domain reputation tracking**, **unsafe message memory (simhash similarity)**, and a **local LLM** for AI assessment.

**Total: 27 Rust source files, ~7,986 lines of code across one library crate, one binary entrypoint, and two standalone CLI binaries.**

---

## Project Structure

```
Poseidon/
├── Cargo.toml                        # Rust project config (edition 2024)
├── architecture.md                   # This file
├── README.md                         # Project README
├── src/
│   ├── lib.rs                        # Library root (exports modules)
│   ├── main.rs                       # Binary entrypoint (CLI router + server)
│   ├── bin/
│   │   ├── brand_scraper.rs          # Standalone: Wikidata brand catalog builder
│   │   └── tranco_importer.rs        # Standalone: Tranco top-1M domain rank importer
│   └── modules/
│       ├── mod.rs                    # Module declarations
│       ├── api.rs                    # HTTP API server (raw TCP)
│       ├── scoring.rs                # Core scoring engine
│       ├── ai.rs                     # LLM integration (Ollama + OpenAI-compatible)
│       ├── llm_server.rs             # llama.cpp server lifecycle management
│       ├── web.rs                    # URL extraction + WHOIS
│       ├── phishing_benchmark.rs     # Full benchmark pipeline (local + HuggingFace datasets)
│       ├── message_memory/
│       │   └── mod.rs                # Unsafe message memory (simhash similarity)
│       ├── url_db/
│       │   └── mod.rs                # URL database layer (DuckDB, 10+ tables)
│       ├── threat_intel/
│       │   ├── mod.rs                # Feed refresh coordinator
│       │   ├── db.rs                 # Threat DB schema & operations
│       │   ├── sources.rs            # Feed source definitions
│       │   └── feeds.rs              # Feed parsers (17 formats)
│       └── url_analysis/
│           ├── mod.rs                # Module declarations
│           ├── enrich.rs             # URL enrichment worker (queue processor)
│           ├── online.rs             # Online URL analysis (DNS/WHOIS/HTTP)
│           ├── brand.rs              # Deterministic brand impersonation
│           ├── brand_detector.rs     # Online brand identity discovery
│           ├── domain.rs             # URL parser (registrable domain extraction)
│           ├── hosting.rs            # Hosting provider domain list
│           ├── page_metadata.rs      # HTML metadata extractor
│           ├── benchmark.rs          # Offline brand detection benchmark
│           └── online_benchmark.rs   # Online brand detection benchmark
├── scripts/
│   ├── build-llama-server.sh         # Builds llama.cpp from source
│   ├── download-model.sh             # Downloads GGUF models (small/medium/large)
│   └── run-llama-server.sh           # Starts llama.cpp server
├── data/
│   ├── benchmarks/                   # Benchmark datasets (JSONL)
│   │   ├── phishing_messages.jsonl   # Built-in phishing benchmark (bundled)
│   │   ├── phishing_hf_500.jsonl     # HuggingFace sample (500 rows)
│   │   └── phishing_hf_200k.jsonl    # Full HuggingFace dataset (200K rows)
│   ├── brand_catalog.json            # Wikidata-sourced brand catalog
│   ├── brand_info.json               # Brand metadata from scraper
│   └── favicon_hashes.json           # Known brand favicon SHA256 hashes
└── external/
    └── llama.cpp/                    # Git submodule for local inference
```

---

## Execution Flow: `cargo run` (Default — Server Mode)

```
main.rs
  │
  ├─ [SUBCOMMAND CHECK] If any CLI arg matches → dispatch & return immediately
  │   worker                    → process_pending() URL enrichment queue (max N=100)
  │   benchmark-brand           → run_brand_benchmark() (offline deterministic)
  │   benchmark-online-brand    → run_online_brand_benchmark() (online enrichment)
  │   benchmark-message-memory  → message_memory::run_benchmark()
  │   benchmark-phishing        → phishing_benchmark::run() (built-in dataset)
  │   benchmark-phishing-full   → full benchmark (HF 200K dataset, offline)
  │   benchmark-phishing-full-online → full benchmark with online enrichment
  │   download-phishing-benchmark → download HF dataset to JSONL
  │   benchmark-brand-learning  → brand_detector::run_real_page_benchmark()
  │   inspect-brand-learning    → UrlDb::print_brand_learning_summary()
  │   enqueue-url <url>         → manually queue URL for analysis
  │   detect-brand-url <url>    → test brand detection on single URL
  │   detect-impersonation-url <url> → test impersonation detection (with runtime brands)
  │   observe-safe-url <url>    → manually record safe domain observation
  │   inspect-domain-reputation → print domain reputation table
  │
  └─ DEFAULT (server mode):
      1. ThreatIntel::from_env()       ← init DuckDB (in-memory or file-backed)
      2. UrlDb::from_env()             ← init URL observation DB
      3. MessageMemory::from_env()     ← init unsafe message store
      4. threat_intel.update_if_due()  ← download & ingest 8 threat feeds
      5. llm_server::ensure()          ← check/start llama.cpp or external LLM
      6. ai::warmup()                  ← test LLM with a trivial prompt
      7. api::serve(addr, &threat_intel, &url_db, &message_memory)
           │
           └─ TcpListener at 127.0.0.1:8080
               │
               ├─ GET  /health     → { "ok": true }
               │
               └─ POST /analyse    → scoring::analyse(message, user_id, ...)
                    │  Request JSON: { "message": "...", "user_id": "..." }
                    │
                    ├─ message_memory.lookup(message)
                    │   ├─ normalize (lowercase, emails→<email>, numbers→<num>)
                    │   ├─ compute simhash64 (weighted by token importance)
                    │   ├─ SHA256 hash for exact match search
                    │   ├─ search unsafe_messages table for exact hash
                    │   ├─ search for similar matches (Hamming distance ≤ 12)
                    │   └─ return risk_adjustment (up to +35 for exact match)
                    │
                    ├─ ai::assess_message_with_url_context(message, url_context)
                    │   └─ POST to LLM → JSON: phishing, prompt_injection,
                    │       impersonation, risk, confidence, flags
                    │   └─ Supports: Ollama API OR OpenAI-compatible endpoint
                    │
                    ├─ scan_known_urls(message)
                    │   ├─ web::extract_urls(message) via regex
                    │   └─ for each URL (in order):
                    │       ├─ threat_intel.lookup(url)       ← known threat feeds?
                    │       ├─ url_db.lookup(identity)         ← previously observed?
                    │       ├─ brand::analyse_with_runtime_brands(url)  ← deterministic
                    │       └─ url_db.enqueue_unknown(url)    ← if unseen, queue for worker
                    │
                    ├─ score_prompt_injection(message)  ← 6 keyword patterns
                    ├─ score_secrets(message)           ← regex for API keys/tokens
                    ├─ score_urgency(message)           ← 6 urgency/account keywords
                    │
                    ├─ combine all scores → overall_risk → decide()
                    │   Block(≥90 or secret≥85) / WarnB(≥75) / WarnS(prompt≥60)
                    │   / WarnR(≥45) / Allow
                    │
                    ├─ observe_url_reputation()  ← update domain reputation per user
                    │   └─ url_db.observe_domain_reputation(safe|unsafe)
                    │
                    ├─ if unsafe: store in message_memory
                    │   └─ message_memory.store_unsafe(lookup, record)
                    │
                    └─ return Scoring::to_json() → HTTP 200 JSON response
```

### Scoring Variants

The `scoring::analyse_inner()` function has four public entry points configured by flags:

| Function | AI Enabled | Online URL Enrichment | Use Case |
|---|---|---|---|
| `analyse()` | ✅ Yes | ❌ No | Default production path |
| `analyse_with_online_url_enrichment()` | ✅ Yes | ✅ Yes | Full analysis (slower) |
| `analyse_without_ai()` | ❌ No | ❌ No | Benchmark (no LLM dependency) |
| `analyse_without_ai_with_online_url_enrichment()` | ❌ No | ✅ Yes | Benchmark with online signals |

---

## URL Enrichment Pipeline: Worker Mode

The `worker` subcommand (`-- worker`) processes queued URLs from `url_analysis_queue`:

```
process_pending(url_db, limit)
  ├─ claim_pending()            ← SELECT pending URLs (ordered by priority DESC)
  ├─ mark each 'processing'
  ├─ for each URL → process_one():
  │   ├─ online::analyse_online_with_runtime_brands(url, learned_brands)
  │   │   ├─ brand::analyse_with_runtime_brands(url, runtime_brands)
  │   │   │   ├─ parse URL into host/registrable_domain/subdomain/path
  │   │   │   ├─ merge static catalog brands + runtime learned brands
  │   │   │   ├─ check hosting provider list (vercel.app, netlify.app, etc.)
  │   │   │   ├─ for each brand: token match + Levenshtein typo + keyword scoring
  │   │   │   └─ return BrandImpersonation {score, matched_brand, official, reasons}
  │   │   │
  │   │   ├─ if NOT official:
  │   │   │   [PARALLEL thread::scope]
  │   │   │   ├─ collect_dns(host)     → DNS resolution + IP provider detection
  │   │   │   │                          (Cloudflare, Vercel, Fastly, etc. via CIDR)
  │   │   │   ├─ collect_whois(domain)  → WHOIS age + privacy protection check
  │   │   │   └─ collect_http_page(url) → fetch + analyse:
  │   │   │       ├─ favicon SHA256 hash → match known brand favicons
  │   │   │       ├─ HTML: title, form fields, password/OTP/card fields
  │   │   │       ├─ external form actions, redirect chain, brand text match
  │   │   │       └─ return OnlineEvidence
  │   │   │
  │   │   └─ score_online(deterministic, evidence)  ← combined scoring
  │   │
  │   ├─ store_observation(verdict, confidence, risk_score)
  │   ├─ store_brand_impersonation()
  │   ├─ store_tags(risk_level, brand, hosting)
  │   ├─ store_evidence(brand, online, dns, whois)
  │   │
  │   └─ IF low risk + NOT official:
  │       └─ learn_brand_identity(url)
  │           ├─ brand_detector::detect_brand_identity_with_reputation()
  │           │   ├─ fetch_page_metadata(url) → JSON-LD, OG, canonical, analytics
  │           │   ├─ best_identity_name()     ← org > og_site > app > title
  │           │   ├─ confidence_for()         ← Tranco rank + reputation + signals
  │           │   └─ candidate_allowed()      ← gating logic
  │           └─ store_brand_candidate() + store_domain_relationship()
  │
  └─ mark_done()
```

---

## Inline Online Enrichment (API Path)

When `online_url_enrichment=true` is passed to scoring (via `analyse_with_online_url_enrichment`), unknown URLs are enriched **synchronously** during the API call:

```
enrich_url_inline(url, identity, url_db)
  ├─ online::analyse_online_with_runtime_brands(url, learned_brands)
  │   (same pipeline as worker mode — DNS/WHOIS/HTTP in parallel)
  ├─ store_observation + store_brand_impersonation + store_tags + store_evidence
  └─ url_db.lookup(identity)  → return fresh UrlLookup
```

This is slower per-request (network calls) but provides immediate results without needing a separate worker.

---

## Detection Layers (Layer Cake)

```
┌──────────────────────────────────────────────────┐
│  Layer 0: Threat Feed Check                      │
│  URLhaus, PhishTank, MetaMask, BlackBook, etc.   │
│  → Known bad indicator → risk=100, verdict="bad"  │
├──────────────────────────────────────────────────┤
│  Layer 1: Deterministic Brand Impersonation      │
│  Brand catalog (Wikidata 2000+ brands / 22       │
│  hardcoded fallback) + typo detection (Levenshtein│
│  ≤ 2) + phishing keywords + hosting provider      │
├──────────────────────────────────────────────────┤
│  Layer 2: Online URL Enrichment                  │
│  DNS resolution, WHOIS age, HTTP page fetch,     │
│  favicon matching, credential field detection,   │
│  external form actions, redirect analysis         │
├──────────────────────────────────────────────────┤
│  Layer 3: Brand Identity Learning                │
│  JSON-LD structured data, OG tags, canonical     │
│  URLs, analytics IDs → discover what brand a     │
│  domain belongs to (auto-learn runtime brands)    │
├──────────────────────────────────────────────────┤
│  Layer 4: Domain Reputation                      │
│  Per-user safe/bad observation counts → boost    │
│  threshold: 25→+5, 75→+10, 250→+15               │
├──────────────────────────────────────────────────┤
│  Layer 5: Unsafe Message Memory (Simhash)        │
│  Previously seen unsafe messages → exact match   │
│  (+35 risk) or similar Hamming ≤12 (+10 to +35)   │
├──────────────────────────────────────────────────┤
│  Layer 6: LLM Assessment                         │
│  Ollama or OpenAI-compatible endpoint →          │
│  phishing/impersonation/risk scores + flags      │
└──────────────────────────────────────────────────┘
```

---

## Decision Matrix

| Condition | Decision |
|---|---|
| `overall_risk ≥ 90` OR `secret ≥ 85` | **Block** |
| `overall_risk ≥ 75` | **Warn Both** (sender + receiver) |
| `prompt_injection ≥ 60` | **Warn Sender** |
| `overall_risk ≥ 45` | **Warn Receiver** |
| Everything else | **Allow** |

### Overall Risk Calculation

**Default mode:** `max(phishing, secret, prompt_injection, impersonation, risk)` with URL reputation capped:
- URL risk ≥ 75 OR non-URL risk ≥ 40 → full URL risk counts
- Otherwise → URL risk capped at 40

**Online enrichment mode:** `max(all scores, URL reputation)` — no capping.

### AI Score Weighting

If `prompt_injection ≥ 80`, LLM scores are weighted at 30% (LLM might be compromised).
Otherwise, LLM scores are weighted at 100%.

### Risk Capping Without Deterministic Support

If NO supporting evidence from URL scans, urgency, secrets, or prompt injection:
- AI-only scores are capped at max 40 (prevents false positives from LLM alone)

---

## LLM Integration (Two Backends)

### 1. Ollama (Default)
- Endpoint: `http://localhost:11434/api/generate`
- Default model: `gemma4:e2b` (configurable via `POSEIDON_OLLAMA_MODEL`)
- JSON output format enforced via `"format": "json"`

### 2. OpenAI-Compatible (via `POSEIDON_LLM_ENDPOINT`)
- Set `POSEIDON_LLM_ENDPOINT=http://host:port/v1` → uses `/chat/completions` API
- Supports any OpenAI-compatible backend (e.g., llama.cpp, vLLM, OpenAI itself)
- Uses `response_format: {"type": "json_object"}` when available

### Auto-Setup (`llm_server.rs`)
If no `POSEIDON_LLM_ENDPOINT` is set, `llm_server::ensure()`:
1. Checks if an endpoint at `127.0.0.1:8081/v1` is already healthy
2. If not, builds `external/llama.cpp/build/bin/llama-server` via CMake
3. Finds a `.gguf` model in `models/` (or auto-downloads if `POSEIDON_LLAMA_AUTO_SETUP != false`)
4. Starts the server and polls `/health` for up to 30 seconds

### Two-Model Support
- Assessment model (`POSEIDON_OLLAMA_MODEL`): primary analysis
- Summary model (`POSEIDON_OLLAMA_SUMMARY_MODEL`): shorter model for danger summaries (falls back to assessment model)

---

## Database Schema (3 DuckDB Databases)

### 1. `poseidon_urls.duckdb` (UrlDb)

| Table | Purpose |
|---|---|
| `url_observations` | URL verdicts (good/bad/suspicious/unknown) with confidence & risk scores |
| `url_tags` | Tags attached to observed URLs (brand_seen, hosting_provider, risk_level) |
| `url_analysis_queue` | Queue of URLs pending enrichment processing (priority-ordered) |
| `url_evidence` | Evidence items: whois age, DNS records, hosting provider, brand scores |
| `brand_impersonation_results` | Full brand impersonation detection output per URL |
| `tranco_domains` | Tranco top-1M domain rankings (used for confidence scoring) |
| `brand_candidates` | Auto-discovered brand identities (from page metadata/JSON-LD) |
| `brand_domains` | Domains associated with discovered brands (relationship tracking) |
| `domain_relationships` | Inter-domain relationships from page metadata (canonical, sameAs, org) |
| `domain_reputation` | Per-domain safe/bad observation counts with calculated boost levels |
| `domain_reputation_users` | Unique users who submitted observations per domain (dedup) |

### 2. `poseidon_threats.duckdb` (ThreatIntel)

| Table | Purpose |
|---|---|
| `threats` | Threat indicators (URLs, domains, IPs) from 8+ external feeds |
| `threat_tags` | Tags on threat indicators (e.g., malware family, target brand) |
| `threat_feed_state` | Last-updated timestamps and record counts per feed source |

### 3. `poseidon_messages.duckdb` (MessageMemory)

| Table | Purpose |
|---|---|
| `unsafe_messages` | Previously-detected unsafe messages with hashes, simhash, risk scores, summaries |
| `unsafe_message_tags` | Tags on unsafe messages (phishing, impersonation, secret_leak) |
| `unsafe_message_urls` | URL hashes associated with unsafe messages |
| `unsafe_message_similarity` | Similarity edges between unsafe messages (hamming distance + risk scores) |

---

## Threat Intelligence Feeds

8 **active** feed sources (plus 18 **commented-out** sources in `sources.rs`):

| Feed | Threat Type | Format | Parser |
|---|---|---|---|
| URLhaus Online | malware_download | JSON | `parse_urlhaus_json` |
| PhishHunt | phishing | JSON | `parse_phishunt` |
| DestroyList | phishing, crypto_drainer | JSON string array | `parse_string_array` |
| MetaMask eth-phishing | crypto_drainer | JSON config | `parse_metamask` |
| spmedia Crypto Scam | crypto_drainer, pig_butchering | JSON | `parse_spmedia` |
| PhishTank | phishing | Gzip JSON | `parse_phishtank` |
| ThreatFox MISP | botnet_cc, malware_download | MISP directory | `parse_misp_directory` |
| BlackBook | malware_download, botnet_cc | Plain lines | `parse_plain_lines` |

### Supported Feed Formats (17 total)
`UrlhausZipJson`, `UrlhausJson`, `PhishuntJson`, `StringArrayJson`, `MetamaskJson`, `TweetFeedJson`, `SpmediaJson`, `PhishTankGzipJson`, `MispDirectory`, `MispManifest`, `HostsFile`, `PlainLines`, `TarGzLines`, `ViribackCsv`, `Adguard`

---

## Brand Detection System

### Offline (Deterministic) — `brand.rs`

- **Brand catalog**: Loaded from `data/brand_catalog.json` (Wikidata-sourced, 2000+ brands) or falls back to 22 hardcoded brands
- **Runtime brands**: Brands auto-discovered via page metadata (stored in `brand_candidates` + `brand_domains` tables) are merged at query time
- **Detection methods**:
  - Direct token matching in host/subdomain/path
  - Levenshtein distance typo detection (≤1 edit for ≤6 char tokens, ≤2 for larger)
  - Character normalization (`0→o`, `1→l`, `3→e`, `5→s`, `@→a`)
  - Phishing keyword detection (12 keywords: login, verify, secure, account, password, wallet, payment, invoice, support, update, suspended, recover)
  - Hosting provider awareness (11 providers)
  - Common word capping (apple, meta, box, x → capped at 35 without keywords)
  - Subdomain typo detection + ignored labels (www, mail, m, web, dev, app)
- **Brand aliases**: apple↔appleid, facebook↔fb, ledger↔ledgr/liveledgr, tmobile↔t-mobile

### Online (Identity Discovery) — `brand_detector.rs`

- Fetches page HTML and parses structured metadata:
  - JSON-LD `@type: Organization/Corporation/Brand`
  - OG meta tags (`og:site_name`, `og:title`)
  - `application-name`, `apple-mobile-web-app-title`
  - Canonical links, manifest links
  - Analytics IDs (GTM, GA, Clarity)
  - Forms + credential fields
- **Confidence scoring**:
  - Tranco rank: ≤10K → +45, ≤100K → +35, lower → +20
  - Local reputation boost: up to +15 (from `domain_reputation`)
  - Organization names (+25), OG/app name (+15)
  - Canonical domain matches (+15)
  - sameAs domains (+10)
  - Top-100 rank + canonical → +15 bonus
- **Brand candidate gating**: blocks candidates on hosting provider domains without authoritative signals, requires title-to-domain match for low-rank domains

### Online Enrichment — `online.rs`

- 3-way parallel DNS/WHOIS/HTTP using `std::thread::scope`
- **DNS**: Socket address resolution + IP provider detection (Cloudflare, Vercel, Fastly, GitHub Pages, AWS)
- **WHOIS**: Creation date parsing → domain age → risk if <30 days old, privacy protection detection
- **HTTP page analysis**:
  - Favicon SHA256 → match against 2000+ known brand favicons from `data/favicon_hashes.json`
  - Form analysis: password fields, OTP fields, card fields, external form actions
  - Title extraction, redirect chain tracking, final domain comparison
- **Online scoring** combines deterministic brand score + online evidence:
  - Credential fields + brand match → 90+
  - Favicon match → 85+
  - External form action + credentials → bump
  - Brand in URL + recent WHOIS → bump
  - Weak/no evidence + old domain → cap at 35
  - No brand/ no page brand match → cap at 40

---

## Domain Reputation System

Per-domain reputation tracking via user observations:

| Table | Tracks |
|---|---|
| `domain_reputation` | `safe_observations` counter, `bad_observations` counter |
| `domain_reputation_users` | Unique users per domain (prevents one user from inflating) |

**Boost levels** (used as confidence modifier in brand detection):
- 250+ safe observations → +15 boost
- 75+ safe observations → +10 boost
- 25+ safe observations → +5 boost
- Any bad observation → 0 boost (reset)

**Flow**: When a message is scored:
- `Allow` + risk < 35 → increment safe observations (per unique user)
- `Block│WarnB` + risk ≥ 75 → increment bad observations
- When safe boost ≥ 10 → auto-enqueue URL for brand learning analysis

---

## Message Memory (Simhash Similarity)

The `message_memory` module detects repeated or similar phishing messages:

1. **Normalization**: lowercase, email→`<email>`, digits→`<num>`, normalize whitespace
2. **Redaction**: secrets→`<secret>`, credit cards→`<card>`, phones→`<phone>` (for storage)
3. **SHA256 hash**: exact match lookup
4. **Simhash64**: 64-bit fuzzy hash with token weighting:
   - High weight (4): url, login, verify, account, password, wallet, payment
   - Medium weight (3): urgent, suspended, immediately, secure, update
   - Default weight (1): everything else
5. **Hamming distance** search: scan up to 5,000 recent messages, threshold ≤ 12
6. **Risk adjustment**: distance ≤ 3 → +35, ≤ 8 → +20, ≤ 12 → +10

---

## Benchmark Suite

### Brand Detection Benchmarks
- `benchmark-brand` (offline): 27 test cases, measures accuracy/precision/recall/F1 + speed (1000 iterations)
- `benchmark-online-brand` (online): 29 real URLs, measures accuracy + per-case timing breakdowns
- `benchmark-brand-learning`: 8 known URLs, tests brand identity discovery pipeline

### Phishing Detection Benchmarks
- `benchmark-phishing`: Built-in dataset (`data/benchmarks/phishing_messages.jsonl`, ~500 rows)
- `benchmark-phishing-full`: Downloads `cybersectony/PhishingEmailDetectionv2.0` from HuggingFace (200K rows)
- `benchmark-phishing-full-online`: Same but with online URL enrichment enabled
- `download-phishing-benchmark`: Standalone downloader for the HF dataset
- **DB isolation**: Creates temp DuckDB files at `/tmp/poseidon_bench_*` unless `POSEIDON_BENCHMARK_PERSIST_DB` is set
- **Configurable**: `POSEIDON_BENCHMARK_LIMIT`, `POSEIDON_BENCHMARK_OFFSET`, `POSEIDON_BENCHMARK_AI`, `POSEIDON_BENCHMARK_DATASET`

### Message Memory Benchmark
- `benchmark-message-memory`: Seeds a "PayPal verification" message, then tests similarity lookup

---

## Key Architectural Patterns

1. **Zero HTTP framework** — the API server is a raw `TcpListener` with manual HTTP/1.1 parsing (no actix/hyper/warp)
2. **DuckDB everywhere** — 3 separate DuckDB databases (urls, threats, messages), all using `bundled` mode, with `SET preserve_insertion_order=false` for perf
3. **Thread::scope for parallelism** — `std::thread::scope()` for structured concurrency: scoring engine runs AI parallel with URL scan, online enrichment runs DNS/WHOIS/HTTP in parallel
4. **Dual LLM backend** — supports Ollama API and OpenAI-compatible endpoints; auto-builds and manages llama.cpp server lifecycle
5. **Simhash for fuzzy matching** — 64-bit weighted simhash with Hamming distance for cross-message similarity detection
6. **Env-configurable** — 30+ `POSEIDON_*` environment variables control all paths, models, intervals, and limits
7. **SHA256 identity hashing** — all URLs, domains, users are stored as SHA256 hashes (privacy by design)
8. **Incremental brand learning** — discovers brand identities from page metadata at runtime, stores them as runtime brands for future matching without updates to the static catalog
9. **Appender-based bulk inserts** — DuckDB `appender` API for efficient bulk threat feed ingestion in a single transaction

---

## CLI Subcommands (Entry Points)

| Command | Function | Purpose |
|---|---|---|
| _(no args)_ | `api::serve()` | Start HTTP API server |
| `worker` | `enrich::process_pending()` | Process URL enrichment queue |
| `benchmark-brand` | `benchmark::run_brand_benchmark()` | Offline brand detection accuracy |
| `benchmark-online-brand` | `online_benchmark::run_online_brand_benchmark()` | Online enrichment accuracy |
| `benchmark-message-memory` | `message_memory::run_benchmark()` | Simhash similarity test |
| `benchmark-phishing` | `phishing_benchmark::run()` | Full phishing benchmark (built-in data) |
| `benchmark-phishing-full` | `phishing_benchmark::run_full()` | Full benchmark (HF 200K, offline) |
| `benchmark-phishing-full-online` | `phishing_benchmark::run_full_online()` | Full benchmark (HF 200K, online) |
| `download-phishing-benchmark` | `phishing_benchmark::download_huggingface_dataset()` | Download HF dataset |
| `benchmark-brand-learning` | `brand_detector::run_real_page_benchmark()` | Test brand identity discovery |
| `inspect-brand-learning` | `url_db::print_brand_learning_summary()` | Print learned brand tables |
| `enqueue-url <url>` | `url_db::enqueue_unknown()` | Manually queue URL for analysis |
| `detect-brand-url <url>` | `brand_detector::detect_brand_identity_with_reputation()` | Test brand detection on one URL |
| `detect-impersonation-url <url>` | `brand::analyse_with_runtime_brands()` | Test impersonation with runtime brands |
| `observe-safe-url <url> [count] [user_prefix]` | `url_db::observe_domain_reputation()` | Record safe observations |
| `inspect-domain-reputation <domain>` | `url_db::print_domain_reputation()` | Print domain reputation stats |

---

## Environment Variables

### Core Configuration
| Variable | Default | Purpose |
|---|---|---|
| `POSEIDON_API_ADDR` | `127.0.0.1:8080` | HTTP API listen address |
| `POSEIDON_URL_DB_PATH` | `poseidon_urls.duckdb` | URL database file path |
| `POSEIDON_THREAT_DB_PATH` | _(in-memory)_ | Threat intel database file path |
| `POSEIDON_THREAT_UPDATE_MINUTES` | `30` | Feed refresh interval (clamped to ≥30) |
| `POSEIDON_MESSAGE_DB_PATH` | `poseidon_messages.duckdb` | Message memory database path |
| `POSEIDON_STORE_RAW_UNSAFE` | `true` | Store raw message text for unsafe messages |
| `POSEIDON_WORKER_LIMIT` | `100` | URLs to process per worker invocation |

### LLM Configuration
| Variable | Default | Purpose |
|---|---|---|
| `POSEIDON_LLM_ENDPOINT` | _(unset → Ollama)_ | OpenAI-compatible API base URL |
| `POSEIDON_OLLAMA_MODEL` | `gemma4:e2b` | Model for message assessment |
| `POSEIDON_OLLAMA_SUMMARY_MODEL` | _(same as assessment)_ | Model for danger summaries |
| `POSEIDON_LLAMA_HOST` | `127.0.0.1` | llama.cpp server host |
| `POSEIDON_LLAMA_PORT` | `8081` | llama.cpp server port |
| `POSEIDON_LLAMA_MODEL` | _(auto-detect)_ | Path to specific GGUF model file |
| `POSEIDON_MODELS_DIR` | `models/` | Directory to search for .gguf files |
| `POSEIDON_LLAMA_CTX` | `8192` | Context size for llama.cpp |
| `POSEIDON_LLAMA_THREADS` | _(auto)_ | CPU threads for llama.cpp |
| `POSEIDON_LLAMA_GPU_LAYERS` | `99` | GPU layers for llama.cpp |
| `POSEIDON_LLAMA_VULKAN` | `OFF` | Enable Vulkan GPU acceleration |
| `POSEIDON_LLAMA_VULKAN_SDK` | `/tmp/vulkan-sdk` | Vulkan SDK path for build |
| `POSEIDON_LLAMA_BUILD_JOBS` | _(auto)_ | Parallel build jobs |
| `POSEIDON_LLAMA_AUTO_SETUP` | `true` | Auto-build/start llama.cpp |

### Brand Detection Configuration
| Variable | Default | Purpose |
|---|---|---|
| `POSEIDON_BRAND_CATALOG_PATH` | `data/brand_catalog.json` | Offline brand catalog file |
| `POSEIDON_BRAND_CATALOG_OUT` | `data/brand_catalog.json` | Brand catalog output path (scraper) |
| `POSEIDON_FAVICON_HASHES_PATH` | `data/favicon_hashes.json` | Known brand favicon SHA256 hashes |
| `POSEIDON_FAVICON_HASHES_OUT` | `data/favicon_hashes.json` | Favicon hashes output path (scraper) |
| `POSEIDON_BRAND_INFO_OUT` | `data/brand_info.json` | Brand info output path (scraper) |
| `POSEIDON_WIKIDATA_MIN_SITELINKS` | `10` | Minimum sitelinks for Wikidata brands |
| `POSEIDON_BRAND_LIMIT` | `2000` | Maximum Wikidata brands to fetch |
| `POSEIDON_FAVICON_WORKERS` | `24` | Parallel favicon scraper workers |
| `POSEIDON_MAX_DOMAINS_PER_BRAND` | `4` | Max domains to scrape per brand |

### Tranco Importer
| Variable | Default | Purpose |
|---|---|---|
| `POSEIDON_TRANCO_CSV_PATH` | _(download)_ | Local Tranco CSV for offline import |
| `POSEIDON_TRANCO_URL` | Tranco online | Tranco download URL |
| `POSEIDON_TRANCO_LIMIT` | _(all)_ | Max domains to import |

### Benchmark Configuration
| Variable | Default | Purpose |
|---|---|---|
| `POSEIDON_BENCHMARK_DATASET` | _(built-in)_ | Custom benchmark JSONL path |
| `POSEIDON_BENCHMARK_LIMIT` | _(all)_ | Max benchmark cases to process |
| `POSEIDON_BENCHMARK_OFFSET` | `0` | Skip N cases from start |
| `POSEIDON_BENCHMARK_AI` | `false` | Enable LLM during benchmark |
| `POSEIDON_BENCHMARK_PERSIST_DB` | `false` | Keep temp benchmark databases |
| `POSEIDON_HF_DATASET` | `cybersectony/PhishingEmailDetectionv2.0` | HF dataset ID |
| `POSEIDON_HF_CONFIG` | `default` | HF dataset config |
| `POSEIDON_HF_SPLITS` | `train,validation,test` | Comma-separated HF dataset splits |
| `POSEIDON_HF_PAGE_DELAY_MS` | `750` | Delay between HF API calls |
| `POSEIDON_HF_RETRIES` | `8` | Max retries for HF API |
| `POSEIDON_HF_RETRY_SECONDS` | `10` | Initial retry delay (exponential backoff) |
| `POSEIDON_DOWNLOAD_LIMIT` | _(all)_ | Max rows for HF dataset download |

---

## Standalone CLI Tools

### `brand_scraper.rs` (`cargo run --bin brand_scraper`)
- Queries **Wikidata SPARQL** for brands/businesses with websites
- Generates `data/brand_catalog.json` (brand→domains mapping)
- Discovers related domains by fetching page metadata (canonical, org, sameAs links)
- Scrapes favicon.ico from each brand domain → SHA256 hashes → `data/favicon_hashes.json`
- Multi-threaded (configurable worker count), with social media/exclude domain filtering

### `tranco_importer.rs` (`cargo run --bin tranco_importer`)
- Downloads the **Tranco top-1M** domain list (via ZIP)
- Imports into `poseidon_urls.duckdb` `tranco_domains` table
- Supports local CSV fallback and configurable row limits
- Used by `brand_detector.rs` for confidence scoring (Tranco rank as authority signal)
