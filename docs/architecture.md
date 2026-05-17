# Poseidon — Architecture

## Overview

Poseidon is a **phishing detection / message security scoring system** built in Rust for the AT&T Hackathon. It analyzes text messages for security threats — phishing URLs, brand impersonation, secrets leakage, and prompt injection — using multiple detection layers: **local threat intelligence feeds**, **URL enrichment (DNS/WHOIS/HTTP page analysis)**, **offline brand matching (typo detection + brand catalog)**, **online brand identity discovery (page metadata/JSON-LD)**, **domain reputation tracking**, **unsafe message memory (simhash similarity)**, and a **local LLM** for AI assessment.

**Total: 44+ Rust source files, ~12,500+ lines of code across one library crate, one binary entrypoint, and three standalone CLI binaries.**

---

## Project Structure

```
Poseidon/
├── Cargo.toml                        # Rust project config (edition 2024)
├── architecture.md                   # This file
├── README.md                         # Project README
├── nazario_top2500.json              # Phishing messages dataset (finetuning input)
├── src/
│   ├── lib.rs                        # Library root (exports modules)
│   ├── main.rs                       # Binary entrypoint (CLI router + server)
│   ├── bin/
│   │   ├── brand_scraper.rs          # Standalone: Wikidata brand catalog builder
│   │   ├── tranco_importer.rs        # Standalone: Tranco top-1M domain rank importer
│   │   └── finetune_dataset.rs       # Standalone: DeepSeek-labeled finetuning dataset generator
│   └── modules/
│       ├── mod.rs                    # Module declarations
│       ├── api.rs                    # HTTP API server (raw TCP)
│       ├── scoring.rs                # Core scoring engine
│       ├── ai.rs                     # LLM integration (Ollama + OpenAI-compatible)
│       ├── llm_server.rs             # llama.cpp server lifecycle management
│       ├── tui/                      # Terminal User Interface (ratatui + crossterm)
│       │   ├── mod.rs                # Module root, exports app, bridge, colors, state, trackers
│       │   ├── app.rs                # Main TUI event loop, rendering, server thread management
│       │   ├── bridge.rs             # Global OnceLock bridge for server→TUI communication
│   │   ├── colors.rs             # Theme: near-black bg, surface shades, muted blue accent
│       │   ├── state.rs              # Thread-safe TuiState (Arc<Mutex<TuiState>>)
│       │   └── trackers.rs           # PerformanceTrackers with atomic counters
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
│       ├── url_analysis/
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
│       └── supply_chain/
│           ├── mod.rs                # Supply chain scanner (WarningLevel, PackageAnalysis, SupplyChainScanner)
│           ├── lockfile.rs           # Lockfile parser (16 types: Cargo.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, poetry.lock, Pipfile.lock, requirements.txt, go.sum, Gemfile.lock, composer.lock, pom.xml, maven-lockfile.json, gradle.lockfile, packages.lock.json, pubspec.lock, mix.lock)
│           ├── osv.rs                # OSV API client (batch vulnerability queries)
│           ├── registry.rs           # Registry metadata checks (PyPI, npm, crates.io)
│           ├── typosquat.rs          # Typosquatting detection (Levenshtein + mutation patterns)
│           ├── deep_analysis.rs      # Deep analysis pipeline (10-step with LLM commit analysis)
│           ├── get_dependency_git_url.rs  # Git URL resolution from registries
│           ├── commit_fetcher.rs     # Commit fetching from GitHub/GitLab/Bitbucket
│           ├── universal_llm_comms.rs    # Unified LLM client (OpenAI, ZEN, GO, Ollama)
│           └── analysis_cache.rs     # TTL-based caching for git URLs and commits
├── scripts/
│   ├── build-llama-server.sh         # Builds llama.cpp from source
│   ├── download-model.sh             # Downloads GGUF models (Theseus/default + fallback variants)
│   ├── run-llama-server.sh           # Starts llama.cpp server
│   └── finetune/                     # Unsloth QLoRA finetuning pipeline
│       ├── install.sh                # ROCm-aware Unsloth + dependencies install
│       ├── requirements.txt          # Python packages (unsloth, transformers, trl, peft)
│       └── train.py                  # QLoRA training script → GGUF export
├── data/
│   ├── benchmarks/                   # Benchmark datasets (JSONL)
│   │   ├── phishing_emails_with_urls_100.jsonl # Built-in email phishing benchmark (bundled)
│   │   ├── phishing_messages.jsonl   # Synthetic URL/brand phishing benchmark
│   │   ├── phishing_hf_500.jsonl     # HuggingFace sample (500 rows)
│   │   └── phishing_hf_200k.jsonl    # Full HuggingFace dataset (200K rows)
│   ├── brand_catalog.json            # Wikidata-sourced brand catalog
│   ├── brand_info.json               # Brand metadata from scraper
│   ├── favicon_hashes.json           # Known brand favicon SHA256 hashes
│   └── finetune/                     # Finetuning output directory (created on-demand)
│       └── deepseek_phishing_training.jsonl  # DeepSeek-labeled training data (generated at runtime)
├── models/                           # GGUF model files (gitignored)
└── external/
    ├── llama.cpp/                    # Git submodule for local inference
    └── unsloth/                      # Git submodule for QLoRA finetuning (uninitialized, git submodule update --init to populate)
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
                ├─ POST /analyse    → scoring::analyse(message, user_id, ...)
                │     │  Request JSON: { "message": "...", "user_id": "..." }
                │     │  (see Execution Flow for full pipeline)
                │
                ├─ POST /supplychain/quick-analyze  → supply_chain::handle_quick_analyze(body)
                │     │  Request JSON: { "lockfile_content": "...", "filename": "Cargo.lock" }
                │     │  Returns: { "overall_sentiment": "...", "packages": [...], "summary": "..." }
                │
                ├─ POST /supplychain/deep-analyze   → supply_chain::handle_deep_analyze(body)
                │     │  Request JSON: { "lockfiles": [{"filename": "...", "content": "..."}] }
                │     │  Returns: hierarchical dependency tree with quick analysis + LLM commit analysis
                │
                └─ GET  /supplychain/status         → supply_chain::handle_status()
                      │  Returns: { "status": "ready", "service": "supply_chain_scanner", "version": "0.1.0", ... }

      For POST /analyse requests, the scoring pipeline executes:

      POST /analyse → scoring::analyse(message, user_id, ...)
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

The AI URL context builder (`scoring::ai_url_context()`) is public and produces a concise textual overview of each URL's threat intel status, hosting provider, and evidence summary. It does **not** include "Known in DB" or "Queued for analysis" flags in the LLM prompt — those fields remain in the JSON response output but were removed from the context to keep the LLM focused on factual evidence rather than internal DB state.

---

## TUI (Terminal User Interface)

The TUI provides an **interactive terminal-based interface** for testing and monitoring the phishing detection system in real-time. It runs the API server in a background thread while displaying live statistics, logs, and analysis results.

Design is dark, minimal, futuristic — inspired by opencode's CLI:
- Near-black background with subtle surface shades for panel separation
- Squared corners, no rounded borders
- Gray borders and separators, color reserved for status/data
- Header bar + footer status bar framing the content
- Grid-like layout with generous internal padding

### Launch

```bash
cargo run -- --interactive
```

The `--interactive` flag routes execution to `modules::tui::run_tui()` instead of `api::serve()`.

### Layout

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POSEIDON  ● ready  step: AI Assessment (30%)                     (header)   │
├──────────────────────────────────────┬───────────────────────────────────────┤
│                                      │  Metrics                              │
│  Output                              │  Requests  42                         │
│  Decision: block                     │  Avg Delay 234.56ms                   │
│  Overall Risk: 92/100                │  Msgs/sec  0.85                       │
│                                      │  Uptime    00:05:23                   │
│  Scores:                             │  Speed     12.50 t/s                  │
│  Phishing............. 85            │                                       │
│  Impersonation....... 30            ├───────────────────────────────────────┤
│  Prompt Injection.... 0             │  Logs                                  │
│  Secret.............. 0             │  [14:32:01] TUI started                │
│  URL Reputation...... N/A           │  [14:32:05] User input                 │
│  Risk................ 75            │  [14:32:06] POST /analyse              │
│                                      │  [14:32:07] Analysis complete          │
│  Flags:                              │                                       │
│    • suspected_brand_impersonation   │                                       │
│    • suspicious_url                  │                                       │
│                                      │                                       │
│  URLs: 1 found                       │                                       │
│    example.com/login (risk: 85)      │                                       │
│                                      │                                       │
│ ─────────────────────────────────── │                                       │
│  ⏳ AI Assessment (30%)             │                                       │
│ ─── Input ──────────────────────── │                                       │
│ › verify account at example.com     │                                       │
├──────────────────────────────────────┴───────────────────────────────────────┤
│ q:quit  enter:send  ↑↓:scroll  esc:quit                        (footer)    │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Header Bar

The top bar shows the app name **POSEIDON** with a status indicator (● green=ready, ● yellow=pending), current processing step, and progress percentage. Styled on a `SURFACE` (#1a1a1a) background.

### Left Column (70% Width)

| Section | Purpose |
|---|---|
| **Output** | Formatted JSON analysis results — decision, overall risk, per-category scores, flags, URLs, message memory, summary. Uses `format_response()` to render structured color-coded output. Scrollable with ↑/↓. Auto-scrolls to bottom on new results |
| **Step Indicator** | Single-line status showing current processing step (e.g., "⏳ AI Assessment (30%)") |
| **Input** | Text input for messages. Shows `›` prompt when idle, `⏳` when request is pending. Bordered with a separator line above |

### Right Column (30% Width)

| Section | Purpose |
|---|---|
| **Metrics** | Request count, average delay, messages/second, uptime (HH:MM:SS), generation speed (tokens/sec). Styled on `SURFACE_HIGH` (#252525) background |
| **Logs** | Reversed-chronological timestamped log entries from server initialization, threat feed updates, errors. Styled on `BG` (#0f0f0f) background |

### Footer Bar

Bottom status bar showing keyboard shortcuts:
- `q` / `esc`: quit
- `enter`: send message for analysis
- `↑` / `↓`: scroll output

### JSON Response Formatting

Analysis responses are parsed and rendered as structured, color-coded output:

| Element | Color Source |
|---|---|
| Decision label | `TEXT_DIM` (#808080) |
| Decision value (block) | `WARNING` (#ffa726) |
| Decision value (allow) | `SUCCESS` (#4caf50) |
| Overall Risk (≥90) | RGB(255, 87, 87) — bright red |
| Overall Risk (≥75) | `WARNING` (#ffa726) |
| Section headers | `HIGHLIGHT` (#5c8aff) |
| Score values ≥90 | Bright red |
| Score values ≥75 | Warning color |
| Summary text | `TEXT_DIM` italic |

### Input Processing Flow

```
User types message → presses Enter
         │
         ├─ Clear input buffer
         ├─ Set request_pending = true
         │
         ├─ Spawn thread:
         │   ├─ POST http://{addr}/analyse
         │   │   Body: {"message": "...", "user_id": "tui"}
         │   │
         │   ├─ Server processes via scoring::analyse()
         │   │   ├─ bridge::post_step() → updates step indicator
         │   │   ├─ bridge::post_progress() → updates progress percent
         │   │   ├─ bridge::post_output() → appends analysis results
         │   │   └─ bridge::track_request_start/end() → updates metrics
         │   │
         │   └─ On response:
         │       ├─ Set request_pending = false
         │       ├─ If HTTP 200 → parse JSON via format_response(), append to output
         │       └─ If HTTP error → show "⚠ Request failed: HTTP {status}"
         │
         └─ TUI re-renders with updated state
             ├─ Output auto-scrolls to bottom on new content
             └─ format_response() converts JSON → color-coded structured display
```

### Analysis Steps (Posted via Bridge)

The scoring engine posts 6 steps with progress percentages, displayed inline in the header bar and step indicator:

| Step | Progress | Description |
|---|---|---|
| 1. Message Memory Lookup | 5% | Simhash similarity search for previously seen unsafe messages |
| 2. URL Scanning | 15% | Threat feed lookup, URL DB observation, brand impersonation |
| 3. AI Assessment | 30% | LLM analysis for phishing/impersonation/risk scoring |
| 4. Security Scoring | 60% | Prompt injection, secrets, urgency pattern detection |
| 5. Decision | 90% | Combine scores → Block/Warn/Allow decision |
| 6. Complete | 100% | Analysis finished, output results |

The header bar displays the current step (e.g., "step: AI Assessment (30%)") with a status dot (● green=ready, ● yellow=pending). The step indicator line below the output shows the same in a condensed form.

### Color Scheme

| Color | Hex | Usage |
|---|---|---|
| Background (`BG`) | `#0f0f0f` | Main background, log panel |
| Surface (`SURFACE`) | `#1a1a1a` | Input area, header/footer background |
| Surface High (`SURFACE_HIGH`) | `#252525` | Metrics panel background |
| Border (`BORDER`) | `#484848` | Panel borders, separator lines |
| Border Dim (`BORDER_DIM`) | `#3c3c3c` | Column separator |
| Highlight (`HIGHLIGHT`) | `#5c8aff` | Section headers, key data, keyboard shortcuts |
| Highlight Dim (`HIGHLIGHT_DIM`) | `#3a5a9e` | Progress percentage, secondary highlights |
| Text (`TEXT`) | `#d4d4d4` | Primary text content |
| Text Bright (`TEXT_BRIGHT`) | `#eeeeee` | App name, input buffer text |
| Text Dim (`TEXT_DIM`) | `#808080` | Labels, descriptions, less important info |
| Success (`SUCCESS`) | `#4caf50` | Allow decisions, ready status |
| Warning (`WARNING`) | `#ffa726` | Block/warn decisions, pending status |
| Error (`ERROR`) | `#ef5350` | Error status indicators |

### Bridge Architecture

The TUI bridge enables **cross-thread communication** between the server/scoring engine and the TUI rendering loop:

```
┌─────────────────────────────────────────────────────────────────┐
│  TUI Thread (ratatui event loop)                                │
│  - Renders UI every 50ms                                        │
│  - Handles keyboard input                                       │
│  - Holds Arc<Mutex<TuiState>>                                   │
└─────────────────────────────────────────────────────────────────┘
                          ▲
                          │ bridge::set_tui_state()
                          │
┌─────────────────────────┴───────────────────────────────────────┐
│  Global OnceLock<Arc<Mutex<TuiState>>>                          │
│  - bridge.rs                                                    │
│  - is_interactive() check                                       │
│  - post_step(), post_progress(), post_log(), post_output()      │
└─────────────────────────┬───────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ API Thread   │  │ Scoring      │  │ Server       │
│ (POST /ana…  │  │ Engine       │  │ Init         │
│              │  │              │  │              │
│ post_output()│  │ post_step()  │  │ bridge::log()│
│ track_*()    │  │ post_prog()  │  │ bridge::elog()│
└──────────────┘  └──────────────┘  └──────────────┘
```

**Key Design:**

- **OnceLock**: Lazy initialization, set once when TUI starts
- **Arc<Mutex<T>>**: Thread-safe shared ownership
- **NO-OP when inactive**: All `post_*()` functions check `is_interactive()` — if TUI is not running, they do nothing
- **Dual-mode logging**: `bridge::log()` posts to TUI if active, otherwise `println!`; `bridge::elog()` posts to TUI or `eprintln!`

### Performance Trackers

`PerformanceTrackers` uses **atomic counters** for lock-free metrics:

| Metric | Type | Calculation |
|---|---|---|
| `request_count` | `AtomicU64` | Total requests processed |
| `total_request_time_ms` | `AtomicU64` | Cumulative request duration |
| `avg_delay_ms` | `f64` | `total_request_time_ms / request_count` |
| `msgs_per_second` | `f64` | `request_count / elapsed_seconds` |
| `uptime` | `Duration` | Time since tracking started |

Trackers are initialized via `bridge::init_trackers()` when TUI starts. Stats are updated on every `track_request_end()` call.

### State Management

`TuiState` holds all UI state:

```rust
pub struct TuiState {
    pub current_step: String,           // "AI Assessment (30%)"
    pub progress_percent: f64,          // 0.0 - 100.0
    pub logs: Vec<String>,              // Last 100 timestamped logs
    pub output: Vec<String>,            // Last 200 output lines
    pub input_buffer: String,           // Current user input
    pub generation_speed: f64,          // Tokens/sec or msgs/sec
    pub is_running: bool,               // Event loop active
    pub placeholder_stats: HashMap<…>,  // Right sidebar stats
    pub request_pending: bool,          // Waiting for API response
}
```

**Thread Safety:** All access is via `Arc<Mutex<TuiState>>`. The TUI event loop locks state for reading during render, and server threads lock for writing during analysis.

### Output Redirection

All modules use `bridge::log()` / `bridge::elog()` instead of direct `println!` / `eprintln!`:

```rust
// Before:
println!("Threat feed updated: {} records", count);

// After:
bridge::log(&format!("Threat feed updated: {} records", count));
```

**Behavior:**
- **TUI active**: Message appears in right-panel logs
- **TUI inactive**: Message prints to stdout/stderr as before

This enables **seamless switching** between interactive and headless modes without code changes.

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
├──────────────────────────────────────────────────┤
│  Layer 7: Supply Chain Analysis                  │
│  Lockfile parsing (16 formats, 10 ecosystems),   │
│  OSV vulnerability checks, registry metadata,    │
│  typosquatting detection, AI commit analysis     │
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
- Sets `max_tokens`: 256 when JSON format requested, 64 otherwise

### Public Prompt Building

The assessment prompt is exposed as a public function `assessment_prompt(message, url_context)` in `ai.rs`, reused by:
- The main `assess_message_with_url_context()` function (runtime API path)
- The `finetune_dataset` binary (to build exact training prompts matching runtime behavior)

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

## Supply Chain Attack Detection

The `supply_chain` module detects malicious packages, typosquatted dependencies, and compromised registries through a two-tier analysis pipeline: **Quick Analysis** for fast vulnerability/typosquat detection, and **Deep Analysis** for AI-powered commit-level inspection.

### Supported Ecosystems and Lockfile Types

The scanner supports **10 package ecosystems** via **16 lockfile formats**:

| Ecosystem | Lockfile Types |
|---|---|
| **Rust (crates.io)** | `Cargo.lock` |
| **JavaScript/TypeScript (npm)** | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| **Python (PyPI)** | `poetry.lock`, `Pipfile.lock`, `requirements.txt` |
| **Go** | `go.sum` |
| **Ruby (RubyGems)** | `Gemfile.lock` |
| **PHP (Packagist)** | `composer.lock` |
| **Java (Maven)** | `pom.xml`, `maven-lockfile.json`, `gradle.lockfile` |
| **.NET (NuGet)** | `packages.lock.json` |
| **Dart (Pub)** | `pubspec.lock` |
| **Elixir (Hex)** | `mix.lock` |

### Warning Levels

Packages are classified into five severity tiers:

| Level | Trigger Conditions |
|---|---|
| **Safe** | No issues detected |
| **Low** | Minor concerns (e.g., low-severity OSV vulnerabilities) |
| **Medium** | Moderate risk (e.g., medium-severity vulnerabilities, recently published packages) |
| **High** | Significant risk (e.g., high-severity vulnerabilities, typosquatting matches) |
| **Critical** | Severe risk (e.g., yanked packages, critical vulnerabilities, confirmed malicious patterns) |

### Quick Analysis Pipeline

The quick analysis pipeline runs in **~1-5 seconds** for typical lockfiles and performs three checks:

```
1. Lockfile Parsing
   ├─ detect_lockfile_type(filename) → LockfileType + Ecosystem
   └─ parse_lockfile(filename, content) → Vec<Package { name, version, ecosystem }>

2. OSV Vulnerability Check (batch API)
   ├─ Build OSVPackage queries for all packages
   ├─ POST https://api.osv.dev/v1/querybatch (max 1000 per batch)
   ├─ Fetch full vulnerability details via GET /v1/vulns/{id}
   └─ Extract severity → WarningLevel mapping

3. Registry Metadata Check
   ├─ PyPI: GET /pypi/{name}/{version}/json → yanked, upload_time, vulnerabilities
   ├─ npm: GET /registry.npmjs.org/{name} → deprecated, time.published
   ├─ crates.io: GET /api/v1/crates/{name}/{version} → yanked, updated_at
    └─ Warnings: yanked (Critical), <7 days old (Medium)

4. Typosquatting Detection
   ├─ Load popular packages for ecosystem (npm: 100+, PyPI: 100+, crates: 100+)
   ├─ Generate mutations: omitted chars, doubled chars, swapped adjacent, similar chars (0↔o, 1↔l, etc.), rn↔m, hyphen/underscore insertion, case variants
   ├─ Levenshtein distance fallback (≤2 edits)
   └─ Warning: High for any typosquat match

5. Aggregate Results
   ├─ Per-package: warning_level (max of all checks), issues[]
   ├─ Overall sentiment: highest warning level across all packages
   └─ Summary: "{critical} critical, {high} high, {medium} medium, {low} low, {safe} safe"
```

**Output format:**
```json
{
  "overall_sentiment": "high",
  "packages": [
    {
      "name": "lodash",
      "version": "4.17.21",
      "ecosystem": "npm",
      "warning_level": "safe",
      "issues": []
    }
  ],
  "summary": "0 critical, 0 high, 0 medium, 0 low, 42 safe"
}
```

### Deep Analysis Pipeline

The deep analysis pipeline performs a **10-step hierarchical inspection** with AI-powered commit analysis:

```
1. Receive Lockfile(s)
   └─ Input: Vec<(filename, content)> (supports multiple lockfiles)

2. Parse Dependencies
   ├─ parse_lockfile() per lockfile
   └─ Deduplicate by (name, version, ecosystem)

3. Build Dependency Hierarchy
   ├─ Track parent references (simplified: all packages treated as top-level)
   └─ Identify top-level vs transitive dependencies

4. Quick Analysis on All Packages
   ├─ OSV batch query (reuse Quick Analysis pipeline)
   ├─ Registry checks (PyPI/npm/crates.io)
   └─ Typosquat detection

5. Filter by WarningLevel
   ├─ Rejected: WarningLevel::Critical → excluded from deep analysis
   └─ Passing: Safe/Low/Medium/High → proceed to git URL lookup

6. Git URL Lookup (passing top-level deps only)
   ├─ GitUrlFinder::find_git_url_with_hosting(name, registry)
   ├─ Registry-specific API queries:
   │  ├─ crates.io: /api/v1/crates/{name} → crate.repository
   │  ├─ npm: /registry.npmjs.org/{name} → repository.url
   │  ├─ PyPI: /pypi/{name}/json → info.home_page or project_urls
   │  ├─ RubyGems: /api/v1/gems/{name}.json → source_code_uri
   │  ├─ Packagist: /packages/{name}.json → repository
   │  ├─ Maven: search.maven.org + POM parsing → scm>url
   │  ├─ NuGet: /v3/registration5-semver1/{name}/index.json → projectUrl
   │  ├─ Pub: /api/packages/{name} → latest.pubspec.repository
   │  └─ Hex: /api/packages/{name} → meta.links.github
   ├─ URL normalization: strip git+, git@→https, .git suffix, git://→https://
   └─ Platform detection: github, gitlab, bitbucket, self-hosted

7. Fetch Recent Commits (per unique git URL)
   ├─ CommitFetcher::fetch_commits(git_url, platform, count=10)
   ├─ Platform-specific APIs:
   │  ├─ GitHub: GET /repos/{owner}/{repo}/commits + GET /commits/{sha} (diff)
   │  ├─ GitLab: GET /projects/{id}/repository/commits + GET /diff
   │  ├─ Bitbucket: GET /repositories/{owner}/{repo}/commits + diff href
   │  └─ Self-hosted: Gitea/GitLab CE compatible endpoints
   ├─ Rate limiting: 100-200ms delay between requests, 429 retry with 1s backoff
   ├─ Diff truncation: max 100KB per commit
   └─ Output: Vec<CommitInfo { hash, author, date, message, diff }>

8. AI Commit Analysis (max 15 parallel)
   ├─ LLM prompt: security-focused analysis for obfuscation, backdoors, network calls, install script changes, credential access, binary blobs
   ├─ LLM client: universal_llm_comms::llm_completion()
   │  ├─ Providers: OpenAI, ZEN, GO, Ollama
   │  ├─ Config: LLM_PROVIDER, PROVIDER_API_KEY, LLM_MODEL env vars
   │  └─ Retry: 3 attempts with exponential backoff (1s, 2s, 4s)
   ├─ Response parsing: { verdict: "allow|suspicious|malicious", confidence: 0.0-1.0, reasons: [], suspicious_patterns: [] }
   └─ Retry on parse failure: one additional LLM call

9. Aggregate Per-Package Verdicts
   ├─ CommitVerdict aggregation: Malicious > Suspicious > Allow
   ├─ Confidence: average of all commit confidences
   ├─ Reasons: deduplicated union of all commit reasons
   └─ Output: CommitAnalysisResult { verdict, confidence, reasons, commits_analyzed, commit_details[] }

10. Hierarchical JSON Output
    ├─ DependencyNode per package: name, version, ecosystem, is_top_level, parent_refs[]
    ├─ Quick analysis: verdict (pass/rejected), warning_level, issues[]
    ├─ Git metadata: git_url, hosting_platform, no_git_url_notice
    ├─ Commit analysis: verdict, confidence, reasons, commits_analyzed, commit_details[]
    ├─ Children: nested DependencyNode[] (future: full tree reconstruction)
    └─ Summary: total_packages, flagged, threshold, cache_hits, api_calls_made
```

**Output format:**
```json
{
  "analysis_timestamp": "1747612345.678Z",
  "lockfile_sources": ["Cargo.lock"],
  "summary": {
    "total_packages": 42,
    "flagged": 2,
    "threshold": "Critical",
    "cache_hits": 15,
    "api_calls_made": 8
  },
  "tree": [
    {
      "name": "serde",
      "version": "1.0.197",
      "ecosystem": "crates.io",
      "quick_analysis": {
        "verdict": "pass",
        "warning_level": "safe",
        "issues": []
      },
      "git_url": "https://github.com/serde-rs/serde",
      "hosting_platform": "github",
      "no_git_url_notice": false,
      "commit_analysis": {
        "verdict": "allow",
        "confidence": 0.92,
        "reasons": ["No suspicious patterns detected", "Version bump only"],
        "commits_analyzed": 10,
        "commit_details": [
          {
            "hash": "abc123...",
            "verdict": "allow",
            "confidence": 0.95,
            "reasons": ["Documentation update"],
            "suspicious_patterns": []
          }
        ]
      },
      "children": [],
      "error": null
    }
  ]
}
```

### Caching Strategy

The `AnalysisCache` module provides TTL-based caching to reduce API calls:

| Cache Type | Key Format | TTL | Cached Value |
|---|---|---|---|
| Git URL | `{registry}:{name}` (e.g., `npm:lodash`) | 1 hour | `Option<String>` (git URL or None) |
| Commits | `{git_url}` (e.g., `github.com/lodash/lodash`) | 1 hour | `Vec<CommitInfo>` |

**Metrics:** `len()`, `hit_count()`, `miss_count()` exposed via `/supplychain/status`.

### Environment Variables

| Variable | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | _(required)_ | LLM provider: `openai`, `zen`, `go`, `ollama` |
| `PROVIDER_API_KEY` | _(required for non-ollama)_ | API key for LLM authentication |
| `LLM_MODEL` | _(required)_ | Model identifier (e.g., `gpt-4o`, `llama3.2`) |
| `GITHUB_TOKEN` | _(optional)_ | GitHub API token for higher rate limits |
| `GITLAB_TOKEN` | _(optional)_ | GitLab API token for private repos |
| `GITEA_TOKEN` | _(optional)_ | Self-hosted Gitea API token (falls back to `GIT_TOKEN`)

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
- `benchmark-phishing`: Built-in email dataset (`data/benchmarks/phishing_emails_with_urls_100.jsonl`, 100 rows)
- `benchmark-phishing-full`: Downloads `cybersectony/PhishingEmailDetectionv2.0` from HuggingFace (200K rows)
- `benchmark-phishing-full-online`: Same but with online URL enrichment enabled
- `download-phishing-benchmark`: Standalone downloader for the HF dataset
- **DB isolation**: Creates temp DuckDB files at `/tmp/poseidon_bench_*` unless `POSEIDON_BENCHMARK_PERSIST_DB` is set
- **Configurable**: `POSEIDON_BENCHMARK_LIMIT`, `POSEIDON_BENCHMARK_OFFSET`, `POSEIDON_BENCHMARK_AI`, `POSEIDON_BENCHMARK_DATASET`
- **Minimum cases**: Requires at least 1 case (lowered from 100) — allows small test runs for rapid iteration

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
10. **TUI bridge pattern** — `OnceLock<Arc<Mutex<T>>>` for global, thread-safe state sharing between server and TUI; all `post_*()` functions are NO-OPs when TUI is inactive
11. **Output redirection** — all modules use `bridge::log()` / `bridge::elog()` for dual-mode output: posts to TUI log window when interactive, falls back to stdout/stderr when headless
12. **Finetuning dataset pipeline** — `finetune_dataset` binary runs Poseidon detection on each message, builds the exact runtime prompt, labels via DeepSeek, and appends to JSONL with stable SHA256 row IDs for resume-safe processing
13. **Unsloth QLoRA finetuning** — `scripts/finetune/train.py` uses Unsloth for 4-bit QLoRA training on the generated dataset, exports to GGUF for inference via llama.cpp
14. **Multi-ecosystem lockfile parsing** — single `parse_lockfile()` interface supports 16 lockfile formats across 10 ecosystems (Rust, npm, PyPI, Go, Ruby, PHP, Maven, NuGet, Dart, Elixir) with format-specific parsers
15. **Two-tier supply chain analysis** — Quick Analysis (OSV + registry + typosquat, ~1-5s) for fast screening, Deep Analysis (10-step pipeline with AI commit inspection) for high-risk packages
16. **TTL-based API caching** — `AnalysisCache` with 1-hour TTL for git URL lookups and commit histories, reducing redundant API calls with hit/miss metrics

---

## CLI Subcommands (Entry Points)

| Command | Function | Purpose |
|---|---|---|
| _(no args)_ | `api::serve()` | Start HTTP API server |
| _(no args) + `--interactive`_ | `modules::tui::run_tui()` | Start TUI with server in background thread |
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

### Finetuning Dataset Generator
| Variable | Default | Purpose |
|---|---|---|
| `DEEPSEEK_API_KEY` | _(required)_ | DeepSeek API key for labelling |
| `DEEPSEEK_API_URL` | `https://api.deepseek.com/chat/completions` | DeepSeek API endpoint |
| `DEEPSEEK_MODEL` | `deepseek-chat` | DeepSeek model name |
| `POSEIDON_FINETUNE_INPUT` | _(unset → nazario_top2500.json)_ | Input JSON array of phishing messages |
| `POSEIDON_FINETUNE_OUTPUT` | `data/finetune/deepseek_phishing_training.jsonl` | Output JSONL path |
| `POSEIDON_FINETUNE_LIMIT` | _(all)_ | Max rows to process |
| `POSEIDON_FINETUNE_OFFSET` | `0` | Skip N entries from start |
| `POSEIDON_FINETUNE_ONLINE` | `false` | Enable online URL enrichment before prompt |
| `POSEIDON_FINETUNE_DRY_RUN` | `false` | Skip DeepSeek API call, use fake response |

### Unsloth Finetuning (Python scripts/finetune/train.py)
| Variable | Default | Purpose |
|---|---|---|
| `POSEIDON_FINETUNE_DATASET` | `data/finetune/deepseek_phishing_training.jsonl` | JSONL training dataset |
| `POSEIDON_FINETUNE_OUTPUT_DIR` | `models/finetuned` | Output directory for adapter + GGUF |
| `POSEIDON_FINETUNE_MODEL` | `unsloth/gemma-3-1b-it-bnb-4bit` | Base model name |
| `POSEIDON_FINETUNE_EPOCHS` | `3` | Number of training epochs |
| `POSEIDON_FINETUNE_LR` | `2e-4` | Learning rate |
| `POSEIDON_FINETUNE_BATCH_SIZE` | `2` | Per-device batch size |
| `POSEIDON_FINETUNE_GRAD_ACCUM` | `4` | Gradient accumulation steps |
| `POSEIDON_FINETUNE_MAX_LEN` | `2048` | Max sequence length |
| `POSEIDON_FINETUNE_R` | `16` | LoRA rank |
| `POSEIDON_FINETUNE_ALPHA` | `16` | LoRA alpha |
| `POSEIDON_FINETUNE_DROPOUT` | `0.0` | LoRA dropout |
| `POSEIDON_FINETUNE_QUANT` | `4bit` | Quantization (4bit/8bit/None) |
| `POSEIDON_SKIP_GGUF` | `false` | Skip GGUF export after training |

---

## Standalone CLI Tools

### `finetune_dataset.rs` (`cargo run --bin finetune_dataset`)
- Reads phishing messages from a JSON array file (`nazario_top2500.json` by default)
- Runs Poseidon detection on each message to gather detection context + URL overview
- Constructs the exact `assessment_prompt()` used at runtime
- Calls DeepSeek API with the prompt to get an AI assessment
- Appends each result immediately to a JSONL file (`data/finetune/deepseek_phishing_training.jsonl`)
- **Resume-safe**: Tracks completed rows by stable SHA256-based row ID — skips already-processed rows on restart
- **Dry-run mode** (`POSEIDON_FINETUNE_DRY_RUN=true`): uses fake AI response, no API call
- Progress bar with success/error/skip counts using indicatif
- Configurable limit, offset, and online enrichment toggle
- Exponential backoff retry (2 attempts) for DeepSeek API failures

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
