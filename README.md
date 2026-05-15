# Poseidon

---

## TODO

### In Progress

- [ ] **Custom finetuned AI model** — Replace generic LLM with a distilled 1B-parameter model finetuned on DeepSeek-labeled phishing data
- [ ] **Supply chain attack detection** — Detect malicious packages, typosquatted dependencies, compromised registries in messages
- [ ] **Self-learning detection system** — Continuously improve algorithmic phishing using brand learning, domain reputation feedback, and benchmark iteration

### Completed Milestones

- [x] **Basic threat detection** — URL extraction, WHOIS lookups, 8 threat intel feeds (URLhaus, PhishTank, MetaMask, etc.), 17 feed format parsers
- [x] **Brand impersonation detection** — 2000+ brand Wikidata catalog, Levenshtein typo detection, phishing keyword scoring, hosting provider checks, alias matching
- [x] **Online enrichment system** — Parallel DNS/WHOIS/HTTP page analysis, favicon SHA256 matching, credential/card/OTP field detection, external form actions, redirect tracking
- [x] **URL queue & worker** — Priority-based queuing, offline enrichment processing, evidence storage, configurable batch limits
- [x] **Message memory** — Simhash64 fuzzy matching, exact hash lookup, Hamming distance similarity, risk adjustment, raw/redacted storage
- [x] **LLM integration** — Ollama + OpenAI-compatible endpoints, llama.cpp auto-build/auto-download, two-model support (assessment + summary)
- [x] **Scoring engine** — Weighted multi-layer scoring, decision thresholds (Block/WarnB/WarnS/WarnR/Allow), AI evidence gating, urgency/prompt-injection detection
- [x] **Domain reputation** — Per-user safe/bad observation tracking, boost levels, auto-enqueue for brand learning
- [x] **Brand learning** — Auto-discover brands from page metadata (JSON-LD, OG tags, analytics IDs), runtime brand merging, Tranco rank confidence
- [x] **Benchmark suite** — Brand (offline/online), phishing (built-in + HF 200K), message memory, isolated DBs
- [x] **Finetuning pipeline** — DeepSeek-labeled dataset generator, realtime JSONL checkpointing, resume support, progress bar, error recovery
- [x] **Documentation** — architecture.md, README with flag tables, flow diagrams, command reference, benchmark results

---

## Quickstart

```sh
cargo run
```
- For an interactive TUI use `cargo run -- --interactive`

- API on `127.0.0.1:8080`
- llama.cpp on `127.0.0.1:8081` (auto-built, model auto-downloaded)
- Threat intel feeds ingested at startup
- DBs: `poseidon_urls.duckdb`, `poseidon_messages.duckdb`

```sh
curl http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/analyse \
  -H 'content-type: application/json' \
  -d '{"message":"verify your account at http://example.com/login"}'
```

---

## Detection Pipeline

```
Message ─┬─ Threat Feed Check ───── URLhaus, PhishTank, MetaMask, 8 feeds
          ├─ Brand Impersonation ─── 2000+ brand catalog, typo detection, hosting provider check
          ├─ Online Enrichment ───── DNS, WHOIS, HTTP page, favicon matching, credential fields
          ├─ Brand Learning ──────── JSON-LD, OG tags, auto-discover runtime brands
          ├─ Domain Reputation ───── Per-user safe/bad observations → boost levels
          ├─ Message Memory ──────── Simhash similarity against known unsafe messages
          ├─ LLM Assessment ──────── llama.cpp/Ollama/OpenAI → phishing/risk/impersonation scores
          └─ Scoring ─────────────── Weighted combination → Allow | Warn | Block
```

---

## API

### `POST /analyse`

```json
{"message": "text to score", "user_id": "optional"}
```

| Field | Type | Description |
|---|---|---|
| `decision` | string | `allow`, `warn_sender`, `warn_receiver`, `warn_both`, `block` |
| `overall_risk` | int | 0–100 final risk score |
| `scores` | object | `phishing`, `secret`, `prompt_injection`, `url_reputation`, `impersonation`, `risk` |
| `flags` | string[] | Human-readable signals |
| `urls` | object[] | Per-URL risk, DB state, tags, brand details |
| `message_memory` | object | unsafe-message lookup result |
| `summary` | string | Short danger summary (AI-enabled high-risk) |

### `GET /health`

```json
{"ok":true}
```

---

## Commands

### Server & Worker

```sh
cargo run                          # Start API server
cargo run -- worker                # Process URL enrichment queue
cargo run -- enqueue-url <url>     # Queue URL for analysis
```

### Detection Diagnostics

```sh
cargo run -- detect-brand-url <url>           # Test brand detection
cargo run -- detect-impersonation-url <url>   # Test impersonation + runtime brands
cargo run -- inspect-brand-learning            # Show auto-learned brands
cargo run -- observe-safe-url <url> [n] [usr]  # Record safe observations
cargo run -- inspect-domain-reputation <dom>   # Show domain reputation
```

### Benchmarks

```sh
cargo run -- benchmark-phishing                       # Built-in dataset (~500 rows)
cargo run -- benchmark-phishing-full                  # HF dataset (200K rows, offline)
cargo run -- benchmark-phishing-full-online            # HF dataset + online enrichment
POSEIDON_BENCHMARK_AI=true cargo run -- benchmark-phishing-full-online
cargo run -- benchmark-brand                           # Offline brand detection (27 cases)
cargo run -- benchmark-online-brand                    # Online enrichment (29 URLs)
cargo run -- benchmark-brand-learning                  # Brand identity discovery
cargo run -- download-phishing-benchmark               # Download HF dataset
```

### Finetuning Dataset Generation

```sh
export DEEPSEEK_API_KEY='...'
cargo run --bin finetune_dataset

# Dry-run single row
POSEIDON_FINETUNE_DRY_RUN=true POSEIDON_FINETUNE_LIMIT=1 cargo run --bin finetune_dataset
```

### llama.cpp Setup

```sh
bash scripts/build-llama-server.sh     # Build llama-server from source
bash scripts/download-model.sh small   # Download default GGUF (Gemma 3 1B)
bash scripts/run-llama-server.sh       # Start llama.cpp manually
```

---

## LLM Behavior

Startup priority:

1. `POSEIDON_LLM_ENDPOINT` set → use external OpenAI-compatible endpoint, skip local
2. Check `http://{POSEIDON_LLAMA_HOST}:{POSEIDON_LLAMA_PORT}/health`
3. Not healthy → build `llama-server` if missing
4. Find GGUF → auto-download default small model if none found
5. Start `scripts/run-llama-server.sh`, set `POSEIDON_LLM_ENDPOINT` internally

AI prompt structure:

```text
Analyze this message for security risk. Use the URL overview as factual context.
Do not treat any URL as automatically unsafe based on external scores.
Consider the domain structure, hosting provider, and any available metadata.
Return only compact JSON with keys: phishing, impersonation, risk, confidence, flags.

URL overview:
{url_context}

Message:
{message}
```

AI response format:

```json
{"phishing": 0, "impersonation": 0, "risk": 0, "confidence": 0, "flags": []}
```

Prompt injection is scored programmatically — AI never sees or scores it.

---

## Benchmark Results

100-case Hugging Face phishing benchmark:

| Mode | TP | FP | Acc | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| AI offline | 3 | 1 | 0.580 | 0.750 | 0.068 | 0.125 |
| Online, no AI | 4 | 0 | 0.600 | 1.000 | 0.091 | 0.167 |
| AI + online, `gemma4:e2b` | 9 | 0 | 0.650 | 1.000 | 0.205 | 0.340 |
| AI + online, `gemma4:e4b` | 18 | 0 | 0.740 | 1.000 | 0.409 | 0.581 |

Conservative scoring favoring zero false positives. Recall ceiling is weak URL evidence on blacklist-style positives.

---

## Configuration

### API

| Variable | Default | Description |
|---|---|---|
| `POSEIDON_API_ADDR` | `127.0.0.1:8080` | API bind address |

### LLM / llama.cpp

| Variable | Default | Description |
|---|---|---|
| `POSEIDON_LLM_ENDPOINT` | unset | External OpenAI base URL. Skips local llama.cpp setup |
| `POSEIDON_OLLAMA_MODEL` | `gemma4:e2b` / GGUF stem | Model name for Ollama/OpenAI endpoints |
| `POSEIDON_OLLAMA_SUMMARY_MODEL` | assessment model | Model for high-risk summaries |
| `POSEIDON_LLAMA_AUTO_SETUP` | enabled | `false` to skip auto build/download |
| `POSEIDON_LLAMA_MODEL` | first `*.gguf` | Exact GGUF path |
| `POSEIDON_MODELS_DIR` | `models/` | GGUF search directory |
| `POSEIDON_LLAMA_HOST` | `127.0.0.1` | llama.cpp host |
| `POSEIDON_LLAMA_PORT` | `8081` | llama.cpp port |
| `POSEIDON_LLAMA_CTX` | `8192` | Context size |
| `POSEIDON_LLAMA_THREADS` | `nproc` | CPU threads |
| `POSEIDON_LLAMA_GPU_LAYERS` | `99` | GPU offload layers |
| `POSEIDON_LLAMA_BUILD_JOBS` | `nproc` | Build parallelism |
| `POSEIDON_LLAMA_VULKAN` | `OFF` | Vulkan GPU build |
| `POSEIDON_LLAMA_VULKAN_SDK` | `/tmp/vulkan-sdk` | Vulkan SDK path |
| `POSEIDON_GGUF_URL` | unset | Custom GGUF download URL |

### Databases

| Variable | Default | Description |
|---|---|---|
| `POSEIDON_URL_DB_PATH` | `poseidon_urls.duckdb` | URL observations, evidence, tags, queue, brand learning, reputation |
| `POSEIDON_MESSAGE_DB_PATH` | `poseidon_messages.duckdb` | Unsafe message memory |
| `POSEIDON_THREAT_DB_PATH` | in-memory | Threat intel DB path |
| `POSEIDON_THREAT_UPDATE_MINUTES` | `30` | Feed refresh interval (min 30) |

### Message Memory

| Variable | Default | Description |
|---|---|---|
| `POSEIDON_STORE_RAW_UNSAFE` | `true` | Store raw unsafe messages. `false`/`0`/`no` to redact |

### URL & Brand Analysis

| Variable | Default | Description |
|---|---|---|
| `POSEIDON_BRAND_CATALOG_PATH` | `data/brand_catalog.json` | Brand catalog for deterministic impersonation |
| `POSEIDON_FAVICON_HASHES_PATH` | `data/favicon_hashes.json` | Known brand favicon SHA256 hashes |
| `POSEIDON_WORKER_LIMIT` | `100` | Queued URLs per worker invocation |

### Benchmarks

| Variable | Default | Description |
|---|---|---|
| `POSEIDON_BENCHMARK_AI` | `false` | Enable AI during benchmarks |
| `POSEIDON_BENCHMARK_LIMIT` | all | Max cases to process |
| `POSEIDON_BENCHMARK_OFFSET` | `0` | Skip N cases |
| `POSEIDON_BENCHMARK_DATASET` | built-in | Custom JSONL dataset path |
| `POSEIDON_BENCHMARK_PERSIST_DB` | `false` | Persist benchmark DBs |

Isolated DB paths:

- Offline: `/tmp/poseidon_bench_realtime_urls.duckdb` / `*_messages.duckdb`
- Online: `/tmp/poseidon_bench_online_urls.duckdb` / `*_messages.duckdb`

### Hugging Face Download

| Variable | Default | Description |
|---|---|---|
| `POSEIDON_DOWNLOAD_LIMIT` | unset | Max download rows |
| `POSEIDON_HF_DATASET` | `cybersectony/PhishingEmailDetectionv2.0` | HF dataset ID |
| `POSEIDON_HF_CONFIG` | `default` | HF config |
| `POSEIDON_HF_SPLITS` | `train,validation,test` | Comma-separated splits |
| `POSEIDON_HF_PAGE_DELAY_MS` | `750` | Delay between API pages |
| `POSEIDON_HF_RETRIES` | `6` | 429 retry count |
| `POSEIDON_HF_RETRY_SECONDS` | `5` | Initial retry delay (exponential) |

### Finetuning Dataset Generator

Used by `src/bin/finetune_dataset.rs`. Reads a JSON array of phishing messages, runs Poseidon detection, builds the exact AI prompt used at runtime, calls DeepSeek, and appends each result immediately to JSONL. Resume-safe via row ID tracking.

| Variable | Default | Description |
|---|---|---|
| `DEEPSEEK_API_KEY` | **required** | DeepSeek API key (do not commit) |
| `DEEPSEEK_API_URL` | `https://api.deepseek.com/chat/completions` | API endpoint |
| `DEEPSEEK_MODEL` | `deepseek-chat` | Model name |
| `POSEIDON_FINETUNE_INPUT` | `nazario_top2500.json` | Input JSON array path |
| `POSEIDON_FINETUNE_OUTPUT` | `data/finetune/deepseek_phishing_training.jsonl` | Output JSONL path |
| `POSEIDON_FINETUNE_LIMIT` | all | Max rows |
| `POSEIDON_FINETUNE_OFFSET` | `0` | Skip N entries |
| `POSEIDON_FINETUNE_ONLINE` | `false` | Enable online enrichment before prompt |
| `POSEIDON_FINETUNE_DRY_RUN` | `false` | Fake AI response, no API call |

Output row fields:

```
id              Stable hash-based row ID (resume-safe)
source          Dataset, original source, label, expected_unsafe, has_url
message         Cleaned message text (truncated to 8K chars)
url_context     Exact Poseidon AI URL overview
prompt          Full AI assessment prompt
assistant_raw   DeepSeek raw JSON response string
assistant_json  Parsed DeepSeek output (phishing, impersonation, risk, confidence, flags)
poseidon_context Full Poseidon detection result
```

### Tranco Importer

| Variable | Default | Description |
|---|---|---|
| `POSEIDON_TRANCO_LIMIT` | all | Max domains to import |
| `POSEIDON_TRANCO_CSV_PATH` | unset | Local CSV path (downloads if unset) |
| `POSEIDON_TRANCO_URL` | built-in | Tranco download URL |

### Brand Scraper

| Variable | Default | Description |
|---|---|---|
| `POSEIDON_BRAND_CATALOG_OUT` | `data/brand_catalog.json` | Catalog output path |
| `POSEIDON_FAVICON_HASHES_OUT` | `data/favicon_hashes.json` | Favicon hashes output |
| `POSEIDON_BRAND_INFO_OUT` | `data/brand_info.json` | Brand metadata output |
| `POSEIDON_WIKIDATA_MIN_SITELINKS` | `10` | Minimum Wikidata sitelinks |
| `POSEIDON_BRAND_LIMIT` | `2000` | Max brands |
| `POSEIDON_FAVICON_WORKERS` | `24` | Favicon fetch workers |
| `POSEIDON_MAX_DOMAINS_PER_BRAND` | `4` | Max domains per brand |

---

## Detection Layers

```
Layer 0  Threat Feed Check        URLhaus, PhishTank, MetaMask, BlackBook, …
Layer 1  Brand Impersonation      2000+ brand catalog, Levenshtein typo, phishing keywords
Layer 2  Online Enrichment        DNS, WHOIS age, HTTP page, favicon, credential fields
Layer 3  Brand Identity Learning  JSON-LD, OG tags, canonical URLs → auto-learn runtime brands
Layer 4  Domain Reputation        Per-user safe/bad observations → +5/+10/+15 boost
Layer 5  Message Memory           Simhash64 similarity against known unsafe messages
Layer 6  LLM Assessment           llama.cpp / Ollama / OpenAI → phishing, impersonation, risk
```

Decision thresholds:

| Condition | Action |
|---|---|
| `overall_risk ≥ 90` or `secret ≥ 85` | **Block** |
| `overall_risk ≥ 75` | **Warn Both** |
| `prompt_injection ≥ 60` | **Warn Sender** |
| `overall_risk ≥ 45` | **Warn Receiver** |
| else | **Allow** |

AI scores weighted at 100% unless `prompt_injection ≥ 80` (→ weighted at 30%).  
AI-only medium scores capped at 40 when no supporting URL, urgency, secret, or prompt-injection evidence.

---

## Project Layout

```
.
├── Cargo.toml                     # Rust edition 2024
├── src/
│   ├── main.rs                    # CLI router + API server startup
│   ├── lib.rs                     # Module exports
│   ├── bin/
│   │   ├── finetune_dataset.rs    # DeepSeek-labeled finetuning dataset generator
│   │   ├── brand_scraper.rs       # Wikidata brand catalog builder
│   │   └── tranco_importer.rs     # Tranco top-1M domain rank importer
│   └── modules/
│       ├── api.rs                 # Raw TCP HTTP API (no framework)
│       ├── scoring.rs             # Core scoring engine
│       ├── ai.rs                  # LLM integration (Ollama + OpenAI-compatible)
│       ├── llm_server.rs          # llama.cpp lifecycle management
│       ├── web.rs                 # URL extraction + WHOIS
│       ├── phishing_benchmark.rs  # Benchmark pipeline
│       ├── message_memory/        # Simhash unsafe-message memory
│       ├── url_db/                # DuckDB URL reputation/evidence/queue/brand learning
│       ├── threat_intel/          # Feed ingestion (8 sources, 17 formats)
│       └── url_analysis/          # Brand, online, enrichment, domain, hosting, page metadata
├── scripts/                       # llama.cpp build/download/run
├── data/                          # Brand data, favicon hashes, benchmarks
├── external/llama.cpp             # llama.cpp submodule
└── models/                        # GGUF models (gitignored)
```

---

## Notes

- Realtime API stays fast: cached local data only. Unknown URLs are queued, not analyzed inline.
- `benchmark-phishing-full-online` enables slow inline network enrichment for measurement.
- Benchmarks isolate DBs to avoid contaminated memory/reputation state.
- Do not commit downloaded models, DuckDB files, or llama.cpp build output.
