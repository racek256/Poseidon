# Poseidon

Poseidon is a local-first phishing defense engine that combines deterministic security signals with a fine-tuned 1B LLM. It analyzes messages, extracts URLs, checks threat intelligence, detects brand impersonation, learns new brand identities, remembers unsafe messages, and returns an explainable risk decision.

---

## TODO

### In Progress

- [ ] **Self-learning detection system** - Continuously improve algorithmic phishing using brand learning, domain reputation feedback, and benchmark iteration
- [ ] **AI supply chain attack detection** - Use AI to flag supply chain attacks before they hit public vulnerability databases

### Completed Milestones

- [x] **Custom finetuned AI model** - Replace generic LLM with a distilled 1B-parameter model finetuned on DeepSeek-labeled phishing data
- [x] **Supply chain attack detection** - Detect malicious packages, typosquatted dependencies, compromised registries in messages
- [x] **Basic threat detection** - URL extraction, WHOIS lookups, 8 threat intel feeds, 17 feed format parsers
- [x] **Brand impersonation detection** - 2000+ brand Wikidata catalog, typo detection, phishing keyword scoring, hosting provider checks, alias matching
- [x] **Online enrichment system** - Parallel DNS/WHOIS/HTTP page analysis, favicon SHA256 matching, credential/card/OTP field detection, external form actions, redirect tracking
- [x] **URL queue & worker** - Priority-based queuing, offline enrichment processing, evidence storage, configurable batch limits
- [x] **Message memory** - Simhash64 fuzzy matching, exact hash lookup, Hamming distance similarity, risk adjustment, raw/redacted storage
- [x] **LLM integration** - Ollama + OpenAI-compatible endpoints, llama.cpp auto-build/auto-download, two-model support
- [x] **Scoring engine** - Weighted multi-layer scoring, decision thresholds, AI evidence gating, urgency/prompt-injection detection
- [x] **Domain reputation** - Per-user safe/bad observation tracking, boost levels, auto-enqueue for brand learning
- [x] **Brand learning** - Auto-discover brands from page metadata, runtime brand merging, Tranco rank confidence
- [x] **Benchmark suite** - Brand, phishing, message memory, isolated DBs
- [x] **Benchmark ~1B models** - Evaluated Gemma 3 1B, Theseus v1, and Theseus v2 on phishing benchmarks
- [x] **Finetuning pipeline** - DeepSeek-labeled dataset generator, realtime JSONL checkpointing, resume support, progress bar, error recovery

---

## Why It Matters

Phishing filters often fail in two opposite ways: they miss suspicious messages that use new infrastructure, or they over-block legitimate business mail. Poseidon targets the middle ground: high-confidence warnings backed by interpretable evidence.

Core idea: do not trust one signal. Combine URL reputation, brand impersonation, known threat feeds, message memory, deterministic heuristics, and a small fine-tuned model that understands email context.

---

## Highlights

- **Fine-tuned local model:** `Theseus-v3-1e`, based on Gemma 3 1B, trained on filtered DeepSeek-labeled phishing/email assessments.
- **Strong precision improvement:** false positives dropped from `33` to `0` on the email benchmark versus base Gemma 3 1B.
- **Runs locally:** llama.cpp OpenAI-compatible server, no hosted model required for inference.
- **Auto-downloads the model:** fresh clones fetch `Theseus-v3-1e.gguf` on first local inference setup.
- **Explainable scoring:** every result includes scores, flags, URL evidence, brand details, and final decision.
- **Brand impersonation detection:** 2000+ brand catalog, typo matching, hosting-provider detection, favicon evidence, learned runtime brands.
- **Threat intelligence:** URLhaus, PhishTank, MetaMask, phishing blocklists, and more.
- **Self-improving memory:** exact and fuzzy unsafe-message lookup using Simhash64.
- **Benchmark-first workflow:** isolated benchmark DBs, reproducible JSONL datasets, AI/no-AI comparison paths.

---

## What can you verify

- Run one command to start the API. Or start interactive version with `cargo run -- --interactive`
- Send a phishing message and inspect the full evidence trail.
- Run the default benchmark and reproduce the fine-tuned model score.
- Swap the GGUF model path to compare base Gemma against Theseus.
- Inspect the training dataset generator and benchmark implementation in `src/bin/finetune_dataset.rs` and `src/modules/phishing_benchmark.rs`.

---

## Demo

Start the API:

```sh
cargo run --release
```

Analyze a phishing-style message:

```sh
curl -s http://127.0.0.1:8080/analyse \
  -H 'content-type: application/json' \
  -d '{"message":"Security alert: your Microsoft mailbox will close today. Sign in at https://microsoft-verify.pages.dev/account to keep access."}'
```

Run the showcase benchmark:

```sh
POSEIDON_BENCHMARK_AI=true cargo run --release -- benchmark-phishing
```

Interactive TUI:

```sh
cargo run --release -- --interactive
```

---

## Benchmark Win

Default benchmark: `data/benchmarks/phishing_emails_with_urls_100.jsonl`.

This dataset is email-shaped: sender, recipient, subject, body, and URLs. It matches the distribution used for Theseus fine-tuning better than URL-only blacklists.

| Model | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `Theseus-v3-1e` fine-tuned | 48 | 0 | 46 | 6 | **0.940** | **1.000** | **0.889** | **0.941** |
| `Theseus-v2-1e` fine-tuned | 38 | 0 | 46 | 16 | 0.840 | **1.000** | 0.704 | 0.826 |
| `Theseus-1e-q4_k_m` v1 fine-tuned | 46 | 14 | 32 | 8 | 0.780 | 0.767 | 0.852 | 0.807 |
| `gemma-3-1b-it-Q4_K_M` base | 48 | 33 | 13 | 6 | 0.610 | 0.593 | 0.889 | 0.711 |

Fine-tuning impact over base Gemma 3 1B:

| Metric | Base Gemma | Theseus-v3-1e | Change |
|---|---:|---:|---:|
| Accuracy | 0.610 | **0.940** | +0.330 |
| Precision | 0.593 | **1.000** | +0.407 |
| False positives | 33 | **0** | -33 |
| F1 | 0.711 | **0.941** | +0.230 |

* Precision: how often unsafe warnings are correct.
* Accuracy: how often all safe/unsafe decisions are correct.

The fine-tuned model eliminates false positives on the email benchmark while sharply improving recall, total accuracy, and F1.

---

## How It Works

```
Message
  |- Extract URLs
  |- Check threat feeds
  |- Detect brand impersonation
  |- Query URL reputation and learned brand DB
  |- Compare against unsafe-message memory
  |- Ask local fine-tuned LLM for phishing/risk/impersonation scores
  `- Combine evidence into Allow | Warn Receiver | Warn Both | Block
```

Detection layers:

| Layer | Purpose |
|---|---|
| Threat feeds | Known malicious URLs/domains from public intelligence sources |
| Brand impersonation | Detect fake Microsoft, PayPal, Apple, GitHub, bank, and shipping domains |
| Online enrichment | DNS, WHOIS, HTTP metadata, forms, favicon matches, redirect evidence |
| Brand learning | Discover new legitimate brand identities from page metadata |
| Domain reputation | Per-user safe/bad observations with reputation boost levels |
| Message memory | Exact hash + Simhash fuzzy matching for repeated attacks |
| Local LLM | Context-aware phishing/risk assessment using a fine-tuned 1B model |

---

## Model

`Theseus-v3` is a QLoRA fine-tune of Gemma 3 1B Instruct. It was trained to emit compact JSON security assessments:

```json
{"phishing": 0, "impersonation": 0, "risk": 0, "confidence": 0, "flags": []}
```

Training pipeline:

1. Build exact runtime prompts from email messages and Poseidon URL context.
2. Label prompts with DeepSeek JSON responses.
3. Filter rows where DeepSeek's unsafe decision disagrees with the source label.
4. Fine-tune Gemma 3 1B using Unsloth QLoRA on ROCm/Colab-compatible settings.
5. Merge adapter, convert to GGUF, quantize to Q4_K_M for llama.cpp inference.

Generated model files are stored in `models/` and intentionally gitignored.

---

## Quickstart

```sh
cargo run --release
```

Runtime defaults:

- API: `127.0.0.1:8080`
- llama.cpp: `127.0.0.1:8081`
- URL DB: `poseidon_urls.duckdb`
- Message memory DB: `poseidon_messages.duckdb`

If no local LLM endpoint is configured, Poseidon can build/start llama.cpp and auto-download `Theseus-v3-1e.gguf` into `models/`.

---

## API

### `POST /analyse`

```json
{"message": "text to score", "user_id": "optional"}
```

| Field | Type | Description |
|---|---|---|
| `decision` | string | `allow`, `warn_sender`, `warn_receiver`, `warn_both`, `block` |
| `overall_risk` | int | 0-100 final risk score |
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
POSEIDON_BENCHMARK_AI=true cargo run -- benchmark-phishing
# Default model benchmark: email-shaped phishing dataset

POSEIDON_BENCHMARK_DATASET=data/benchmarks/phishing_messages.jsonl cargo run -- benchmark-phishing
# Synthetic URL/brand dataset (110 rows)

cargo run -- benchmark-phishing-full                   # HF dataset (200K rows, offline)
cargo run -- benchmark-phishing-full-online            # HF dataset with online enrichment
POSEIDON_BENCHMARK_AI=true cargo run -- benchmark-phishing-full-online
```

Other benchmarks:

```sh
cargo run -- benchmark-brand             # Offline brand detection
cargo run -- benchmark-online-brand      # Online enrichment
cargo run -- benchmark-brand-learning    # Brand identity discovery
cargo run -- download-phishing-benchmark # Download HF dataset

POSEIDON_HF_DATASET='puyang2025/seven-phishing-email-datasets' POSEIDON_HF_SPLITS=train POSEIDON_HF_REQUIRE_URLS=true cargo run -- download-phishing-benchmark data/benchmarks/phishing_emails_with_urls.jsonl
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
bash scripts/download-model.sh         # Download default GGUF (Theseus-v3-1e)
bash scripts/download-model.sh small   # Download base Gemma 3 1B fallback
bash scripts/run-llama-server.sh       # Start llama.cpp manually
```

---

## LLM Behavior

Startup priority:

1. `POSEIDON_LLM_ENDPOINT` set -> use external OpenAI-compatible endpoint, skip local
2. Check `http://{POSEIDON_LLAMA_HOST}:{POSEIDON_LLAMA_PORT}/health`
3. Not healthy -> build `llama-server` if missing
4. Find GGUF -> auto-download default small model if none found
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

Prompt injection is scored programmatically; AI never sees or scores it.

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
| `POSEIDON_LLAMA_MODEL` | preferred local GGUF | Exact GGUF path |
| `POSEIDON_MODELS_DIR` | `models/` | GGUF search directory |
| `POSEIDON_LLAMA_HOST` | `127.0.0.1` | llama.cpp host |
| `POSEIDON_LLAMA_PORT` | `8081` | llama.cpp port |
| `POSEIDON_LLAMA_CTX` | `8192` | Context size |
| `POSEIDON_LLAMA_THREADS` | `nproc` | CPU threads |
| `POSEIDON_LLAMA_GPU_LAYERS` | `99` | GPU offload layers |
| `POSEIDON_LLAMA_BUILD_JOBS` | `nproc` | Build parallelism |
| `POSEIDON_LLAMA_VULKAN` | `OFF` | Vulkan GPU build |
| `POSEIDON_LLAMA_VULKAN_SDK` | `/tmp/vulkan-sdk` | Vulkan SDK path |
| `POSEIDON_GGUF_URL` | Theseus-v3 release URL | Custom GGUF download URL |

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
| `POSEIDON_BENCHMARK_DATASET` | email benchmark | Custom JSONL dataset path |
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
Layer 0  Threat Feed Check        URLhaus, PhishTank, MetaMask, BlackBook, etc.
Layer 1  Brand Impersonation      2000+ brand catalog, Levenshtein typo, phishing keywords
Layer 2  Online Enrichment        DNS, WHOIS age, HTTP page, favicon, credential fields
Layer 3  Brand Identity Learning  JSON-LD, OG tags, canonical URLs -> auto-learn runtime brands
Layer 4  Domain Reputation        Per-user safe/bad observations -> +5/+10/+15 boost
Layer 5  Message Memory           Simhash64 similarity against known unsafe messages
Layer 6  LLM Assessment           llama.cpp / Ollama / OpenAI -> phishing, impersonation, risk
```

Decision thresholds:

| Condition | Action |
|---|---|
| `overall_risk >= 90` or `secret >= 85` | **Block** |
| `overall_risk >= 75` | **Warn Both** |
| `prompt_injection >= 60` | **Warn Sender** |
| `overall_risk >= 45` | **Warn Receiver** |
| else | **Allow** |

AI scores weighted at 100% unless `prompt_injection >= 80` (weighted at 30%).
AI-only medium scores capped at 40 when no supporting URL, urgency, secret, or prompt-injection evidence.

---

## Project Layout

```
.
|-- Cargo.toml                     # Rust edition 2024
|-- src/
|   |-- main.rs                    # CLI router + API server startup
|   |-- lib.rs                     # Module exports
|   |-- bin/
|   |   |-- finetune_dataset.rs    # DeepSeek-labeled finetuning dataset generator
|   |   |-- brand_scraper.rs       # Wikidata brand catalog builder
|   |   `-- tranco_importer.rs     # Tranco top-1M domain rank importer
|   `-- modules/
|       |-- api.rs                 # Raw TCP HTTP API (no framework)
|       |-- scoring.rs             # Core scoring engine
|       |-- ai.rs                  # LLM integration (Ollama + OpenAI-compatible)
|       |-- llm_server.rs          # llama.cpp lifecycle management
|       |-- web.rs                 # URL extraction + WHOIS
|       |-- phishing_benchmark.rs  # Benchmark pipeline
|       |-- message_memory/        # Simhash unsafe-message memory
|       |-- url_db/                # DuckDB URL reputation/evidence/queue/brand learning
|       |-- threat_intel/          # Feed ingestion (8 sources, 17 formats)
|       `-- url_analysis/          # Brand, online, enrichment, domain, hosting, page metadata
|-- scripts/                       # llama.cpp build/download/run
|-- data/                          # Brand data, favicon hashes, benchmarks
|-- external/llama.cpp             # llama.cpp submodule
`-- models/                        # GGUF models (gitignored)
```

---

## Notes

- Realtime API stays fast: cached local data only. Unknown URLs are queued, not analyzed inline.
- `benchmark-phishing-full-online` enables slow inline network enrichment for measurement.
- Benchmarks isolate DBs to avoid contaminated memory/reputation state.
- Do not commit downloaded models, DuckDB files, or llama.cpp build output.
