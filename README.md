# Poseidon

Poseidon is a local-first message security engine for phishing, impersonation, prompt-injection, secret leakage, URL reputation, and unsafe-message memory.

It is intentionally modular:

- Realtime API: fast scoring with local threat intel, URL DB lookups, deterministic heuristics, message memory, and AI assessment.
- URL enrichment: slower DNS/WHOIS/HTTP/page analysis, either inline for benchmarks or queued for worker processing.
- AI: defaults to local llama.cpp with a GGUF model, with optional external OpenAI-compatible endpoint.
- Benchmarks: local and Hugging Face phishing benchmarks with isolated DuckDB databases by default.

## Quickstart

```sh
cargo run
```

Default behavior:

- API listens on `127.0.0.1:8080`.
- llama.cpp listens on `127.0.0.1:8081`.
- If no external LLM endpoint is configured, Poseidon builds `llama-server` if needed, downloads the default small GGUF if needed, starts llama.cpp, and points AI calls at it.
- URL and message-memory DBs are persisted as `poseidon_urls.duckdb` and `poseidon_messages.duckdb`.
- Threat intel defaults to in-memory DuckDB and refreshes every startup, with a minimum refresh interval of 30 minutes.

Health check:

```sh
curl http://127.0.0.1:8080/health
```

Analyze a message:

```sh
curl -s http://127.0.0.1:8080/analyse \
  -H 'content-type: application/json' \
  -d '{"user_id":"demo","message":"verify your account at http://example.com/login"}'
```

## API

### `GET /health`

Returns:

```json
{"ok":true}
```

### `POST /analyse` or `POST /analyze`

Request body:

```json
{
  "user_id": "optional-user-id",
  "message": "message text to score"
}
```

Response fields include:

- `decision`: `allow`, `warn_sender`, `warn_receiver`, `warn_both`, or `block`.
- `overall_risk`: final 0-100 risk score.
- `scores`: phishing, secret, prompt-injection, URL reputation, impersonation, and AI risk components.
- `flags`: human-readable signals.
- `urls`: URL-level risk, DB state, tags, and brand impersonation details.
- `message_memory`: unsafe-message memory lookup result when available.
- `summary`: short danger summary for high-risk AI-enabled results.

## Commands

Run API:

```sh
cargo run
```

Run queued URL enrichment worker:

```sh
cargo run -- worker
```

Queue a URL manually:

```sh
cargo run -- enqueue-url 'https://example.com/login'
```

Inspect or test brand detection:

```sh
cargo run -- detect-brand-url 'https://example.com'
cargo run -- detect-impersonation-url 'https://example.com'
cargo run -- inspect-brand-learning
cargo run -- benchmark-brand
cargo run -- benchmark-online-brand
cargo run -- benchmark-brand-learning
```

Inspect local domain reputation:

```sh
cargo run -- observe-safe-url 'https://example.com' 10 test-user
cargo run -- inspect-domain-reputation example.com
```

Benchmarks:

```sh
cargo run -- benchmark-phishing
cargo run -- benchmark-phishing-full
cargo run -- benchmark-phishing-full-online
POSEIDON_BENCHMARK_AI=true cargo run -- benchmark-phishing-full-online
```

Download the Hugging Face benchmark explicitly:

```sh
cargo run -- download-phishing-benchmark
```

Build/download/run llama.cpp manually:

```sh
bash scripts/build-llama-server.sh
bash scripts/download-model.sh small
bash scripts/run-llama-server.sh
```

## LLM Behavior

Poseidon prefers llama.cpp by default.

Startup order:

1. If `POSEIDON_LLM_ENDPOINT` is set, use that external OpenAI-compatible endpoint and skip local llama.cpp setup.
2. Otherwise check `http://POSEIDON_LLAMA_HOST:POSEIDON_LLAMA_PORT/health`.
3. If not healthy, build `llama-server` if missing.
4. Find a GGUF model from `POSEIDON_LLAMA_MODEL` or `POSEIDON_MODELS_DIR`.
5. If no model exists, download the default small model.
6. Start `scripts/run-llama-server.sh` and set `POSEIDON_LLM_ENDPOINT` internally.

Default local model is `models/gemma-3-1b-it-Q4_0.gguf` when auto-downloaded. Use `POSEIDON_LLAMA_MODEL` to select another GGUF.

The AI assessment prompt receives:

- URL overview: URL, registrable domain, subdomain, hosting provider, known DB status, queued status, and selected DNS/WHOIS/hosting evidence.
- Raw message text.

The AI is asked to return compact JSON with only:

```json
{"phishing":0,"impersonation":0,"risk":0,"confidence":0,"flags":[]}
```

Prompt-injection score is programmatic only; AI is not asked to score it.

## Configuration Flags

### API

| Flag | Default | Description |
|---|---:|---|
| `POSEIDON_API_ADDR` | `127.0.0.1:8080` | API bind address. |

### LLM And llama.cpp

| Flag | Default | Description |
|---|---:|---|
| `POSEIDON_LLM_ENDPOINT` | unset | External OpenAI-compatible base URL. If set, local llama.cpp setup is skipped. Example: `http://127.0.0.1:8081/v1`. |
| `POSEIDON_OLLAMA_MODEL` | `gemma4:e2b` or local GGUF stem | Model name sent to Ollama/OpenAI-compatible endpoints. Local llama.cpp startup sets this from the GGUF filename if unset. |
| `POSEIDON_OLLAMA_SUMMARY_MODEL` | assessment model | Model used for high-risk summaries. |
| `POSEIDON_LLAMA_AUTO_SETUP` | enabled | Set to `false` to prevent automatic llama.cpp build/model download. |
| `POSEIDON_LLAMA_MODEL` | first `*.gguf` in models dir | Exact GGUF path for local llama.cpp. |
| `POSEIDON_MODELS_DIR` | `models` | Directory searched for `*.gguf` models and used by download script. |
| `POSEIDON_LLAMA_HOST` | `127.0.0.1` | llama.cpp server host. |
| `POSEIDON_LLAMA_PORT` | `8081` | llama.cpp server port. |
| `POSEIDON_LLAMA_CTX` | `8192` | llama.cpp context size. |
| `POSEIDON_LLAMA_THREADS` | `nproc` or `4` | llama.cpp CPU thread count. |
| `POSEIDON_LLAMA_GPU_LAYERS` | `99` | Number of layers to offload to GPU. Use `0` for CPU-only. |
| `POSEIDON_LLAMA_BUILD_JOBS` | `nproc` or `4` | Parallelism for `scripts/build-llama-server.sh`. |
| `POSEIDON_LLAMA_VULKAN` | `OFF` | Set `ON` to build llama.cpp with Vulkan support. |
| `POSEIDON_LLAMA_VULKAN_SDK` | `/tmp/vulkan-sdk` | Vulkan SDK install/cache path used by the build script. |
| `POSEIDON_GGUF_URL` | unset | Custom GGUF URL for `scripts/download-model.sh`. |

### Databases

| Flag | Default | Description |
|---|---:|---|
| `POSEIDON_URL_DB_PATH` | `poseidon_urls.duckdb` | Persistent URL observations, evidence, tags, queue, brand learning, and domain reputation DB. |
| `POSEIDON_MESSAGE_DB_PATH` | `poseidon_messages.duckdb` | Unsafe-message memory DB. |
| `POSEIDON_THREAT_DB_PATH` | in-memory | Threat-intel DuckDB path. Leave unset for in-memory startup ingestion. |
| `POSEIDON_THREAT_UPDATE_MINUTES` | `30` | Threat feed refresh interval. Values below 30 are clamped to 30. |

### Message Memory

| Flag | Default | Description |
|---|---:|---|
| `POSEIDON_STORE_RAW_UNSAFE` | `true` | Store raw message text for unsafe messages. Set `false`, `0`, or `no` to store only redacted/normalized forms. Safe/unknown messages are not stored raw. |

### URL And Brand Analysis

| Flag | Default | Description |
|---|---:|---|
| `POSEIDON_BRAND_CATALOG_PATH` | `data/brand_catalog.json` | Brand allowlist/catalog used for deterministic brand impersonation. |
| `POSEIDON_FAVICON_HASHES_PATH` | `data/favicon_hashes.json` | Known favicon hashes for online brand/page analysis. |
| `POSEIDON_WORKER_LIMIT` | `100` | Max queued URLs processed by `cargo run -- worker`. |

### Benchmark Controls

| Flag | Default | Description |
|---|---:|---|
| `POSEIDON_BENCHMARK_AI` | `false` | Enable AI during phishing benchmarks when `true`, `1`, or `yes`. |
| `POSEIDON_BENCHMARK_LIMIT` | benchmark-dependent | Limit benchmark cases. For full HF benchmark, also controls download size if file is missing/incomplete. |
| `POSEIDON_BENCHMARK_OFFSET` | `0` | Skip this many cases before benchmarking. |
| `POSEIDON_BENCHMARK_DATASET` | built-in small dataset | JSONL dataset path for `benchmark-phishing`. Each line needs `id`, `expected_unsafe`, and `message`. |
| `POSEIDON_BENCHMARK_PERSIST_DB` | `false` | Preserve normal DB paths during benchmarks. By default benchmark DBs are isolated under `/tmp`. |

Benchmark DB isolation defaults:

- Realtime/full: `/tmp/poseidon_bench_realtime_urls.duckdb` and `/tmp/poseidon_bench_realtime_messages.duckdb`.
- Online/full-online: `/tmp/poseidon_bench_online_urls.duckdb` and `/tmp/poseidon_bench_online_messages.duckdb`.

### Hugging Face Benchmark Download

| Flag | Default | Description |
|---|---:|---|
| `POSEIDON_DOWNLOAD_LIMIT` | unset | Max rows downloaded by `download-phishing-benchmark` when no CLI row limit is supplied. |
| `POSEIDON_HF_DATASET` | `cybersectony/PhishingEmailDetectionv2.0` | Hugging Face dataset id. |
| `POSEIDON_HF_CONFIG` | `default` | Hugging Face dataset config. |
| `POSEIDON_HF_SPLITS` | `train,validation,test` | Comma-separated splits to download. |
| `POSEIDON_HF_PAGE_DELAY_MS` | `750` | Delay between Hugging Face dataset page requests. |
| `POSEIDON_HF_RETRIES` | `6` | Retry attempts for `429 Too Many Requests`. |
| `POSEIDON_HF_RETRY_SECONDS` | `5` | Initial retry delay for rate limits. Backoff is exponential. |

### Tranco Importer

Used by `src/bin/tranco_importer.rs`.

| Flag | Default | Description |
|---|---:|---|
| `POSEIDON_TRANCO_LIMIT` | unset | Max Tranco rows to import. |
| `POSEIDON_TRANCO_CSV_PATH` | unset | Local Tranco CSV path. If unset, importer downloads from `POSEIDON_TRANCO_URL`. |
| `POSEIDON_TRANCO_URL` | built-in Tranco URL | Source URL for Tranco CSV download. |

### Brand Scraper

Used by `src/bin/brand_scraper.rs`.

| Flag | Default | Description |
|---|---:|---|
| `POSEIDON_BRAND_CATALOG_OUT` | `data/brand_catalog.json` | Output brand catalog path. |
| `POSEIDON_FAVICON_HASHES_OUT` | `data/favicon_hashes.json` | Output favicon hash path. |
| `POSEIDON_BRAND_INFO_OUT` | `data/brand_info.json` | Output detailed brand metadata path. |
| `POSEIDON_WIKIDATA_MIN_SITELINKS` | `10` | Minimum Wikidata sitelinks for brand candidates. |
| `POSEIDON_BRAND_LIMIT` | `2000` | Maximum brands to scrape. |
| `POSEIDON_FAVICON_WORKERS` | `24` | Favicon fetch worker count. |
| `POSEIDON_MAX_DOMAINS_PER_BRAND` | `4` | Max domains retained per brand. |

## Benchmark Snapshot

Recent 100-case HF benchmark results with current conservative scoring:

| Mode | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| AI offline | 3 | 1 | 55 | 41 | 0.580 | 0.750 | 0.068 | 0.125 |
| Online, no AI | 4 | 0 | 56 | 40 | 0.600 | 1.000 | 0.091 | 0.167 |
| AI + online, `gemma4:e2b` | 9 | 0 | 56 | 35 | 0.650 | 1.000 | 0.205 | 0.340 |
| AI + online, `gemma4:e4b` | 18 | 0 | 56 | 26 | 0.740 | 1.000 | 0.409 | 0.581 |

Interpretation: current scoring is conservative and favors zero false positives. Recall is mainly limited by weak/missing URL evidence on blacklist-style URL-only positives.

## Project Layout

```text
src/main.rs                         command routing and API startup
src/modules/api.rs                  minimal HTTP API
src/modules/scoring.rs              main scoring pipeline
src/modules/ai.rs                   AI prompt, llama.cpp/OpenAI/Ollama client handling
src/modules/llm_server.rs           local llama.cpp bootstrap
src/modules/url_analysis/           URL, brand, online, and worker enrichment modules
src/modules/url_db/                 DuckDB URL reputation/evidence/queue/brand learning
src/modules/message_memory/         unsafe-message memory
src/modules/threat_intel/           feed ingestion and local threat-intel lookup
src/modules/phishing_benchmark.rs   phishing benchmark and HF downloader
scripts/                            llama.cpp build/download/run helpers
data/                               brand data, favicon hashes, benchmarks
external/llama.cpp                  llama.cpp submodule/source
models/                             downloaded GGUF models, ignored by git
```

## Notes

- Normal realtime API should stay fast: it uses cached/local data and queues unknown URLs instead of doing slow live network enrichment.
- `benchmark-phishing-full-online` explicitly enables slow inline online URL enrichment for measurement.
- Benchmarks isolate their DBs by default to avoid contaminated memory/reputation state.
- Do not commit downloaded models, generated DuckDB files, or llama.cpp build output.
