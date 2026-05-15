use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde_json::{Value, json};

use crate::modules::message_memory::MessageMemory;
use crate::modules::scoring::{self, Decision};
use crate::modules::threat_intel::ThreatIntel;
use crate::modules::url_db::UrlDb;

const DATASET: &str = include_str!("../../data/benchmarks/phishing_messages.jsonl");
const DEFAULT_HF_DATASET: &str = "cybersectony/PhishingEmailDetectionv2.0";
const DEFAULT_HF_CONFIG: &str = "default";
const DEFAULT_HF_SPLITS: &[&str] = &["train", "validation", "test"];
const HF_PAGE_SIZE: usize = 100;
const FULL_DATASET_PATH: &str = "data/benchmarks/phishing_hf_200k.jsonl";
const FULL_DATASET_EXPECTED_ROWS: usize = 200_000;

struct Case {
    id: String,
    expected_unsafe: bool,
    message: String,
}

pub fn run() -> Result<(), String> {
    let cases = load_cases()?;
    run_cases(cases, false)
}

pub fn run_full() -> Result<(), String> {
    let requested_rows = benchmark_limit().unwrap_or(FULL_DATASET_EXPECTED_ROWS);
    let existing_rows = count_lines(FULL_DATASET_PATH).unwrap_or(0);
    if existing_rows < requested_rows {
        if existing_rows > 0 {
            println!(
                "phishing benchmark incomplete ({existing_rows}/{requested_rows}); redownloading {FULL_DATASET_PATH}"
            );
            std::fs::remove_file(FULL_DATASET_PATH)
                .map_err(|err| format!("failed to remove partial {FULL_DATASET_PATH}: {err}"))?;
        } else {
            println!("full phishing benchmark missing; downloading {FULL_DATASET_PATH}");
        }
        let download_limit = if requested_rows < FULL_DATASET_EXPECTED_ROWS {
            Some(requested_rows)
        } else {
            None
        };
        download_huggingface_dataset_to(FULL_DATASET_PATH, download_limit)?;
    }

    let cases =
        load_cases_from_text(&std::fs::read_to_string(FULL_DATASET_PATH).map_err(|err| {
            format!("failed to read full phishing benchmark {FULL_DATASET_PATH}: {err}")
        })?)?;
    run_cases(cases, false)
}

pub fn run_full_online() -> Result<(), String> {
    let requested_rows = benchmark_limit().unwrap_or(FULL_DATASET_EXPECTED_ROWS);
    let existing_rows = count_lines(FULL_DATASET_PATH).unwrap_or(0);
    if existing_rows < requested_rows {
        let download_limit = if requested_rows < FULL_DATASET_EXPECTED_ROWS {
            Some(requested_rows)
        } else {
            None
        };
        download_huggingface_dataset_to(FULL_DATASET_PATH, download_limit)?;
    }

    let cases =
        load_cases_from_text(&std::fs::read_to_string(FULL_DATASET_PATH).map_err(|err| {
            format!("failed to read full phishing benchmark {FULL_DATASET_PATH}: {err}")
        })?)?;
    run_cases(cases, true)
}

fn benchmark_limit() -> Option<usize> {
    std::env::var("POSEIDON_BENCHMARK_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
}

fn run_cases(cases: Vec<Case>, online_url_enrichment: bool) -> Result<(), String> {
    isolate_benchmark_databases(online_url_enrichment)?;
    let threat_intel = ThreatIntel::from_env().map_err(|err| err.to_string())?;
    let url_db = UrlDb::from_env().map_err(|err| err.to_string())?;
    let message_memory = MessageMemory::from_env().map_err(|err| err.to_string())?;
    let ai_enabled = std::env::var("POSEIDON_BENCHMARK_AI")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    let mut true_positive = 0_u32;
    let mut false_positive = 0_u32;
    let mut true_negative = 0_u32;
    let mut false_negative = 0_u32;
    let mut risk_sum = 0_u64;
    let started = Instant::now();

    for case in &cases {
        let user_id = format!("benchmark-{}", case.id);
        let scoring = if ai_enabled {
            if online_url_enrichment {
                scoring::analyse_with_online_url_enrichment(
                    &case.message,
                    Some(&user_id),
                    &threat_intel,
                    &url_db,
                    &message_memory,
                )
            } else {
                scoring::analyse(
                    &case.message,
                    Some(&user_id),
                    &threat_intel,
                    &url_db,
                    &message_memory,
                )
            }
        } else {
            if online_url_enrichment {
                scoring::analyse_without_ai_with_online_url_enrichment(
                    &case.message,
                    Some(&user_id),
                    &threat_intel,
                    &url_db,
                    &message_memory,
                )
            } else {
                scoring::analyse_without_ai(
                    &case.message,
                    Some(&user_id),
                    &threat_intel,
                    &url_db,
                    &message_memory,
                )
            }
        };
        let predicted_unsafe = matches!(
            scoring.decision,
            Decision::WarnR | Decision::WarnB | Decision::Block
        ) || scoring.overall_risk >= 60;
        risk_sum += scoring.overall_risk as u64;

        match (case.expected_unsafe, predicted_unsafe) {
            (true, true) => true_positive += 1,
            (false, true) => {
                false_positive += 1;
                print_failure("false_positive", case, &scoring);
            }
            (false, false) => true_negative += 1,
            (true, false) => {
                false_negative += 1;
                print_failure("false_negative", case, &scoring);
            }
        }
    }

    let total = cases.len() as f64;
    let accuracy = (true_positive + true_negative) as f64 / total;
    let precision = safe_div(true_positive, true_positive + false_positive);
    let recall = safe_div(true_positive, true_positive + false_negative);
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    let elapsed = started.elapsed();

    println!("cases: {}", cases.len());
    println!("true_positive: {true_positive}");
    println!("false_positive: {false_positive}");
    println!("true_negative: {true_negative}");
    println!("false_negative: {false_negative}");
    println!("accuracy: {:.3}", accuracy);
    println!("precision: {:.3}", precision);
    println!("recall: {:.3}", recall);
    println!("f1: {:.3}", f1);
    println!("avg_risk: {:.1}", risk_sum as f64 / total);
    println!("total_ms: {:.1}", elapsed.as_secs_f64() * 1000.0);
    println!(
        "avg_ms_per_case: {:.3}",
        elapsed.as_secs_f64() * 1000.0 / total
    );
    println!("ai_enabled: {ai_enabled}");
    println!("online_url_enrichment: {online_url_enrichment}");

    Ok(())
}

fn isolate_benchmark_databases(online_url_enrichment: bool) -> Result<(), String> {
    if std::env::var("POSEIDON_BENCHMARK_PERSIST_DB")
        .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
    {
        return Ok(());
    }

    let suffix = if online_url_enrichment {
        "online"
    } else {
        "realtime"
    };
    set_temp_db_if_missing(
        "POSEIDON_URL_DB_PATH",
        &format!("/tmp/poseidon_bench_{suffix}_urls.duckdb"),
    )?;
    set_temp_db_if_missing(
        "POSEIDON_MESSAGE_DB_PATH",
        &format!("/tmp/poseidon_bench_{suffix}_messages.duckdb"),
    )?;
    Ok(())
}

fn set_temp_db_if_missing(env_key: &str, path: &str) -> Result<(), String> {
    if std::env::var(env_key).is_ok_and(|value| !value.is_empty()) {
        return Ok(());
    }
    let _ = std::fs::remove_file(path);
    let wal_path = format!("{path}.wal");
    let _ = std::fs::remove_file(wal_path);
    // Benchmark startup is single-threaded; setting process env here keeps existing DB constructors unchanged.
    unsafe {
        std::env::set_var(env_key, path);
    }
    Ok(())
}

fn load_cases() -> Result<Vec<Case>, String> {
    if let Ok(path) = std::env::var("POSEIDON_BENCHMARK_DATASET") {
        return load_cases_from_text(
            &std::fs::read_to_string(&path).map_err(|err| {
                format!("failed to read POSEIDON_BENCHMARK_DATASET {path}: {err}")
            })?,
        );
    }

    load_cases_from_text(DATASET)
}

fn load_cases_from_text(dataset: &str) -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();
    let offset = std::env::var("POSEIDON_BENCHMARK_OFFSET")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let limit = std::env::var("POSEIDON_BENCHMARK_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());

    let mut seen_cases = 0_usize;
    for (line_number, line) in dataset.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if seen_cases < offset {
            seen_cases += 1;
            continue;
        }
        if let Some(limit) = limit {
            if cases.len() >= limit {
                break;
            }
        }
        seen_cases += 1;
        let value: Value = serde_json::from_str(line)
            .map_err(|err| format!("invalid benchmark json line {}: {err}", line_number + 1))?;
        cases.push(Case {
            id: value
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("missing id on line {}", line_number + 1))?
                .to_string(),
            expected_unsafe: value
                .get("expected_unsafe")
                .and_then(Value::as_bool)
                .ok_or_else(|| format!("missing expected_unsafe on line {}", line_number + 1))?,
            message: value
                .get("message")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("missing message on line {}", line_number + 1))?
                .to_string(),
        });
    }
    if cases.len() < 1 {
        return Err(format!(
            "benchmark needs at least 1 cases, got {}",
            cases.len()
        ));
    }
    Ok(cases)
}

pub fn download_huggingface_dataset() -> Result<(), String> {
    let output = std::env::args()
        .nth(2)
        .unwrap_or_else(|| FULL_DATASET_PATH.to_string());
    let max_rows = std::env::args()
        .nth(3)
        .or_else(|| std::env::var("POSEIDON_DOWNLOAD_LIMIT").ok())
        .and_then(|value| value.parse::<usize>().ok());
    download_huggingface_dataset_to(&output, max_rows)
}

fn download_huggingface_dataset_to(output: &str, max_rows: Option<usize>) -> Result<(), String> {
    let dataset =
        std::env::var("POSEIDON_HF_DATASET").unwrap_or_else(|_| DEFAULT_HF_DATASET.to_string());
    let config =
        std::env::var("POSEIDON_HF_CONFIG").unwrap_or_else(|_| DEFAULT_HF_CONFIG.to_string());
    let splits = std::env::var("POSEIDON_HF_SPLITS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|split| !split.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            DEFAULT_HF_SPLITS
                .iter()
                .map(|split| split.to_string())
                .collect()
        });

    let client = Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|err| err.to_string())?;
    if let Some(parent) = std::path::Path::new(output).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let file = File::create(&output).map_err(|err| format!("failed to create {output}: {err}"))?;
    let mut writer = BufWriter::new(file);
    let mut written = 0_usize;
    let page_delay = Duration::from_millis(
        std::env::var("POSEIDON_HF_PAGE_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(750),
    );

    for split in splits {
        let mut offset = 0_usize;
        loop {
            if max_rows.is_some_and(|limit| written >= limit) {
                break;
            }
            let remaining = max_rows.map(|limit| limit.saturating_sub(written));
            let length = remaining.map_or(HF_PAGE_SIZE, |remaining| remaining.min(HF_PAGE_SIZE));
            if length == 0 {
                break;
            }

            let url = format!(
                "https://datasets-server.huggingface.co/rows?dataset={dataset}&config={config}&split={split}&offset={offset}&length={length}"
            );
            let body = fetch_huggingface_page(&client, &url)?;
            let page: Value = serde_json::from_str(&body)
                .map_err(|err| format!("invalid huggingface json for {url}: {err}"))?;
            let rows = page
                .get("rows")
                .and_then(Value::as_array)
                .ok_or_else(|| format!("huggingface response missing rows for {url}"))?;
            if rows.is_empty() {
                break;
            }

            for row in rows {
                if max_rows.is_some_and(|limit| written >= limit) {
                    break;
                }
                let row_idx = row
                    .get("row_idx")
                    .and_then(Value::as_u64)
                    .unwrap_or(written as u64);
                let payload = row
                    .get("row")
                    .ok_or_else(|| "huggingface row missing row payload".to_string())?;
                let content = payload
                    .get("content")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "huggingface row missing content".to_string())?;
                let label = payload
                    .get("label")
                    .and_then(Value::as_i64)
                    .ok_or_else(|| "huggingface row missing label".to_string())?;
                let expected_unsafe = matches!(label, 1 | 3);
                let benchmark_row = json!({
                    "id": format!("hf-{split}-{row_idx}"),
                    "expected_unsafe": expected_unsafe,
                    "message": content
                });
                writeln!(writer, "{benchmark_row}")
                    .map_err(|err| format!("failed to write {output}: {err}"))?;
                written += 1;
            }

            offset += rows.len();
            if rows.len() < length {
                break;
            }
            if written % 10_000 == 0 {
                println!("downloaded {written} rows");
            }
            std::thread::sleep(page_delay);
        }
    }

    writer
        .flush()
        .map_err(|err| format!("failed to flush {output}: {err}"))?;
    println!("wrote {written} rows to {output}");
    println!("run with: POSEIDON_BENCHMARK_DATASET={output} cargo run -- benchmark-phishing");
    Ok(())
}

fn fetch_huggingface_page(client: &Client, url: &str) -> Result<String, String> {
    let max_attempts = std::env::var("POSEIDON_HF_RETRIES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(8);
    let mut delay = Duration::from_secs(
        std::env::var("POSEIDON_HF_RETRY_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(10),
    );

    for attempt in 1..=max_attempts {
        match client.get(url).send() {
            Ok(response) if response.status().is_success() => {
                return response.text().map_err(|err| {
                    format!("failed to read huggingface response for {url}: {err}")
                });
            }
            Ok(response) if response.status().as_u16() == 429 => {
                eprintln!(
                    "huggingface rate limit on attempt {attempt}/{max_attempts}; sleeping {}s",
                    delay.as_secs()
                );
            }
            Ok(response) => {
                return Err(format!(
                    "huggingface returned error for {url}: HTTP status {}",
                    response.status()
                ));
            }
            Err(err) => {
                if attempt == max_attempts {
                    return Err(format!("failed to fetch {url}: {err}"));
                }
                eprintln!(
                    "huggingface fetch failed on attempt {attempt}/{max_attempts}: {err}; sleeping {}s",
                    delay.as_secs()
                );
            }
        }

        if attempt < max_attempts {
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_secs(120));
        }
    }

    Err(format!("huggingface rate limit persisted for {url}"))
}

fn count_lines(path: &str) -> Option<usize> {
    std::fs::read_to_string(path)
        .ok()
        .map(|text| text.lines().filter(|line| !line.trim().is_empty()).count())
}

fn safe_div(numerator: u32, denominator: u32) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn print_failure(kind: &str, case: &Case, scoring: &scoring::Scoring) {
    println!("failure_kind: {kind}");
    println!("id: {}", case.id);
    println!("expected_unsafe: {}", case.expected_unsafe);
    println!("risk: {}", scoring.overall_risk);
    println!("decision: {}", scoring.decision.as_str());
    println!(
        "scores: phishing={} secret={} prompt_injection={} url_reputation={:?} impersonation={} risk={}",
        scoring.scores.phishing,
        scoring.scores.secret,
        scoring.scores.prompt_injection,
        scoring.scores.url_reputation,
        scoring.scores.impersonation,
        scoring.scores.risk
    );
    println!("flags: {}", scoring.flags.join(" | "));
    for url in &scoring.urls {
        println!(
            "url_detail: url={} risk={} known_db={} verdict={:?} tags={}",
            url.url,
            url.risk,
            url.known_url_db,
            url.stored_verdict,
            url.tags.join("|")
        );
        if let Some(brand) = &url.brand_impersonation {
            println!(
                "brand_detail: matched={:?} official={} provider={:?} score={} confidence={} level={} reasons={} safe={}",
                brand.matched_brand,
                brand.official,
                brand.hosting_provider,
                brand.score,
                brand.confidence,
                brand.risk_level,
                brand.reasons_json,
                brand.safe_evidence_json
            );
        }
    }
    println!("message: {}", case.message);
    println!(
        "ai_response: {}",
        scoring.ai_raw_response.as_deref().unwrap_or("<none>")
    );
}
