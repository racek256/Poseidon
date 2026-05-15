use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use Poseidon::modules;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DEFAULT_OUTPUT: &str = "data/finetune/deepseek_phishing_training.jsonl";
const DEFAULT_DEEPSEEK_URL: &str = "https://api.deepseek.com/chat/completions";
const DEFAULT_DEEPSEEK_MODEL: &str = "deepseek-chat";
const MAX_MESSAGE_CHARS: usize = 8_000;
const MAX_PROMPT_CHARS: usize = 32_000;
const DEEPSEEK_RETRIES: u32 = 2;
const DEEPSEEK_TIMEOUT_SECS: u64 = 45;

struct Config {
    input: Option<PathBuf>,
    output: PathBuf,
    limit: Option<usize>,
    offset: usize,
    online: bool,
    dry_run: bool,
    deepseek_url: String,
    deepseek_model: String,
    api_key: Option<String>,
}

impl Config {
    fn from_env() -> Self {
        Self {
            input: std::env::var("POSEIDON_FINETUNE_INPUT")
                .ok()
                .map(PathBuf::from),
            output: PathBuf::from(env_string("POSEIDON_FINETUNE_OUTPUT", DEFAULT_OUTPUT)),
            limit: env_usize("POSEIDON_FINETUNE_LIMIT"),
            offset: env_usize("POSEIDON_FINETUNE_OFFSET").unwrap_or(0),
            online: env_bool("POSEIDON_FINETUNE_ONLINE", false),
            dry_run: env_bool("POSEIDON_FINETUNE_DRY_RUN", false),
            deepseek_url: env_string("DEEPSEEK_API_URL", DEFAULT_DEEPSEEK_URL),
            deepseek_model: env_string("DEEPSEEK_MODEL", DEFAULT_DEEPSEEK_MODEL),
            api_key: std::env::var("DEEPSEEK_API_KEY").ok(),
        }
    }
}

fn main() -> Result<(), String> {
    let config = Config::from_env();

    if !config.dry_run && config.api_key.as_deref().unwrap_or_default().is_empty() {
        return Err("DEEPSEEK_API_KEY is required unless POSEIDON_FINETUNE_DRY_RUN=true".into());
    }

    let input_path = config.input.as_deref().unwrap_or_else(|| {
        eprintln!("POSEIDON_FINETUNE_INPUT not set, using nazario_top2500.json");
        Path::new("nazario_top2500.json")
    });

    if !input_path.is_file() {
        return Err(format!("input file not found: {}", input_path.display()));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(DEEPSEEK_TIMEOUT_SECS))
        .build()
        .map_err(|err| err.to_string())?;

    if let Some(parent) = config.output.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }

    generate_rows(&client, &config, input_path)
}

fn generate_rows(client: &Client, config: &Config, input_path: &Path) -> Result<(), String> {
    let threat_intel =
        modules::threat_intel::ThreatIntel::from_env().map_err(|err| err.to_string())?;
    let url_db = modules::url_db::UrlDb::from_env().map_err(|err| err.to_string())?;
    let message_memory =
        modules::message_memory::MessageMemory::from_env().map_err(|err| err.to_string())?;
    threat_intel.update_if_due();

    let raw = std::fs::read_to_string(input_path)
        .map_err(|err| format!("failed to read {}: {err}", input_path.display()))?;
    let entries: Vec<Value> =
        serde_json::from_str(&raw).map_err(|err| format!("invalid json: {err}"))?;

    let total = entries.len();
    let limit = config.limit.unwrap_or(total);
    let target = total.min(limit);
    let completed = completed_ids(&config.output)?;
    let already_done = completed.len();

    eprintln!(
        "input: {total} entries | offset={} | completed={already_done} | target={target}",
        config.offset
    );

    if target == 0 || already_done >= target {
        eprintln!("nothing to do");
        return Ok(());
    }

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&config.output)
        .map_err(|err| format!("failed to open {}: {err}", config.output.display()))?;
    let mut writer = BufWriter::new(file);

    let pb = ProgressBar::new(target as u64);
    pb.set_position(already_done as u64);
    let template = "{prefix} [{bar:30}] {pos}/{len} ({eta}) | {msg}";
    pb.set_style(
        ProgressStyle::default_bar()
            .template(template)
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_prefix("labelling");

    let mut success_count = 0_u32;
    let mut error_count = 0_u32;
    let mut skip_count = 0_u32;
    let mut seen = 0_usize;
    let started = Instant::now();

    for (index, entry) in entries.iter().enumerate() {
        if success_count as usize >= target {
            break;
        }
        seen += 1;
        if seen <= config.offset {
            continue;
        }

        let label = entry.get("label").and_then(Value::as_u64).unwrap_or(0);
        let has_url = entry
            .get("has_url")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let source = entry
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("unknown");

        let text = entry
            .get("text")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if text.is_empty() {
            continue;
        }
        let text = truncate(text, MAX_MESSAGE_CHARS);

        let id = row_id(source, index, &text);
        if completed.contains(&id) {
            skip_count += 1;
            continue;
        }

        let scoring = if config.online {
            modules::scoring::analyse_without_ai_with_online_url_enrichment(
                &text,
                None,
                &threat_intel,
                &url_db,
                &message_memory,
            )
        } else {
            modules::scoring::analyse_without_ai(
                &text,
                None,
                &threat_intel,
                &url_db,
                &message_memory,
            )
        };

        let url_context = modules::scoring::ai_url_context(&scoring.urls, &url_db);
        let prompt = truncate(
            &modules::ai::assessment_prompt(&text, &url_context),
            MAX_PROMPT_CHARS,
        );

        let assistant_raw = if config.dry_run {
            "{\"phishing\":100,\"impersonation\":0,\"risk\":90,\"confidence\":50,\"flags\":[\"dry_run\"]}"
                .to_string()
        } else {
            match call_deepseek_with_retry(client, config, &prompt) {
                Ok(raw) => raw,
                Err(err) => {
                    eprintln!("\nerror on {id}: {err}");
                    error_count += 1;
                    pb.set_message(format!("{} success, {} errors", success_count, error_count));
                    continue;
                }
            }
        };

        let assistant_json = serde_json::from_str::<Value>(&assistant_raw)
            .unwrap_or_else(|_| json!({ "parse_error": true, "raw": assistant_raw.clone() }));

        let row = json!({
            "id": id,
            "source": {
                "dataset": "nazario",
                "original_source": source,
                "index": index,
                "label": label,
                "has_url": has_url,
                "expected_unsafe": label == 1
            },
            "message": text,
            "url_context": url_context,
            "prompt": prompt,
            "assistant_raw": assistant_raw,
            "assistant_json": assistant_json,
            "poseidon_context": scoring.to_json()
        });

        writeln!(writer, "{row}").map_err(|err| err.to_string())?;
        writer.flush().map_err(|err| err.to_string())?;
        success_count += 1;
        pb.inc(1);
        pb.set_message(format!("{} success, {} errors", success_count, error_count));
    }

    pb.finish_with_message(format!(
        "success={success_count} errors={error_count} skipped={skip_count}",
    ));

    let elapsed = started.elapsed();
    let rate = if success_count > 0 {
        elapsed.as_secs_f64() / success_count as f64
    } else {
        0.0
    };
    eprintln!(
        "done: {success_count} rows written to {} ({error_count} errors, {skip_count} already done) in {:.1}s ({:.2}s/row)",
        config.output.display(),
        elapsed.as_secs_f64(),
        rate,
    );

    Ok(())
}
fn call_deepseek_with_retry(
    client: &Client,
    config: &Config,
    prompt: &str,
) -> Result<String, String> {
    let mut last_err = String::new();
    for attempt in 0..DEEPSEEK_RETRIES {
        if attempt > 0 {
            let delay = Duration::from_secs(2_u64.pow(attempt));
            std::thread::sleep(delay);
        }
        match call_deepseek(client, config, prompt) {
            Ok(raw) => return Ok(raw),
            Err(err) => {
                last_err = err;
                eprint!(
                    "\nretry {}/{} after error: {last_err}",
                    attempt + 1,
                    DEEPSEEK_RETRIES
                );
            }
        }
    }
    Err(format!(
        "deepseek failed after {DEEPSEEK_RETRIES} retries: {last_err}"
    ))
}

fn call_deepseek(client: &Client, config: &Config, prompt: &str) -> Result<String, String> {
    let body = json!({
        "model": config.deepseek_model,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.0,
        "stream": false,
        "response_format": {"type": "json_object"}
    });
    let raw = client
        .post(&config.deepseek_url)
        .bearer_auth(config.api_key.as_deref().unwrap_or_default())
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|err| format!("request failed: {err}"))?
        .error_for_status()
        .map_err(|err| format!("http error: {err}"))?
        .text()
        .map_err(|err| err.to_string())?;
    let parsed: Value =
        serde_json::from_str(&raw).map_err(|err| format!("bad json: {err}: {raw}"))?;

    let content = parsed
        .get("choices")
        .and_then(|choices| choices.get(0))
        .and_then(|choice| choice.get("message"))
        .and_then(|msg| msg.get("content"))
        .and_then(Value::as_str)
        .map(strip_code_fences)
        .ok_or_else(|| format!("response missing content: {raw}"))?;

    if content.trim().is_empty() {
        return Err("empty content".to_string());
    }

    Ok(content)
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.len() <= max_chars {
        text.to_string()
    } else {
        let mut result = text[..max_chars].to_string();
        result.push_str("\n[truncated]");
        result
    }
}

fn completed_ids(path: &Path) -> Result<HashSet<String>, String> {
    if !path.is_file() {
        return Ok(HashSet::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    let mut ids = HashSet::new();
    for (lineno, line) in raw.lines().enumerate() {
        let id = serde_json::from_str::<Value>(line)
            .map_err(|err| format!("parse error on line {}: {err}", lineno + 1))?
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing id on line {}", lineno + 1))?
            .to_string();
        ids.insert(id);
    }
    Ok(ids)
}

fn row_id(file_name: &str, index: usize, message: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(file_name.as_bytes());
    hasher.update(index.to_string().as_bytes());
    hasher.update(message.as_bytes());
    let hash = hasher.finalize();
    format!(
        "{file_name}-{index}-{:02x}{:02x}{:02x}{:02x}",
        hash[0], hash[1], hash[2], hash[3]
    )
}

fn env_string(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|value| value.parse().ok())
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(default)
}

fn strip_code_fences(text: &str) -> String {
    let stripped = text
        .trim()
        .strip_prefix("```json\n")
        .or_else(|| text.trim().strip_prefix("```json"))
        .or_else(|| text.trim().strip_prefix("```\n"))
        .or_else(|| text.trim().strip_prefix("```"))
        .unwrap_or(text.trim());
    stripped
        .trim_end()
        .strip_suffix("\n```")
        .or_else(|| stripped.trim_end().strip_suffix("```"))
        .unwrap_or(stripped)
        .trim()
        .to_string()
}
