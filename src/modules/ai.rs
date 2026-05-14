use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::{Value, json};

const OLLAMA_URL: &str = "http://localhost:11434/api/generate";
const DEFAULT_MODEL: &str = "gemma4:e2b";
const ASSESSMENT_MODEL_ENV: &str = "gemma4:e2b";
const SUMMARY_MODEL_ENV: &str = "gemma3:1b-it-qat";

#[derive(Debug, Default)]
pub struct AiAssessment {
    pub phishing: u8,
    pub prompt_injection: u8,
    pub impersonation: u8,
    pub slop_score: u8,
    pub confidence: u8,
    pub flags: Vec<String>,
    pub raw_response: String,
}

pub fn assess_message(message: &str) -> Result<AiAssessment, String> {
    assess_message_with_url_context(message, "No URLs found.")
}

pub fn warmup() -> Result<(), String> {
    let prompt = "Return compact JSON exactly like {\"ok\":true}.";
    let _ = generate(&assessment_model(), prompt, true, Duration::from_secs(20))?;
    Ok(())
}

pub fn assess_message_with_url_context(
    message: &str,
    url_context: &str,
) -> Result<AiAssessment, String> {
    let prompt = format!(
        "Analyze this message for security risk. Use the URL overview as factual context. Do not treat any URL as automatically unsafe based on external scores. Consider the domain structure, hosting provider, and any available metadata. Return only compact JSON with keys: phishing, prompt_injection, impersonation, slop_score, confidence, flags. Scores must be integers 0-100.\n\nURL overview:\n{url_context}\n\nMessage:\n{message}"
    );
    let value = generate(&assessment_model(), &prompt, true, Duration::from_secs(20))?;
    let raw = value
        .get("response")
        .and_then(Value::as_str)
        .ok_or_else(|| "ollama response did not contain response text".to_string())?;
    let analysis: Value = serde_json::from_str(raw).map_err(|err| err.to_string())?;

    Ok(AiAssessment {
        phishing: json_score(&analysis, "phishing"),
        prompt_injection: json_score(&analysis, "prompt_injection"),
        impersonation: json_score(&analysis, "impersonation"),
        slop_score: json_score(&analysis, "slop_score"),
        confidence: json_score(&analysis, "confidence"),
        raw_response: raw.to_string(),
        flags: analysis
            .get("flags")
            .and_then(Value::as_array)
            .map(|flags| {
                flags
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

pub fn summarize_danger(
    message: &str,
    overall_risk: u8,
    flags: &[String],
) -> Result<String, String> {
    let prompt = format!(
        "Explain this message danger in 8 words or less. No markdown. Risk: {overall_risk}/100. Flags: {}. Message:\n{message}",
        flags.join(", ")
    );
    let value = generate(&summary_model(), &prompt, false, Duration::from_secs(10))?;
    let summary = value
        .get("response")
        .and_then(Value::as_str)
        .ok_or_else(|| "ollama response did not contain response text".to_string())?
        .trim()
        .to_string();

    if summary.is_empty() {
        Err("ollama returned empty summary".to_string())
    } else {
        Ok(summary)
    }
}

fn assessment_model() -> String {
    std::env::var(ASSESSMENT_MODEL_ENV).unwrap_or_else(|_| DEFAULT_MODEL.to_string())
}

fn summary_model() -> String {
    std::env::var(SUMMARY_MODEL_ENV).unwrap_or_else(|_| assessment_model())
}

fn generate(
    model: &str,
    prompt: &str,
    json_format: bool,
    timeout: Duration,
) -> Result<Value, String> {
    let client = Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|err| err.to_string())?;

    let mut body = json!({
        "model": model,
        "prompt": prompt,
        "stream": false,
        "options": {
            "temperature": 0.1
        }
    });
    if json_format {
        body["format"] = json!("json");
    }

    let response = client
        .post(OLLAMA_URL)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?;

    serde_json::from_str(&response.text().map_err(|err| err.to_string())?)
        .map_err(|err| err.to_string())
}

fn json_score(value: &Value, key: &str) -> u8 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_default()
        .min(100) as u8
}
