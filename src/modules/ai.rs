use std::sync::Once;
use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::{Value, json};

use crate::modules::llm_server;

const OLLAMA_URL: &str = "http://localhost:11434/api/generate";
const DEFAULT_MODEL: &str = "gemma4:e2b";
const ASSESSMENT_MODEL_ENV: &str = "POSEIDON_OLLAMA_MODEL";
const SUMMARY_MODEL_ENV: &str = "POSEIDON_OLLAMA_SUMMARY_MODEL";

#[derive(Debug, Default)]
pub struct AiAssessment {
    pub phishing: u8,
    pub prompt_injection: u8,
    pub impersonation: u8,
    pub risk: u8,
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
    let prompt = assessment_prompt(message, url_context);
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
        risk: json_score(&analysis, "risk"),
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

pub fn assessment_prompt(message: &str, url_context: &str) -> String {
    format!(
        "Analyze this message for security risk. Use the URL overview as factual context. Do not treat any URL as automatically unsafe based on external scores. Consider the domain structure, hosting provider, and any available metadata. Return only compact JSON with keys: phishing, impersonation, risk, confidence, flags. Scores must be integers 0-100.\n\nURL overview:\n{url_context}\n\nMessage:\n{message}"
    )
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
    ensure_default_llm();
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
    ensure_default_llm();

    let client = Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|err| err.to_string())?;

    if let Some(endpoint) = llm_endpoint() {
        generate_openai(&client, model, prompt, json_format, &endpoint)
    } else {
        generate_ollama(&client, model, prompt, json_format)
    }
}

fn ensure_default_llm() {
    static ENSURE: Once = Once::new();
    ENSURE.call_once(llm_server::ensure);
}

fn llm_endpoint() -> Option<String> {
    std::env::var("POSEIDON_LLM_ENDPOINT")
        .ok()
        .filter(|value| !value.is_empty())
}

fn generate_ollama(
    client: &Client,
    model: &str,
    prompt: &str,
    json_format: bool,
) -> Result<Value, String> {
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

fn generate_openai(
    client: &Client,
    model: &str,
    prompt: &str,
    json_format: bool,
    endpoint: &str,
) -> Result<Value, String> {
    let mut body = json!({
        "model": model,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "max_tokens": if json_format { 256 } else { 64 },
        "stream": false
    });
    if json_format {
        body["response_format"] = json!({"type": "json_object"});
    }

    let url = format!("{}/chat/completions", endpoint.trim_end_matches('/'));
    let raw = client
        .post(&url)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|err| format!("llm endpoint request failed: {err}"))?
        .error_for_status()
        .map_err(|err| format!("llm endpoint returned error: {err}"))?
        .text()
        .map_err(|err| err.to_string())?;

    let parsed: Value = serde_json::from_str(&raw).map_err(|err| err.to_string())?;
    let raw_content = parsed
        .get("choices")
        .and_then(|choices| choices.get(0))
        .and_then(|choice| choice.get("message"))
        .and_then(|msg| msg.get("content"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("llm endpoint response missing choices[0].message.content: {raw}",))?
        .to_string();

    let content = strip_code_fences(&raw_content).trim().to_string();
    if content.is_empty() {
        return Err(format!(
            "llm endpoint returned empty content: {raw_content}"
        ));
    }

    Ok(json!({ "response": content }))
}

fn json_score(value: &Value, key: &str) -> u8 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_default()
        .min(100) as u8
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
        .to_string()
}
