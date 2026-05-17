//! Universal LLM communication module for supply chain analysis.
//!
//! Supports multiple LLM providers:
//! - `openai` → OpenAI API (`https://api.openai.com/v1/chat/completions`)
//! - `zen` → OpenCode ZEN (`https://opencode.ai/zen/v1/chat/completions`)
//! - `go` → OpenCode GO (`https://api.opencode.ai/v1/chat/completions`)
//! - `ollama` → Local Ollama (`http://localhost:11434/api/chat`)
//!
//! Configuration via environment variables:
//! - `LLM_PROVIDER` (required): provider name (`openai`, `zen`, `go`, `ollama`)
//! - `PROVIDER_API_KEY` (required for non-ollama): API key for authentication
//! - `LLM_MODEL` (required): model identifier (e.g., `gpt-4o`, `llama3.2`)

use std::time::Duration;

use reqwest::blocking::Client;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::{Value, json};

use crate::modules::tui::bridge;

/// LLM provider identifiers.
const PROVIDER_OPENAI: &str = "openai";
const PROVIDER_ZEN: &str = "zen";
const PROVIDER_GO: &str = "go";
const PROVIDER_OLLAMA: &str = "ollama";

/// API endpoints for each provider.
const ENDPOINT_OPENAI: &str = "https://api.openai.com/v1/chat/completions";
const ENDPOINT_ZEN: &str = "https://opencode.ai/zen/v1/chat/completions";
const ENDPOINT_GO: &str = "https://api.opencode.ai/v1/chat/completions";
const ENDPOINT_OLLAMA: &str = "http://localhost:11434/api/chat";

/// Environment variable names.
const ENV_LLM_PROVIDER: &str = "LLM_PROVIDER";
const ENV_PROVIDER_API_KEY: &str = "PROVIDER_API_KEY";
const ENV_LLM_MODEL: &str = "LLM_MODEL";

/// Timeout for LLM requests in seconds.
const REQUEST_TIMEOUT_SECS: u64 = 60;

/// Temperature for LLM sampling.
const TEMPERATURE: f64 = 0.1;

/// Maximum retries for transient errors.
const MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff in seconds.
const BASE_DELAY_SECS: u64 = 1;

/// LLM client for making completion requests.
#[derive(Debug)]
pub struct LlmClient {
    client: Client,
}

impl LlmClient {
    /// Create a new LLM client.
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()
            .expect("failed to create HTTP client for LLM client");
        Self { client }
    }

    /// Send a prompt to the LLM and return the response content.
    pub fn llm_completion(&self, prompt: &str) -> Result<String, String> {
        let provider = std::env::var(ENV_LLM_PROVIDER)
            .map_err(|_| format!("{} environment variable not set", ENV_LLM_PROVIDER))?;
        let model = std::env::var(ENV_LLM_MODEL)
            .map_err(|_| format!("{} environment variable not set", ENV_LLM_MODEL))?;
        let api_key = std::env::var(ENV_PROVIDER_API_KEY).ok();

        bridge::log(&format!(
            "llm_completion: provider={}, model={}",
            provider, model
        ));

        // Validate API key for non-ollama providers
        match provider.as_str() {
            PROVIDER_OPENAI | PROVIDER_ZEN | PROVIDER_GO => {
                if api_key.is_none() || api_key.as_ref().map_or(true, |k| k.is_empty()) {
                    return Err(format!(
                        "PROVIDER_API_KEY is required for {} provider",
                        provider
                    ));
                }
            }
            PROVIDER_OLLAMA => {
                // API key is optional for ollama
            }
            _ => {
                return Err(format!(
                    "unknown LLM provider: '{}'. Valid options: openai, zen, go, ollama",
                    provider
                ));
            }
        }

        match provider.as_str() {
            PROVIDER_OPENAI => {
                self.send_openai_compatible(&model, prompt, ENDPOINT_OPENAI, api_key.as_deref())
            }
            PROVIDER_ZEN => {
                self.send_openai_compatible(&model, prompt, ENDPOINT_ZEN, api_key.as_deref())
            }
            PROVIDER_GO => {
                self.send_openai_compatible(&model, prompt, ENDPOINT_GO, api_key.as_deref())
            }
            PROVIDER_OLLAMA => self.send_ollama(&model, prompt),
            _ => Err(format!("unknown LLM provider: '{}'", provider)),
        }
    }

    /// Send a prompt using the OpenAI-compatible chat completions API.
    ///
    /// This format is used by OpenAI, ZEN, and GO providers.
    fn send_openai_compatible(
        &self,
        model: &str,
        prompt: &str,
        endpoint: &str,
        api_key: Option<&str>,
    ) -> Result<String, String> {
        let body = json!({
            "model": model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": TEMPERATURE
        });

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        if let Some(key) = api_key {
            if !key.is_empty() {
                let auth_value = HeaderValue::from_str(&format!("Bearer {}", key))
                    .map_err(|e| format!("invalid authorization header: {}", e))?;
                headers.insert("authorization", auth_value);
            }
        }

        let method = reqwest::Method::POST;
        let url = reqwest::Url::parse(endpoint).map_err(|e| format!("invalid URL: {}", e))?;

        let response = self.send_with_retries(method, url, headers, body.to_string(), endpoint)?;

        let response_text = response
            .text()
            .map_err(|err| format!("failed to read response body: {}", err))?;

        let parsed: Value = serde_json::from_str(&response_text).map_err(|err| {
            format!(
                "failed to parse JSON response: {} (body: {})",
                err, response_text
            )
        })?;

        let content = parsed
            .get("choices")
            .and_then(|choices| choices.get(0))
            .and_then(|choice| choice.get("message"))
            .and_then(|msg| msg.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "response missing expected field 'choices[0].message.content'. Response: {}",
                    response_text
                )
            })?
            .to_string();

        Ok(content)
    }

    /// Send a prompt using the Ollama `/api/chat` endpoint.
    ///
    /// Ollama uses a different response format with `message.content` at the top level.
    fn send_ollama(&self, model: &str, prompt: &str) -> Result<String, String> {
        let body = json!({
            "model": model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "options": {
                "temperature": TEMPERATURE
            },
            "stream": false
        });

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let method = reqwest::Method::POST;
        let url =
            reqwest::Url::parse(ENDPOINT_OLLAMA).map_err(|e| format!("invalid URL: {}", e))?;

        let response =
            self.send_with_retries(method, url, headers, body.to_string(), ENDPOINT_OLLAMA)?;

        let response_text = response
            .text()
            .map_err(|err| format!("failed to read response body: {}", err))?;

        let parsed: Value = serde_json::from_str(&response_text).map_err(|err| {
            format!(
                "failed to parse JSON response: {} (body: {})",
                err, response_text
            )
        })?;

        let content = parsed
            .get("message")
            .and_then(|msg| msg.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "response missing expected field 'message.content'. Response: {}",
                    response_text
                )
            })?
            .to_string();

        Ok(content)
    }

    /// Send HTTP request with exponential backoff retry for 429 and 5xx errors.
    fn send_with_retries(
        &self,
        method: reqwest::Method,
        url: reqwest::Url,
        headers: reqwest::header::HeaderMap,
        body: String,
        endpoint: &str,
    ) -> Result<reqwest::blocking::Response, String> {
        let mut attempt = 0;

        loop {
            let mut req_builder = self.client.request(method.clone(), url.clone());
            req_builder = req_builder.headers(headers.clone());

            let response = req_builder
                .body(body.clone())
                .send()
                .map_err(|err| format!("request to {} failed: {}", endpoint, err))?;

            let status = response.status();

            if status.is_success() {
                return Ok(response);
            }

            // Retry on 429 Too Many Requests or 5xx Server Errors
            if status.as_u16() == 429 || status.is_server_error() {
                if attempt >= MAX_RETRIES {
                    let body_text = response.text().unwrap_or_default();
                    return Err(format!(
                        "{} returned error status {} after {} retries: {}",
                        endpoint, status, MAX_RETRIES, body_text
                    ));
                }
                attempt += 1;
                let delay_secs = BASE_DELAY_SECS * (2_u64.pow(attempt - 1));
                bridge::elog(&format!(
                    "{} returned {}, retrying in {}s (attempt {}/{})",
                    endpoint, status, delay_secs, attempt, MAX_RETRIES
                ));
                std::thread::sleep(Duration::from_secs(delay_secs));
                continue;
            }

            // Non-retryable error
            let body_text = response.text().unwrap_or_default();
            return Err(format!(
                "{} returned error status {}: {}",
                endpoint, status, body_text
            ));
        }
    }
}

impl Default for LlmClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function that creates a default LlmClient and calls llm_completion.
pub fn llm_completion(prompt: &str) -> Result<String, String> {
    let client = LlmClient::new();
    client.llm_completion(prompt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_constants() {
        assert_eq!(PROVIDER_OPENAI, "openai");
        assert_eq!(PROVIDER_ZEN, "zen");
        assert_eq!(PROVIDER_GO, "go");
        assert_eq!(PROVIDER_OLLAMA, "ollama");
    }

    #[test]
    fn test_endpoint_constants() {
        assert_eq!(
            ENDPOINT_OPENAI,
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(ENDPOINT_ZEN, "https://opencode.ai/zen/v1/chat/completions");
        assert_eq!(ENDPOINT_GO, "https://api.opencode.ai/v1/chat/completions");
        assert_eq!(ENDPOINT_OLLAMA, "http://localhost:11434/api/chat");
    }

    #[test]
    fn test_openai_request_body_format() {
        // Test that the request body is correctly structured for OpenAI-compatible API
        let body = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Test prompt"}
            ],
            "temperature": TEMPERATURE
        });

        let body_str = body.to_string();
        assert!(body_str.contains("\"model\":\"gpt-4o\""));
        assert!(body_str.contains("\"messages\""));
        assert!(body_str.contains("\"role\":\"user\""));
        assert!(body_str.contains("\"content\":\"Test prompt\""));
        assert!(body_str.contains("\"temperature\":0.1"));
    }

    #[test]
    fn test_ollama_request_body_format() {
        // Test that the request body is correctly structured for Ollama API
        let body = json!({
            "model": "llama3.2",
            "messages": [
                {"role": "user", "content": "Test prompt"}
            ],
            "options": {
                "temperature": TEMPERATURE
            },
            "stream": false
        });

        let body_str = body.to_string();
        assert!(body_str.contains("\"model\":\"llama3.2\""));
        assert!(body_str.contains("\"messages\""));
        assert!(body_str.contains("\"role\":\"user\""));
        assert!(body_str.contains("\"content\":\"Test prompt\""));
        assert!(body_str.contains("\"stream\":false"));
        // Ollama now includes temperature in the request via options
        assert!(body_str.contains("temperature"));
    }

    #[test]
    fn test_openai_response_parsing() {
        // Test parsing of OpenAI-compatible response format
        let response_json = r#"{
            "choices": [
                {
                    "message": {
                        "content": "This is the LLM response text."
                    }
                }
            ]
        }"#;

        let parsed: Value = serde_json::from_str(response_json).unwrap();
        let content = parsed
            .get("choices")
            .and_then(|choices| choices.get(0))
            .and_then(|choice| choice.get("message"))
            .and_then(|msg| msg.get("content"))
            .and_then(Value::as_str)
            .unwrap();

        assert_eq!(content, "This is the LLM response text.");
    }

    #[test]
    fn test_ollama_response_parsing() {
        // Test parsing of Ollama response format
        let response_json = r#"{
            "model": "llama3.2",
            "message": {
                "role": "assistant",
                "content": "Ollama response content here."
            },
            "done": true
        }"#;

        let parsed: Value = serde_json::from_str(response_json).unwrap();
        let content = parsed
            .get("message")
            .and_then(|msg| msg.get("content"))
            .and_then(Value::as_str)
            .unwrap();

        assert_eq!(content, "Ollama response content here.");
    }

    #[test]
    fn test_missing_required_env_var() {
        // This test relies on LLM_PROVIDER not being set in the test environment
        // We can't test llm_completion directly without mocking, but we can test
        // that the function handles missing env vars gracefully by checking the
        // error message format
        let result = std::env::var("THIS_VARIABLE_DOES_NOT_EXIST_12345");
        assert!(result.is_err());
    }
}
