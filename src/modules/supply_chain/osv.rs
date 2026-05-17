use std::time::Duration;

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

use crate::modules::tui::bridge;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSVVulnerability {
    pub id: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub severity: Vec<OSVSeverity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OSVSeverity {
    pub r#type: Option<String>,
    pub score: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OSVBatchQuery {
    queries: Vec<OSVQuery>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OSVQuery {
    package: OSVPackage,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OSVPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct OSVBatchResponse {
    #[serde(default)]
    results: Vec<OSVQueryResult>,
}

#[derive(Debug, Deserialize)]
struct OSVQueryResult {
    #[serde(default)]
    vulns: Vec<OSVVulnSummary>,
}

#[derive(Debug, Deserialize)]
struct OSVVulnSummary {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    modified: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OSVFullVulnerability {
    id: Option<String>,
    summary: Option<String>,
    details: Option<String>,
    #[serde(default)]
    severity: Vec<OSVSeverity>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

/// Resolve severity from a vulnerability.
/// Returns (numeric_score, severity_label) where label is one of:
/// "none", "low", "medium", "high", "critical".
pub fn resolve_severity(vuln: &OSVVulnerability) -> (f64, &'static str) {
    // First, try the severity vector
    for sev in &vuln.severity {
        // Try parsing score as a plain number first
        if let Some(score_str) = &sev.score {
            if let Ok(score) = score_str.parse::<f64>() {
                let level = numeric_score_to_level(score);
                return (score, level);
            }
            // If not a plain number, check if it's a CVSS vector string
            if let Some(type_str) = &sev.r#type {
                if type_str == "CVSS_V3" || type_str == "CVSS_V2" {
                    if let Some(cvss_score) = parse_cvss_vector(score_str) {
                        let level = numeric_score_to_level(cvss_score);
                        return (cvss_score, level);
                    }
                }
            }
        }
    }

    // Fallback: check database_specific for severity string
    // (This would require access to the full vulnerability with database_specific,
    // but we can check if severity vec was empty and return a default)
    // For OSVVulnerability passed here, we don't have database_specific directly.
    // The caller should use the full OSVFullVulnerability if they need that fallback.
    // For now, return default medium.
    (5.0, "medium")
}

/// Resolve severity from a full vulnerability (includes database_specific fallback).
/// Returns (numeric_score, severity_label).
pub fn resolve_severity_full(full: &OSVFullVulnerability) -> (f64, &'static str) {
    // First, try the severity vector
    for sev in &full.severity {
        if let Some(score_str) = &sev.score {
            if let Ok(score) = score_str.parse::<f64>() {
                let level = numeric_score_to_level(score);
                return (score, level);
            }
            if let Some(type_str) = &sev.r#type {
                if type_str == "CVSS_V3" || type_str == "CVSS_V2" {
                    if let Some(cvss_score) = parse_cvss_vector(score_str) {
                        let level = numeric_score_to_level(cvss_score);
                        return (cvss_score, level);
                    }
                }
            }
        }
    }

    // Fallback: check database_specific for severity string
    if let Some(db) = &full.database_specific {
        if let Some(obj) = db.as_object() {
            if let Some(sev_val) = obj.get("severity") {
                if let Some(sev_str) = sev_val.as_str() {
                    let sev_upper = sev_str.to_uppercase();
                    let level = match sev_upper.as_str() {
                        "CRITICAL" => "critical",
                        "HIGH" => "high",
                        "MEDIUM" | "MODERATE" => "medium",
                        "LOW" => "low",
                        "NONE" => "none",
                        _ => "medium",
                    };
                    // Map to a numeric score as well
                    let score = match level {
                        "critical" => 9.0,
                        "high" => 7.0,
                        "medium" => 5.0,
                        "low" => 3.0,
                        _ => 0.0,
                    };
                    return (score, level);
                }
            }
        }
    }

    (5.0, "medium")
}

/// Convert a numeric CVSS score to a severity level string.
fn numeric_score_to_level(score: f64) -> &'static str {
    if score >= 9.0 {
        "critical"
    } else if score >= 7.0 {
        "high"
    } else if score >= 4.0 {
        "medium"
    } else if score > 0.0 {
        "low"
    } else {
        "none"
    }
}

/// Minimal CVSS v3.1 vector string parser.
/// Extracts the 8 metric values and computes the base score.
/// Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
/// Returns None if parsing fails.
fn parse_cvss_vector(vector: &str) -> Option<f64> {
    // Remove CVSS:3.1/ prefix if present
    let vector = vector.strip_prefix("CVSS:3.1/").unwrap_or(vector);
    let vector = vector.strip_prefix("CVSS:3.0/").unwrap_or(vector);
    let vector = vector.strip_prefix("CVSS:2.0/").unwrap_or(vector);

    let mut av = 'X';
    let mut ac = 'X';
    let mut pr_u = 'X'; // for PR when UI=N (unchanged)
    let mut pr_c = 'X'; // for PR when UI=R (changed)
    let mut ui = 'X';
    let mut s = 'X';
    let mut c = 'X';
    let mut i = 'X';
    let mut a = 'X';

    for part in vector.split('/') {
        let parts: Vec<&str> = part.split(':').collect();
        if parts.len() >= 2 {
            let key = parts[0];
            let value = parts[1].chars().next().unwrap_or('X');
            match key {
                "AV" => av = value,
                "AC" => ac = value,
                "PR_U" => pr_u = value,
                "PR_C" => pr_c = value,
                "PR" => {
                    pr_u = value;
                    pr_c = value;
                }
                "UI" => ui = value,
                "S" => s = value,
                "C" => c = value,
                "I" => i = value,
                "A" => a = value,
                _ => {}
            }
        }
    }

    // Parse CVSS v3.1 metric values to numeric values
    fn cvss_v31_value(metric: char, vector_type: &str) -> f64 {
        match (vector_type, metric) {
            // Attack Vector (AV)
            ("AV", 'N') => 0.85,
            ("AV", 'A') => 0.62,
            ("AV", 'P') => 0.55,
            ("AV", 'L') => 0.20,
            // Attack Complexity (AC)
            ("AC", 'L') => 0.77,
            ("AC", 'H') => 0.44,
            // Privileges Required (PR) - v3.1 has PR_U and PR_C
            ("PR_U", 'N') => 0.85,
            ("PR_U", 'L') => 0.62,
            ("PR_U", 'H') => 0.27,
            ("PR_C", 'N') => 0.85,
            ("PR_C", 'L') => 0.62,
            ("PR_C", 'H') => 0.27,
            ("PR", 'N') => 0.85,
            ("PR", 'L') => 0.62,
            ("PR", 'H') => 0.27,
            // User Interaction (UI)
            ("UI", 'N') => 0.85,
            ("UI", 'R') => 0.62,
            // Scope (S)
            ("S", 'U') => 0.0,
            ("S", 'C') => 0.0,
            // Confidentiality (C)
            ("C", 'H') => 0.56,
            ("C", 'L') => 0.22,
            ("C", 'N') => 0.0,
            // Integrity (I)
            ("I", 'H') => 0.56,
            ("I", 'L') => 0.22,
            ("I", 'N') => 0.0,
            // Availability (A)
            ("A", 'H') => 0.56,
            ("A", 'L') => 0.22,
            ("A", 'N') => 0.0,
            _ => 0.0,
        }
    }

    // Get the ISS (Impact SubScore)
    let c_val = cvss_v31_value(c, "C");
    let i_val = cvss_v31_value(i, "I");
    let a_val = cvss_v31_value(a, "A");

    let iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val));

    // Check if scope is changed
    let scope_changed = s == 'C';

    // Get PR value based on scope
    let pr_val = if scope_changed {
        cvss_v31_value(pr_c, "PR_C")
    } else {
        cvss_v31_value(pr_u, "PR_U")
    };

    // Get other values
    let av_val = cvss_v31_value(av, "AV");
    let ac_val = cvss_v31_value(ac, "AC");
    let ui_val = cvss_v31_value(ui, "UI");

    // Calculate impact using proper CVSS v3.1 formulas
    let impact = if scope_changed {
        // Changed scope: 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15
        let iss_adj = iss - 0.029;
        let pow = iss_adj.powi(15);
        7.52 * iss_adj - 3.25 * pow
    } else {
        // Unchanged scope: 6.42 * ISS
        6.42 * iss
    };

    // Clamp impact to [0, 10]
    let impact = impact.max(0.0).min(10.0);

    // Calculate exploitability
    let exploitability = 8.22 * av_val * ac_val * pr_val * ui_val;

    // Calculate base score
    let base_score = if impact <= 0.0 {
        0.0
    } else if scope_changed {
        // Changed scope: round(min(1.08 * (impact + exploitability), 10))
        f64::min(1.08 * (impact + exploitability), 10.0)
    } else {
        // Unchanged scope: round(min(impact + exploitability, 10))
        f64::min(impact + exploitability, 10.0)
    };

    Some((base_score * 10.0).round() / 10.0)
}

/// Resolve summary: return summary if present, otherwise first sentence of details.
pub fn resolve_summary(vuln: &OSVVulnerability) -> String {
    if let Some(summary) = &vuln.summary {
        if !summary.is_empty() {
            return summary.clone();
        }
    }
    if let Some(details) = &vuln.details {
        if !details.is_empty() {
            // Get first sentence (up to 200 chars)
            let first_sentence = details
                .split(|c: char| c == '.' || c == '!' || c == '?')
                .next()
                .unwrap_or(details)
                .trim();
            let truncated = if first_sentence.len() > 200 {
                &first_sentence[..200]
            } else {
                first_sentence
            };
            return truncated.to_string();
        }
    }
    "No description".to_string()
}

const OSV_API_QUERY_BATCH: &str = "https://api.osv.dev/v1/querybatch";
const OSV_API_VULNS: &str = "https://api.osv.dev/v1/vulns";
const USER_AGENT: &str = "Poseidon/0.1.0";
const MAX_BATCH_SIZE: usize = 1000;
const MAX_RETRIES: u32 = 4;
const BASE_DELAY_MS: u64 = 500;

#[derive(Debug)]
pub struct OSVClient {
    http_client: Client,
}

impl OSVClient {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent(USER_AGENT)
            .build()
            .expect("failed to create HTTP client for OSV client");
        Self {
            http_client: client,
        }
    }

    pub fn query_batch(&self, packages: &[Package]) -> Result<Vec<Vec<OSVVulnerability>>, String> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }

        bridge::log(&format!("OSVClient: querying {} packages", packages.len()));

        let mut all_results: Vec<Vec<OSVVulnerability>> = Vec::with_capacity(packages.len());

        for chunk in packages.chunks(MAX_BATCH_SIZE) {
            let vulns = self.query_batch_chunk(chunk)?;
            all_results.extend(vulns);
        }

        Ok(all_results)
    }

    fn query_batch_chunk(
        &self,
        packages: &[Package],
    ) -> Result<Vec<Vec<OSVVulnerability>>, String> {
        let queries: Vec<OSVQuery> = packages
            .iter()
            .map(|p| OSVQuery {
                package: OSVPackage {
                    name: p.name.clone(),
                    ecosystem: p.ecosystem.clone(),
                },
                version: p.version.clone(),
            })
            .collect();

        let body = OSVBatchQuery { queries };
        let json_body = serde_json::to_string(&body).map_err(|e| e.to_string())?;

        let response = self.post_with_retries(OSV_API_QUERY_BATCH, json_body)?;
        let batch_response: OSVBatchResponse =
            serde_json::from_str(&response).map_err(|e| e.to_string())?;

        let mut results: Vec<Vec<OSVVulnerability>> = Vec::with_capacity(packages.len());
        for result in batch_response.results.iter() {
            let mut hydrated = Vec::new();
            for vuln_summary in &result.vulns {
                match self.fetch_vulnerability(&vuln_summary.id) {
                    Ok(full) => {
                        hydrated.push(full);
                    }
                    Err(e) => {
                        bridge::elog(&format!(
                            "OSVClient: failed to fetch vulnerability {}: {}",
                            vuln_summary.id, e
                        ));
                    }
                }
            }
            results.push(hydrated);
        }

        Ok(results)
    }

    fn post_with_retries(&self, url: &str, body: String) -> Result<String, String> {
        let mut attempt = 0;

        loop {
            match self
                .http_client
                .post(url)
                .header("User-Agent", USER_AGENT)
                .body(body.clone())
                .send()
            {
                Ok(response) => match response.error_for_status() {
                    Ok(resp) => {
                        return resp.text().map_err(|e| e.to_string());
                    }
                    Err(err) => {
                        if attempt >= MAX_RETRIES {
                            return Err(format!(
                                "OSV API request failed after {} attempts: {}",
                                MAX_RETRIES, err
                            ));
                        }
                        bridge::elog(&format!(
                            "OSV API error (attempt {}): {}, retrying...",
                            attempt + 1,
                            err
                        ));
                    }
                },
                Err(err) => {
                    if attempt >= MAX_RETRIES {
                        return Err(format!(
                            "OSV API request failed after {} attempts: {}",
                            MAX_RETRIES, err
                        ));
                    }
                    bridge::elog(&format!(
                        "OSV API request error (attempt {}): {}, retrying...",
                        attempt + 1,
                        err
                    ));
                }
            }

            attempt += 1;
            let delay = self.calculate_delay(attempt);
            std::thread::sleep(Duration::from_millis(delay));
        }
    }

    fn calculate_delay(&self, attempt: u32) -> u64 {
        let exponential = BASE_DELAY_MS * (2_u64.pow(attempt.min(MAX_RETRIES)));
        let jitter = ((attempt as u64) * 127) % 500;
        (exponential + jitter).min(30_000)
    }

    fn fetch_vulnerability(&self, id: &str) -> Result<OSVVulnerability, String> {
        let url = format!("{}/{}", OSV_API_VULNS, id);

        let response = self
            .http_client
            .get(&url)
            .header("User-Agent", USER_AGENT)
            .send()
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?;

        let full: OSVFullVulnerability =
            serde_json::from_str(&response.text().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;

        Ok(OSVVulnerability {
            id: full.id.unwrap_or_else(|| id.to_string()),
            summary: full.summary,
            details: full.details,
            severity: full.severity,
        })
    }
}

impl Default for OSVClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_serialization() {
        let pkg = Package {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: "npm".to_string(),
        };
        let json = serde_json::to_string(&pkg).unwrap();
        assert!(json.contains("lodash"));
        assert!(json.contains("4.17.21"));
        assert!(json.contains("npm"));
    }

    #[test]
    fn test_osv_query_serialization() {
        let query = OSVQuery {
            package: OSVPackage {
                name: "requests".to_string(),
                ecosystem: "PyPI".to_string(),
            },
            version: "2.28.0".to_string(),
        };
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("requests"));
        assert!(json.contains("2.28.0"));
        assert!(json.contains("PyPI"));
    }

    #[test]
    fn test_batch_query_serialization() {
        let queries = vec![
            OSVQuery {
                package: OSVPackage {
                    name: "lodash".to_string(),
                    ecosystem: "npm".to_string(),
                },
                version: "4.17.21".to_string(),
            },
            OSVQuery {
                package: OSVPackage {
                    name: "requests".to_string(),
                    ecosystem: "PyPI".to_string(),
                },
                version: "2.28.0".to_string(),
            },
        ];
        let batch = OSVBatchQuery { queries };
        let json = serde_json::to_string(&batch).unwrap();
        assert!(json.contains("queries"));
        assert!(json.contains("lodash"));
        assert!(json.contains("requests"));
    }

    #[test]
    fn test_osv_vulnerability_deserialization_single_severity() {
        let json = r#"{
            "id": "OSV-2023-1234",
            "summary": "Test vulnerability",
            "details": "Detailed description",
            "severity": [{
                "type": "CVSS_V3",
                "score": "9.8"
            }]
        }"#;
        let vuln: OSVFullVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.id, Some("OSV-2023-1234".to_string()));
        assert_eq!(vuln.summary, Some("Test vulnerability".to_string()));
        assert_eq!(vuln.severity.len(), 1);
        assert_eq!(vuln.severity[0].score.as_deref(), Some("9.8"));
    }

    #[test]
    fn test_osv_vulnerability_deserialization_severity_array() {
        let json = r#"{
            "id": "GHSA-xxxx",
            "summary": "Test vulnerability",
            "details": "Detailed description",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                {"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}
            ]
        }"#;
        let vuln: OSVFullVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.id, Some("GHSA-xxxx".to_string()));
        assert_eq!(vuln.severity.len(), 2);
        assert_eq!(vuln.severity[0].r#type.as_deref(), Some("CVSS_V3"));
        assert_eq!(vuln.severity[1].r#type.as_deref(), Some("CVSS_V2"));
    }

    #[test]
    fn test_osv_vulnerability_deserialization_database_specific() {
        let json = r#"{
            "id": "PYSEC-1234",
            "summary": "PySEC vulnerability",
            "details": "Python security advisory",
            "database_specific": {
                "severity": "HIGH",
                "url": "https://example.com"
            }
        }"#;
        let vuln: OSVFullVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.id, Some("PYSEC-1234".to_string()));
        assert!(vuln.database_specific.is_some());
        let db = vuln.database_specific.unwrap();
        assert!(db.as_object().is_some());
    }

    #[test]
    fn test_resolve_severity_numeric_score() {
        let vuln = OSVVulnerability {
            id: "TEST-1".to_string(),
            summary: Some("Test".to_string()),
            details: None,
            severity: vec![
                OSVSeverity {
                    r#type: Some("CVSS_V3".to_string()),
                    score: Some("9.8".to_string()),
                },
            ],
        };
        let (score, level) = resolve_severity(&vuln);
        assert_eq!(score, 9.8);
        assert_eq!(level, "critical");
    }

    #[test]
    fn test_resolve_severity_cvss_v31_vector() {
        let vuln = OSVVulnerability {
            id: "TEST-2".to_string(),
            summary: Some("Test".to_string()),
            details: None,
            severity: vec![
                OSVSeverity {
                    r#type: Some("CVSS_V3".to_string()),
                    score: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                },
            ],
        };
        let (score, level) = resolve_severity(&vuln);
        // This vector should parse to approximately 10.0 (critical)
        assert!(score >= 9.0);
        assert_eq!(level, "critical");
    }

    #[test]
    fn test_resolve_severity_empty_severity() {
        let vuln = OSVVulnerability {
            id: "TEST-3".to_string(),
            summary: Some("Test".to_string()),
            details: None,
            severity: vec![],
        };
        let (score, level) = resolve_severity(&vuln);
        assert_eq!(score, 5.0);
        assert_eq!(level, "medium");
    }

    #[test]
    fn test_resolve_severity_low_score() {
        let vuln = OSVVulnerability {
            id: "TEST-4".to_string(),
            summary: Some("Test".to_string()),
            details: None,
            severity: vec![
                OSVSeverity {
                    r#type: Some("CVSS_V3".to_string()),
                    score: Some("3.5".to_string()),
                },
            ],
        };
        let (score, level) = resolve_severity(&vuln);
        assert_eq!(score, 3.5);
        assert_eq!(level, "low");
    }

    #[test]
    fn test_resolve_summary_with_summary() {
        let vuln = OSVVulnerability {
            id: "TEST-5".to_string(),
            summary: Some("This is the summary".to_string()),
            details: Some("This is a very long details field that should not be used when summary is present.".to_string()),
            severity: vec![],
        };
        let summary = resolve_summary(&vuln);
        assert_eq!(summary, "This is the summary");
    }

    #[test]
    fn test_resolve_summary_without_summary() {
        let vuln = OSVVulnerability {
            id: "TEST-6".to_string(),
            summary: None,
            details: Some("This is the details. It should become the summary if summary is missing.".to_string()),
            severity: vec![],
        };
        let summary = resolve_summary(&vuln);
        assert_eq!(summary, "This is the details");
    }

    #[test]
    fn test_resolve_summary_truncation() {
        let long_details = "A".repeat(300);
        let vuln = OSVVulnerability {
            id: "TEST-7".to_string(),
            summary: None,
            details: Some(long_details),
            severity: vec![],
        };
        let summary = resolve_summary(&vuln);
        assert_eq!(summary.len(), 200);
    }

    #[test]
    fn test_resolve_summary_no_summary_no_details() {
        let vuln = OSVVulnerability {
            id: "TEST-8".to_string(),
            summary: None,
            details: None,
            severity: vec![],
        };
        let summary = resolve_summary(&vuln);
        assert_eq!(summary, "No description");
    }

    #[test]
    fn test_resolve_severity_full_with_database_specific() {
        let json = r#"{
            "id": "PYSEC-9999",
            "summary": "PySEC vulnerability",
            "details": "Details here",
            "severity": [],
            "database_specific": {
                "severity": "CRITICAL"
            }
        }"#;
        let full: OSVFullVulnerability = serde_json::from_str(json).unwrap();
        let (score, level) = resolve_severity_full(&full);
        assert_eq!(level, "critical");
        assert_eq!(score, 9.0);
    }

    #[test]
    fn test_batch_response_deserialization() {
        let json = r#"{
            "results": [
                {
                    "vulns": [
                        { "id": "OSV-2023-001", "modified": "2023-01-01T00:00:00Z" },
                        { "id": "OSV-2023-002" }
                    ]
                },
                {
                    "vulns": []
                }
            ]
        }"#;
        let response: OSVBatchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.results.len(), 2);
        assert_eq!(response.results[0].vulns.len(), 2);
        assert_eq!(response.results[1].vulns.len(), 0);
    }

    #[test]
    fn test_osv_client_creation() {
        let client = OSVClient::new();
        assert!(format!("{:?}", client).contains("OSVClient"));
    }

    #[test]
    fn test_delay_calculation() {
        let client = OSVClient::new();
        let delay1 = client.calculate_delay(0);
        let delay2 = client.calculate_delay(1);
        let delay3 = client.calculate_delay(2);

        assert!(delay1 >= BASE_DELAY_MS);
        assert!(delay2 > delay1);
        assert!(delay3 > delay2);
        assert!(delay1 <= 30_000);
        assert!(delay2 <= 30_000);
        assert!(delay3 <= 30_000);
    }

    #[test]
    fn test_cvss_v31_high_score() {
        // Test a known high-severity CVSS 3.1 vector
        let vuln = OSVVulnerability {
            id: "TEST-CVSS-HIGH".to_string(),
            summary: Some("Critical vulnerability".to_string()),
            details: None,
            severity: vec![
                OSVSeverity {
                    r#type: Some("CVSS_V3".to_string()),
                    score: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                },
            ],
        };
        let (score, level) = resolve_severity(&vuln);
        assert_eq!(level, "critical");
        assert!(score >= 9.0);
    }

    #[test]
    fn test_cvss_v31_medium_score() {
        // Test a medium severity CVSS 3.1 vector
        let vuln = OSVVulnerability {
            id: "TEST-CVSS-MED".to_string(),
            summary: Some("Medium vulnerability".to_string()),
            details: None,
            severity: vec![
                OSVSeverity {
                    r#type: Some("CVSS_V3".to_string()),
                    score: Some("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L".to_string()),
                },
            ],
        };
        let (score, level) = resolve_severity(&vuln);
        assert!(score >= 4.0);
        assert!(score < 7.0);
        assert_eq!(level, "medium");
    }
}
