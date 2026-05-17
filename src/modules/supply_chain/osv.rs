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
    pub severity: Option<OSVSeverity>,
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
    modified: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OSVFullVulnerability {
    id: Option<String>,
    summary: Option<String>,
    details: Option<String>,
    severity: Option<OSVSeverity>,
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
                if let Ok(full) = self.fetch_vulnerability(&vuln_summary.id) {
                    hydrated.push(full);
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
    fn test_osv_vulnerability_deserialization() {
        let json = r#"{
            "id": "OSV-2023-1234",
            "summary": "Test vulnerability",
            "details": "Detailed description",
            "severity": {
                "type": "CVSS_V3",
                "score": "9.8"
            }
        }"#;
        let vuln: OSVFullVulnerability = serde_json::from_str(json).unwrap();
        assert_eq!(vuln.id, Some("OSV-2023-1234".to_string()));
        assert_eq!(vuln.summary, Some("Test vulnerability".to_string()));
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
}
