use serde_json::{Value, json};

use crate::modules::tui::bridge;

pub mod lockfile;
pub mod osv;
pub mod registry;
pub mod typosquat;
pub mod get_dependency_git_url;
pub mod universal_llm_comms;
pub mod analysis_cache;
pub mod commit_fetcher;
pub mod deep_analysis;

use lockfile::{detect_lockfile_type, parse_lockfile};
use osv::{OSVClient, Package as OSVPackage};
use registry::RegistryChecker;
use typosquat::TyposquatChecker;
use get_dependency_git_url::GitUrlFinder;
use analysis_cache::AnalysisCache;
use commit_fetcher::CommitFetcher;

/// Warning levels for packages based on detected issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WarningLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl WarningLevel {
    fn as_str(&self) -> &'static str {
        match self {
            WarningLevel::Safe => "safe",
            WarningLevel::Low => "low",
            WarningLevel::Medium => "medium",
            WarningLevel::High => "high",
            WarningLevel::Critical => "critical",
        }
    }

    fn from_vulnerability_severity(severity: &str) -> Self {
        let severity_lower = severity.to_lowercase();
        if severity_lower.contains("critical") || severity_lower.contains("high") {
            WarningLevel::High
        } else if severity_lower.contains("medium") {
            WarningLevel::Medium
        } else if severity_lower.contains("low") {
            WarningLevel::Low
        } else {
            WarningLevel::Medium
        }
    }
}

/// A package issue with associated warning level.
#[derive(Debug, Clone)]
pub struct PackageIssue {
    pub description: String,
    pub level: WarningLevel,
}

impl PackageIssue {
    fn new(description: String, level: WarningLevel) -> Self {
        Self { description, level }
    }
}

/// Per-package analysis result.
#[derive(Debug, Clone)]
pub struct PackageAnalysis {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub warning_level: WarningLevel,
    pub issues: Vec<String>,
}

impl PackageAnalysis {
    fn new(name: String, version: String, ecosystem: String) -> Self {
        Self {
            name,
            version,
            ecosystem,
            warning_level: WarningLevel::Safe,
            issues: Vec::new(),
        }
    }

    fn add_issue(&mut self, issue: String) {
        self.issues.push(issue);
    }

    fn update_warning_level(&mut self, level: WarningLevel) {
        if level > self.warning_level {
            self.warning_level = level;
        }
    }
}

/// Overall sentiment based on package analysis results.
fn compute_overall_sentiment(packages: &[PackageAnalysis]) -> &'static str {
    let mut highest = WarningLevel::Safe;
    for pkg in packages {
        if pkg.warning_level > highest {
            highest = pkg.warning_level;
        }
    }
    highest.as_str()
}

/// Count packages by warning level.
fn count_by_level(packages: &[PackageAnalysis]) -> (usize, usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut safe = 0;

    for pkg in packages {
        match pkg.warning_level {
            WarningLevel::Critical => critical += 1,
            WarningLevel::High => high += 1,
            WarningLevel::Medium => medium += 1,
            WarningLevel::Low => low += 1,
            WarningLevel::Safe => safe += 1,
        }
    }
    (critical, high, medium, low, safe)
}

#[derive(Debug)]
pub struct SupplyChainScanner {
    osv_client: OSVClient,
    registry_checker: RegistryChecker,
    git_url_finder: GitUrlFinder,
    commit_fetcher: CommitFetcher,
    analysis_cache: AnalysisCache,
}

impl SupplyChainScanner {
    pub fn new() -> Self {
        Self {
            osv_client: OSVClient::new(),
            registry_checker: RegistryChecker::new(),
            git_url_finder: GitUrlFinder::new(),
            commit_fetcher: CommitFetcher::new(),
            analysis_cache: AnalysisCache::default(),
        }
    }

    pub fn quick_analyze(&self, lockfile_content: &str, filename: Option<&str>) -> Value {
        bridge::log("SupplyChainScanner: quick_analyze called");

        // Step 1: Detect lockfile type
        let lockfile_type = detect_lockfile_type(filename.unwrap_or(""));
        if lockfile_type.is_none() {
            bridge::elog("SupplyChainScanner: unknown lockfile type");
            return json!({
                "overall_sentiment": "safe",
                "packages": [],
                "summary": "Unknown lockfile type",
                "error": "Could not detect lockfile type from filename"
            });
        }
        let lockfile_type = lockfile_type.unwrap();
        let ecosystem = lockfile_type.ecosystem().as_str();
        bridge::log(&format!("SupplyChainScanner: detected lockfile type: {:?}", lockfile_type));

        // Step 2: Parse packages from lockfile
        let packages = match parse_lockfile(filename.unwrap_or(""), lockfile_content) {
            Ok(pkgs) => pkgs,
            Err(e) => {
                bridge::elog(&format!("SupplyChainScanner: failed to parse lockfile: {}", e));
                return json!({
                    "overall_sentiment": "safe",
                    "packages": [],
                    "summary": &format!("Failed to parse lockfile: {}", e)
                });
            }
        };

        if packages.is_empty() {
            return json!({
                "overall_sentiment": "safe",
                "packages": [],
                "summary": "No packages found in lockfile"
            });
        }

        bridge::log(&format!("SupplyChainScanner: parsed {} packages", packages.len()));

        // Convert to OSV package format for vulnerability querying
        let osv_packages: Vec<OSVPackage> = packages
            .iter()
            .map(|p| OSVPackage {
                name: p.name.clone(),
                version: p.version.clone(),
                ecosystem: ecosystem.to_string(),
            })
            .collect();

        // Step 3: Query OSV API for vulnerabilities
        let vulnerability_results = self.osv_client.query_batch(&osv_packages).unwrap_or_else(|e| {
            bridge::elog(&format!("SupplyChainScanner: OSV query failed: {}", e));
            vec![Vec::new(); packages.len()]
        });

        // Create typosquat checker for this ecosystem
        let typosquat_checker = TyposquatChecker::new(ecosystem);

        // Step 4-6: Analyze each package and collect issues
        let mut package_analyses: Vec<PackageAnalysis> = Vec::new();

        for (i, pkg) in packages.iter().enumerate() {
            let mut analysis = PackageAnalysis::new(
                pkg.name.clone(),
                pkg.version.clone(),
                ecosystem.to_string(),
            );

            // Step 3: Process vulnerabilities from OSV
            if i < vulnerability_results.len() {
                for vuln in &vulnerability_results[i] {
                    let severity_str = vuln
                        .severity
                        .as_ref()
                        .and_then(|s| s.score.as_deref())
                        .unwrap_or("medium");

                    let level = WarningLevel::from_vulnerability_severity(severity_str);
                    analysis.update_warning_level(level);
                    analysis.add_issue(format!("{}: {}", vuln.id, vuln.summary.as_deref().unwrap_or("No description")));
                }
            }

            // Step 4: Check registry metadata
            let registry_warnings = self.registry_checker.check_package(&pkg.name, &pkg.version, ecosystem);
            for warning in registry_warnings {
                if warning.contains("yanked") {
                    analysis.update_warning_level(WarningLevel::Critical);
                } else if warning.contains("week old") {
                    analysis.update_warning_level(WarningLevel::Medium);
                }
                analysis.add_issue(warning);
            }

            // Step 5: Check typosquatting
            let typo_warnings = typosquat_checker.check_package(&pkg.name, ecosystem);
            for warning in typo_warnings {
                analysis.update_warning_level(WarningLevel::High);
                analysis.add_issue(warning);
            }

            package_analyses.push(analysis);
        }

        // Compute overall sentiment and summary
        let overall_sentiment = compute_overall_sentiment(&package_analyses);
        let (critical, high, medium, low, safe) = count_by_level(&package_analyses);
        let summary = format!("{} critical, {} high, {} medium, {} low, {} safe",
            critical, high, medium, low, safe);

        // Build per-package JSON output
        let packages_json: Vec<Value> = package_analyses
            .iter()
            .map(|p| {
                json!({
                    "name": p.name,
                    "version": p.version,
                    "ecosystem": p.ecosystem,
                    "warning_level": p.warning_level.as_str(),
                    "issues": p.issues
                })
            })
            .collect();

        json!({
            "overall_sentiment": overall_sentiment,
            "packages": packages_json,
            "summary": summary
        })
    }

    pub fn deep_analyze(&self, lockfiles: Vec<(String, String)>) -> Value {
        bridge::log(&format!("SupplyChainScanner: deep_analyze called with {} lockfiles", lockfiles.len()));
        deep_analysis::run_deep_analysis(
            lockfiles,
            &self.osv_client,
            &self.registry_checker,
            &self.git_url_finder,
            &self.commit_fetcher,
            &self.analysis_cache,
        )
    }

    pub fn status(&self) -> Value {
        bridge::log("SupplyChainScanner: status called");
        let llm_provider = std::env::var("LLM_PROVIDER")
            .unwrap_or_else(|_| "not configured".to_string());
        json!({
            "status": "ready",
            "service": "supply_chain_scanner",
            "version": "0.1.0",
            "llm_provider": llm_provider,
            "cache_entries": self.analysis_cache.len(),
            "cache_hits": self.analysis_cache.hit_count(),
            "cache_misses": self.analysis_cache.miss_count(),
        })
    }
}

impl Default for SupplyChainScanner {
    fn default() -> Self {
        Self::new()
    }
}

pub fn handle_quick_analyze(body: &str) -> Value {
    let scanner = SupplyChainScanner::new();

    // Try to parse the request body as JSON to extract lockfile content and filename
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) {
        let lockfile_content = parsed.get("lockfile_content")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let filename = parsed.get("filename")
            .and_then(|v| v.as_str());
        scanner.quick_analyze(lockfile_content, filename)
    } else {
        // Fall back to treating the body as raw lockfile content
        scanner.quick_analyze(body, None)
    }
}

pub fn handle_deep_analyze(body: &str) -> Value {
    let scanner = SupplyChainScanner::new();

    // Parse the request body as JSON to extract lockfile(s)
    if let Ok(parsed) = serde_json::from_str::<Value>(body) {
        // Support both single lockfile and batch formats
        if let Some(lockfiles) = parsed.get("lockfiles").and_then(|v| v.as_array()) {
            // Batch format: {"lockfiles": [{"filename": "...", "content": "..."}]}
            let parsed_lockfiles: Vec<(String, String)> = lockfiles.iter()
                .filter_map(|lf| {
                    let filename = lf.get("filename").and_then(|v| v.as_str())?;
                    let content = lf.get("content").and_then(|v| v.as_str())?;
                    Some((filename.to_string(), content.to_string()))
                })
                .collect();
            if parsed_lockfiles.is_empty() {
                return json!({"error": "No valid lockfiles found in request"});
            }
            scanner.deep_analyze(parsed_lockfiles)
        } else if let Some(content) = parsed.get("lockfile_content").and_then(|v| v.as_str()) {
            // Single format: {"lockfile_content": "...", "filename": "..."}
            let filename = parsed.get("filename")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown.lock")
                .to_string();
            scanner.deep_analyze(vec![(filename, content.to_string())])
        } else if let Some(content) = parsed.get("content").and_then(|v| v.as_str()) {
            // Minimal single format: {"content": "...", "filename": "..."}
            let filename = parsed.get("filename")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown.lock")
                .to_string();
            scanner.deep_analyze(vec![(filename, content.to_string())])
        } else {
            json!({"error": "Request must contain 'lockfiles' (array) or 'lockfile_content' (string)"})
        }
    } else {
        // Fallback: treat raw body as a single unnamed lockfile
        scanner.deep_analyze(vec![("unknown.lock".to_string(), body.to_string())])
    }
}

pub fn handle_status() -> Value {
    let scanner = SupplyChainScanner::new();
    scanner.status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_creation() {
        let scanner = SupplyChainScanner::new();
        assert!(!format!("{:?}", scanner).is_empty());
    }

    #[test]
    fn test_quick_analyze_unknown_lockfile() {
        let scanner = SupplyChainScanner::new();
        let result = scanner.quick_analyze("some content", Some("unknown.xyz"));
        assert!(result.get("overall_sentiment").is_some());
        assert!(result.get("packages").is_some());
        assert!(result.get("summary").is_some());
    }

    #[test]
    fn test_quick_analyze_with_filename() {
        let scanner = SupplyChainScanner::new();
        let content = r#"{
  "lockfileVersion": 2,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}"#;
        let result = scanner.quick_analyze(content, Some("package-lock.json"));
        assert!(result.get("overall_sentiment").is_some());
        assert!(result.get("packages").is_some());
    }

    #[test]
    fn test_deep_analyze_stub() {
        let scanner = SupplyChainScanner::new();
        let result = scanner.deep_analyze(vec![("test.lock".to_string(), "test content".to_string())]);
        assert!(result.get("analysis_timestamp").is_some() || result.get("status").is_some());
    }

    #[test]
    fn test_status_stub() {
        let scanner = SupplyChainScanner::new();
        let result = scanner.status();
        assert_eq!(result["status"], "ready");
    }

    #[test]
    fn test_handler_functions() {
        let quick = handle_quick_analyze(r#"{"lockfile_content": "test", "filename": "Cargo.lock"}"#);
        assert!(quick.get("overall_sentiment").is_some());

        let deep = handle_deep_analyze("yarn.lock content");
        assert!(deep.get("error").is_some() || deep.get("analysis_timestamp").is_some());

        let status = handle_status();
        assert_eq!(status["status"], "ready");
    }

    #[test]
    fn test_handler_functions_fallback() {
        let quick = handle_quick_analyze("raw lockfile content");
        assert!(quick.get("overall_sentiment").is_some());
    }
}