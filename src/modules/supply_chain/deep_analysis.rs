//! Deep analysis pipeline for supply chain attack detection.
//!
//! 10-step pipeline:
//! 1. Receive lockfile(s)
//! 2. Parse into dependencies + versions (reuse lockfile::parse_lockfile)
//! 3. Build recursive dependency tree with hierarchy
//! 4. Quick analysis on all deps (reuse OSVClient, RegistryChecker, TyposquatChecker)
//! 5. Filter: only WarningLevel::Critical → rejected; others pass
//! 6. Git URL lookup for passing top-level deps (reuse GitUrlFinder)
//! 7. Fetch last 10 commits + diffs (reuse CommitFetcher)
//! 8. AI commit analysis via LLM (reuse universal_llm_comms::llm_completion, max 15 parallel)
//! 9. Aggregate per-commit verdicts per package
//! 10. Output hierarchical JSON
//!
//! Uses AnalysisCache for TTL-based caching and CommitFetcher for commit fetching.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};

use crate::modules::tui::bridge;

use super::WarningLevel;
use super::analysis_cache::{AnalysisCache, CommitInfo};
use super::commit_fetcher::CommitFetcher;
use super::get_dependency_git_url::GitUrlFinder;
use super::lockfile::{detect_lockfile_type, parse_lockfile};
use super::osv::OSVClient;
use super::registry::RegistryChecker;
use super::typosquat::TyposquatChecker;
use super::universal_llm_comms::LlmClient;

/// Verdict from quick analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum AnalysisVerdict {
    Pass,
    Rejected,
}

/// Verdict from commit analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum CommitVerdict {
    Allow,
    Suspicious,
    Malicious,
    Uncertain,
}

/// Result from single commit analysis.
#[derive(Debug, Clone)]
pub struct CommitDetail {
    pub hash: String,
    pub verdict: CommitVerdict,
    pub confidence: f64,
    pub reasons: Vec<String>,
    pub suspicious_patterns: Vec<String>,
}

/// Aggregated commit analysis result for a package.
#[derive(Debug, Clone)]
pub struct CommitAnalysisResult {
    pub verdict: CommitVerdict,
    pub confidence: f64,
    pub reasons: Vec<String>,
    pub commits_analyzed: usize,
    pub commit_details: Vec<CommitDetail>,
    pub error: Option<String>,
}

/// Quick analysis result for a package.
#[derive(Debug, Clone)]
pub struct QuickAnalysisResult {
    pub verdict: AnalysisVerdict,
    pub warning_level: WarningLevel,
    pub issues: Vec<String>,
}

/// A node in the dependency hierarchy.
#[derive(Debug, Clone)]
pub struct DependencyNode {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub is_top_level: bool,
    pub parent_refs: Vec<(String, String)>, // (parent_name, parent_version) tuples
    pub quick_analysis: QuickAnalysisResult,
    pub git_url: Option<String>,
    pub hosting_platform: Option<String>,
    pub no_git_url_notice: bool,
    pub commit_analysis: Option<CommitAnalysisResult>,
    pub children: Vec<DependencyNode>,
    pub error: Option<String>,
}

/// Summary of deep analysis.
#[derive(Debug, Clone)]
pub struct DeepAnalysisSummary {
    pub total_packages: usize,
    pub flagged: usize,
    pub threshold: String,
    pub cache_hits: usize,
    pub api_calls_made: usize,
}

/// AI analysis status for the output JSON.
#[derive(Debug, Clone, PartialEq)]
pub enum AiStatus {
    Ok,
    NotConfigured,
    Failed,
}

/// Full deep analysis output.
#[derive(Debug, Clone)]
pub struct DeepAnalysisOutput {
    pub analysis_timestamp: String,
    pub ai_status: AiStatus,
    pub error: Option<String>,
    pub lockfile_sources: Vec<String>,
    pub summary: DeepAnalysisSummary,
    pub tree: Vec<DependencyNode>,
}

/// Normalizes ecosystem string to registry name for GitUrlFinder.
fn ecosystem_to_registry(ecosystem: &str) -> String {
    match ecosystem {
        "crates.io" | "npm" => ecosystem.to_string(),
        "PyPI" | "pypi" => "pypi".to_string(),
        "Go" | "go" => "go".to_string(),
        "RubyGems" | "rubygems" => "rubygems".to_string(),
        "Packagist" | "packagist" => "packagist".to_string(),
        "Maven" | "maven" => "maven".to_string(),
        "NuGet" | "nuget" => "nuget".to_string(),
        "Pub" | "pub" => "pub".to_string(),
        "Hex" | "hex" => "hex".to_string(),
        _ => ecosystem.to_lowercase(),
    }
}

/// Builds the LLM prompt for a single commit analysis.
fn build_llm_prompt(commit: &CommitInfo) -> String {
    format!(
        r#"You are a cybersecurity agent analyzing a single code commit for supply chain compromise.

Focus on these suspicious patterns:
- Obfuscated/minified/encoded code (base64, hex, eval(), string encoding)
- New network calls (fetch, curl, request, post) to unfamiliar hosts/IPs
- Modified install scripts (postinstall, build, setup, preinstall)
- Changed repository URLs or download URLs in the code
- Code reading environment variables, config files, or credentials
- Unexpected binary blobs or large encoded strings added
- Backdoored imports or modified require/import paths
- Suspicious file writes to system directories

Ignore: version bumps in metadata, whitespace-only changes, lockfile-only changes, README/doc updates, dependency version bumps without code changes.

Commit: {hash}
Author: {author}
Date: {date}
Message: {message}
Diff:
{diff}

Respond with EXACTLY this JSON — no markdown fences, no explanatory text, exactly this structure:
{{"verdict": "allow", "confidence": 1.0, "reasons": [], "suspicious_patterns": []}}

Verdict must be one of: "allow", "suspicious", "malicious"
Confidence must be a float 0.0-1.0
Reasons is an array of strings explaining the verdict
Suspicious_patterns is an array of detected pattern names (empty if allow)"#,
        hash = commit.hash,
        author = commit.author,
        date = commit.date,
        message = commit.message,
        diff = commit.diff
    )
}

/// Parses the LLM response into a CommitDetail.
fn parse_llm_response(response: &str) -> Result<CommitDetail, String> {
    // Try to extract JSON from the response (in case there's extra text)
    let json_str = if let Some(start) = response.find('{') {
        if let Some(end) = response.rfind('}') {
            &response[start..=end]
        } else {
            response
        }
    } else {
        response
    };

    let parsed: Value = serde_json::from_str(json_str)
        .map_err(|e| format!("failed to parse JSON: {} - raw: {}", e, response))?;

    let verdict_str = parsed
        .get("verdict")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("missing verdict in response: {}", json_str))?;

    let verdict = match verdict_str.to_lowercase().as_str() {
        "allow" => CommitVerdict::Allow,
        "suspicious" => CommitVerdict::Suspicious,
        "malicious" => CommitVerdict::Malicious,
        _ => CommitVerdict::Uncertain,
    };

    let confidence = parsed
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.5);

    let reasons: Vec<String> = parsed
        .get("reasons")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let suspicious_patterns: Vec<String> = parsed
        .get("suspicious_patterns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let hash = parsed
        .get("hash")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_default();

    Ok(CommitDetail {
        hash,
        verdict,
        confidence,
        reasons,
        suspicious_patterns,
    })
}

/// Aggregates per-commit verdicts into a package-level verdict.
fn aggregate_commit_verdicts(details: &[CommitDetail]) -> (CommitVerdict, f64, Vec<String>) {
    if details.is_empty() {
        return (CommitVerdict::Allow, 1.0, Vec::new());
    }

    let mut has_malicious = false;
    let has_suspicious = details
        .iter()
        .any(|d| d.verdict == CommitVerdict::Suspicious);
    let total_confidence: f64 =
        details.iter().map(|d| d.confidence).sum::<f64>() / details.len() as f64;

    for detail in details {
        if detail.verdict == CommitVerdict::Malicious {
            has_malicious = true;
            break;
        }
    }

    let verdict = if has_malicious {
        CommitVerdict::Malicious
    } else if has_suspicious {
        CommitVerdict::Suspicious
    } else {
        CommitVerdict::Allow
    };

    // Collect unique reasons
    let mut all_reasons: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for detail in details {
        for reason in &detail.reasons {
            if seen.insert(reason.clone()) {
                all_reasons.push(reason.clone());
            }
        }
    }

    (verdict, total_confidence, all_reasons)
}

/// Returns current UTC time as a Unix timestamp string (seconds.millisZ).
fn now_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    format!("{}.{:03}Z", secs, millis)
}

/// Converts a DependencyNode to a serde_json::Value.
fn dependency_node_to_json(node: &DependencyNode) -> Value {
    let quick_verdict = match node.quick_analysis.verdict {
        AnalysisVerdict::Pass => "pass",
        AnalysisVerdict::Rejected => "rejected",
    };

    let warning_level_str = match node.quick_analysis.warning_level {
        WarningLevel::Safe => "safe",
        WarningLevel::Low => "low",
        WarningLevel::Medium => "medium",
        WarningLevel::High => "high",
        WarningLevel::Critical => "critical",
    };

    let commit_analysis_json = node.commit_analysis.as_ref().map(|ca| {
        let verdict_str = match ca.verdict {
            CommitVerdict::Allow => "allow",
            CommitVerdict::Suspicious => "suspicious",
            CommitVerdict::Malicious => "malicious",
            CommitVerdict::Uncertain => "uncertain",
        };

        let commit_details_json: Vec<Value> = ca
            .commit_details
            .iter()
            .map(|cd| {
                let cd_verdict = match cd.verdict {
                    CommitVerdict::Allow => "allow",
                    CommitVerdict::Suspicious => "suspicious",
                    CommitVerdict::Malicious => "malicious",
                    CommitVerdict::Uncertain => "uncertain",
                };
                json!({
                    "hash": cd.hash,
                    "verdict": cd_verdict,
                    "confidence": cd.confidence,
                    "reasons": cd.reasons,
                    "suspicious_patterns": cd.suspicious_patterns
                })
            })
            .collect();

        json!({
            "verdict": verdict_str,
            "confidence": ca.confidence,
            "reasons": ca.reasons,
            "commits_analyzed": ca.commits_analyzed,
            "commit_details": commit_details_json,
            "error": ca.error
        })
    });

    json!({
        "name": node.name,
        "version": node.version,
        "ecosystem": node.ecosystem,
        "quick_analysis": {
            "verdict": quick_verdict,
            "warning_level": warning_level_str,
            "issues": node.quick_analysis.issues
        },
        "git_url": node.git_url,
        "hosting_platform": node.hosting_platform,
        "no_git_url_notice": node.no_git_url_notice,
        "commit_analysis": commit_analysis_json,
        "children": node.children.iter().map(dependency_node_to_json).collect::<Vec<Value>>(),
        "error": node.error
    })
}

/// Run the full deep analysis pipeline.
/// `lockfiles` is a Vec of (filename, content) tuples.
/// Returns the complete analysis as JSON Value.
pub fn run_deep_analysis(
    lockfiles: Vec<(String, String)>,
    osv_client: &OSVClient,
    registry_checker: &RegistryChecker,
    git_url_finder: &GitUrlFinder,
    commit_fetcher: &CommitFetcher,
    analysis_cache: &AnalysisCache,
) -> Value {
    bridge::log(&format!(
        "DeepAnalysis: starting with {} lockfiles",
        lockfiles.len()
    ));

    // Step 1-2: Parse each lockfile into packages
    let mut all_packages: Vec<(String, String, String, String)> = Vec::new();
    let mut lockfile_sources: Vec<String> = Vec::new();
    let mut ecosystem_per_lockfile: HashMap<String, String> = HashMap::new();

    for (filename, content) in &lockfiles {
        lockfile_sources.push(filename.clone());

        let lockfile_type = match detect_lockfile_type(filename) {
            Some(t) => t,
            None => {
                bridge::elog(&format!(
                    "DeepAnalysis: unknown lockfile type: {}",
                    filename
                ));
                continue;
            }
        };
        let ecosystem = lockfile_type.ecosystem().as_str().to_string();
        ecosystem_per_lockfile.insert(filename.clone(), ecosystem.clone());

        match parse_lockfile(filename, content) {
            Ok(packages) => {
                bridge::log(&format!(
                    "DeepAnalysis: parsed {} packages from {}",
                    packages.len(),
                    filename
                ));
                for pkg in packages {
                    all_packages.push((
                        pkg.name.clone(),
                        pkg.version.clone(),
                        ecosystem.clone(),
                        filename.clone(),
                    ));
                }
            }
            Err(e) => {
                bridge::elog(&format!(
                    "DeepAnalysis: failed to parse {}: {}",
                    filename, e
                ));
            }
        }
    }

    // Deduplicate by (name, version, ecosystem)
    let mut unique_packages: Vec<(String, String, String, String)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for pkg in &all_packages {
        let key = format!("{}@{}@{}", pkg.0, pkg.1, pkg.2);
        if seen.insert(key) {
            unique_packages.push(pkg.clone());
        }
    }

    bridge::log(&format!(
        "DeepAnalysis: {} unique packages after deduplication",
        unique_packages.len()
    ));

    // Step 3: Build parent tracking and identify top-level packages
    // For simplicity in this phase, packages from each lockfile that don't appear
    // as a dependency of another package are considered top-level.
    // Since we don't have full tree info, we mark all packages as top-level initially
    // and track parent refs based on lockfile associations.

    let mut parent_refs: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut top_level_keys: HashSet<String> = HashSet::new();

    // All unique packages are initially treated as potential top-level
    for (name, version, ecosystem, _) in &unique_packages {
        let key = format!("{}@{}@{}", name, version, ecosystem);
        top_level_keys.insert(key);
    }

    // Step 4: Run quick analysis on all unique packages
    let mut quick_analysis_results: HashMap<String, QuickAnalysisResult> = HashMap::new();
    let mut api_calls_made = 0;

    // Build OSV packages for batch query
    let osv_packages: Vec<super::osv::Package> = unique_packages
        .iter()
        .map(|(name, version, ecosystem, _)| super::osv::Package {
            name: name.clone(),
            version: version.clone(),
            ecosystem: ecosystem.clone(),
        })
        .collect();

    // Query OSV in batch
    let vulnerability_results = match osv_client.query_batch(&osv_packages) {
        Ok(results) => {
            api_calls_made += 1;
            results
        }
        Err(e) => {
            bridge::elog(&format!("DeepAnalysis: OSV query failed: {}", e));
            vec![Vec::new(); unique_packages.len()]
        }
    };

    // Process each package with quick analysis
    for (i, (name, version, ecosystem, _)) in unique_packages.iter().enumerate() {
        let key = format!("{}@{}@{}", name, version, ecosystem);
        let ecosystem_str = ecosystem.as_str();

        // Create typosquat checker for this ecosystem
        let typosquat_checker = TyposquatChecker::new(ecosystem_str);

        // Get vulnerabilities
        let vulns = if i < vulnerability_results.len() {
            vulnerability_results[i].clone()
        } else {
            Vec::new()
        };

        // Determine warning level from vulnerabilities
        let mut warning_level = WarningLevel::Safe;
        let mut issues: Vec<String> = Vec::new();

        for vuln in &vulns {
            let (_, level_str) = super::osv::resolve_severity(vuln);
            let level = WarningLevel::from_vulnerability_severity(level_str);

            if level > warning_level {
                warning_level = level;
            }
            issues.push(format!(
                "{}: {}",
                vuln.id,
                super::osv::resolve_summary(vuln)
            ));
        }

        // Check registry metadata
        let registry_warnings = registry_checker.check_package(name, version, ecosystem_str);
        for warning in &registry_warnings {
            if warning.contains("yanked") {
                if warning_level < WarningLevel::Critical {
                    warning_level = WarningLevel::Critical;
                }
            } else if warning.contains("week old") || warning.contains("days ago") {
                if warning_level < WarningLevel::Medium {
                    warning_level = WarningLevel::Medium;
                }
            }
            issues.push(warning.clone());
        }

        // Check typosquatting
        let typo_warnings = typosquat_checker.check_package(name, ecosystem_str);
        for warning in &typo_warnings {
            if warning_level < WarningLevel::High {
                warning_level = WarningLevel::High;
            }
            issues.push(warning.clone());
        }

        let verdict = if warning_level >= WarningLevel::Critical {
            AnalysisVerdict::Rejected
        } else {
            AnalysisVerdict::Pass
        };

        quick_analysis_results.insert(
            key,
            QuickAnalysisResult {
                verdict,
                warning_level,
                issues,
            },
        );
    }

    // Step 5: Filter - separate passing and failing packages
    let mut passing_packages: Vec<(String, String, String, QuickAnalysisResult)> = Vec::new();
    let mut failing_packages: Vec<(String, String, String, QuickAnalysisResult)> = Vec::new();

    for (name, version, ecosystem, source) in &unique_packages {
        let key = format!("{}@{}@{}", name, version, ecosystem);
        if let Some(analysis) = quick_analysis_results.get(&key) {
            if analysis.verdict == AnalysisVerdict::Rejected {
                failing_packages.push((
                    name.clone(),
                    version.clone(),
                    ecosystem.clone(),
                    analysis.clone(),
                ));
            } else {
                passing_packages.push((
                    name.clone(),
                    version.clone(),
                    ecosystem.clone(),
                    analysis.clone(),
                ));
            }
        }
    }

    bridge::log(&format!(
        "DeepAnalysis: {} passing, {} rejected",
        passing_packages.len(),
        failing_packages.len()
    ));

    // Step 6: Git URL lookup for passing top-level packages
    let mut git_url_results: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();

    for (name, version, ecosystem, _) in &passing_packages {
        let key = format!("{}@{}@{}", name, version, ecosystem);
        let registry = ecosystem_to_registry(ecosystem);
        let cache_key = format!("{}:{}", registry, name);

        // Check cache first
        if let Some(cached_url) = analysis_cache.get_git_url(&cache_key) {
            if let Some(url) = cached_url {
                let platform = git_url_finder.detect_hosting_platform(&url);
                git_url_results.insert(key, (Some(url), Some(platform)));
            } else {
                git_url_results.insert(key, (None, None));
            }
            continue;
        }

        // Look up git URL
        if let Some((url, platform)) = git_url_finder.find_git_url_with_hosting(name, &registry) {
            analysis_cache.set_git_url(&cache_key, Some(url.clone()));
            git_url_results.insert(key, (Some(url.clone()), Some(platform.clone())));
        } else {
            analysis_cache.set_git_url(&cache_key, None);
            git_url_results.insert(key, (None, None));
        }
    }

    // Step 7: Deduplicate by unique git URL and fetch commits
    let mut unique_git_urls: HashMap<String, Vec<String>> = HashMap::new(); // git_url -> package keys
    let mut commits_by_url: HashMap<String, Vec<CommitInfo>> = HashMap::new();

    for (name, version, ecosystem, _) in &passing_packages {
        let key = format!("{}@{}@{}", name, version, ecosystem);
        if let Some((Some(git_url), Some(_platform))) = git_url_results.get(&key) {
            unique_git_urls
                .entry(git_url.clone())
                .or_default()
                .push(key.clone());
        }
    }

    for (git_url, package_keys) in &unique_git_urls {
        let cache_key = git_url.replace("https://", "").replace("http://", "");
        let platform = git_url_finder.detect_hosting_platform(git_url);

        // Check commit cache
        if let Some(cached_commits) = analysis_cache.get_commits(&cache_key) {
            commits_by_url.insert(git_url.clone(), cached_commits);
            continue;
        }

        // Fetch commits
        match commit_fetcher.fetch_commits(git_url, &platform, 10) {
            Ok(commits) => {
                api_calls_made += 1;
                analysis_cache.set_commits(&cache_key, commits.clone());
                commits_by_url.insert(git_url.clone(), commits);
            }
            Err(e) => {
                bridge::elog(&format!(
                    "DeepAnalysis: failed to fetch commits for {}: {}",
                    git_url, e
                ));
                commits_by_url.insert(git_url.clone(), Vec::new());
            }
        }
    }

    // Step 8: AI analysis in parallel (max 15 concurrent)
    let llm_provider = std::env::var("LLM_PROVIDER").unwrap_or_default();
    let llm_available = !llm_provider.is_empty();
    let mut all_commits_failed = true;

    let llm_client = LlmClient::new();
    let max_parallel = 15;
    let mut all_commit_details: HashMap<String, Vec<CommitDetail>> = HashMap::new();

    if !llm_available {
        bridge::elog("DeepAnalysis: LLM not configured (LLM_PROVIDER not set). Skipping AI commit analysis.");
    }

    // Collect all commits to analyze
    let mut commits_to_analyze: Vec<(String, CommitInfo)> = Vec::new();
    for (git_url, commits) in &commits_by_url {
        for commit in commits {
            commits_to_analyze.push((git_url.clone(), commit.clone()));
        }
    }

    bridge::log(&format!(
        "DeepAnalysis: analyzing {} commits with max {} parallel (LLM available: {})",
        commits_to_analyze.len(),
        max_parallel,
        llm_available
    ));

    if !llm_available {
        all_commit_details = commits_by_url
            .keys()
            .map(|url| (url.clone(), Vec::new()))
            .collect();
    } else {
    // Process in batches of max_parallel
    let results = Arc::new(Mutex::new(Vec::new()));
    let in_flight = Arc::new(Mutex::new(0));

    let total_commits = commits_to_analyze.len();
    let mut handles = Vec::new();

    for (git_url, commit) in commits_to_analyze {
        let in_flight = in_flight.clone();
        let results_arc = results.clone();

        // Wait if at max capacity
        loop {
            let current = *in_flight.lock().unwrap();
            if current < max_parallel {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        *in_flight.lock().unwrap() += 1;

        let handle = std::thread::spawn(move || {
            let client = LlmClient::new();
            let prompt = build_llm_prompt(&commit);
            let mut detail = CommitDetail {
                hash: commit.hash.clone(),
                verdict: CommitVerdict::Uncertain,
                confidence: 0.0,
                reasons: vec!["LLM response could not be parsed".to_string()],
                suspicious_patterns: Vec::new(),
            };

            match client.llm_completion(&prompt) {
                Ok(response) => {
                    match parse_llm_response(&response) {
                        Ok(parsed) => {
                            detail = parsed;
                            detail.hash = commit.hash.clone();
                        }
                        Err(e) => {
                            bridge::elog(&format!(
                                "DeepAnalysis: LLM parse error for {}: {}",
                                commit.hash, e
                            ));
                            // Retry once
                            if let Ok(retry_response) = client.llm_completion(&prompt) {
                                match parse_llm_response(&retry_response) {
                                    Ok(parsed) => {
                                        detail = parsed;
                                        detail.hash = commit.hash.clone();
                                    }
                                    Err(_) => {
                                        // Keep uncertain verdict
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    bridge::elog(&format!(
                        "DeepAnalysis: LLM call failed for {}: {}",
                        commit.hash, e
                    ));
                }
            }

            *in_flight.lock().unwrap() -= 1;

            if let Ok(mut r) = results_arc.lock() {
                r.push((git_url, detail));
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        let _ = handle.join();
    }

    // Collect results
    if let Ok(r) = results.lock() {
        for (git_url, detail) in r.iter() {
            all_commit_details
                .entry(git_url.clone())
                .or_default()
                .push(detail.clone());

            if detail.verdict != CommitVerdict::Uncertain
                || detail.confidence != 0.0
                || detail.reasons.len() != 1
                || detail.reasons.first() != Some(&"LLM response could not be parsed".to_string())
            {
                all_commits_failed = false;
            }
        }
    }
    } 

    // Step 9: Aggregate verdicts per package
    let mut commit_analysis_results: HashMap<String, Option<CommitAnalysisResult>> = HashMap::new();

    for (git_url, package_keys) in &unique_git_urls {
        let commit_details = all_commit_details.get(git_url).cloned().unwrap_or_default();
        let (verdict, confidence, reasons) = aggregate_commit_verdicts(&commit_details);

        let analysis = CommitAnalysisResult {
            verdict,
            confidence,
            reasons,
            commits_analyzed: commit_details.len(),
            commit_details,
            error: None,
        };

        for key in package_keys {
            commit_analysis_results.insert(key.clone(), Some(analysis.clone()));
        }
    }

    // For packages without git URLs, set commit_analysis to None
    for (name, version, ecosystem, _) in &passing_packages {
        let key = format!("{}@{}@{}", name, version, ecosystem);
        if !commit_analysis_results.contains_key(&key) {
            commit_analysis_results.insert(key, None);
        }
    }

    // Step 10: Build hierarchical output
    let mut tree: Vec<DependencyNode> = Vec::new();
    let mut flagged_count = 0;

    // Add passing packages first
    for (name, version, ecosystem, quick_res) in &passing_packages {
        let key = format!("{}@{}@{}", name, version, ecosystem);
        let is_top = top_level_keys.contains(&key);
        let (git_url, hosting_platform) =
            git_url_results.get(&key).cloned().unwrap_or((None, None));
        let no_git_url_notice = git_url.is_none();
        let commit_analysis = commit_analysis_results.get(&key).cloned().unwrap_or(None);

        if let Some(ref ca) = commit_analysis {
            if ca.verdict == CommitVerdict::Suspicious || ca.verdict == CommitVerdict::Malicious {
                flagged_count += 1;
            }
        }

        let node = DependencyNode {
            name: name.clone(),
            version: version.clone(),
            ecosystem: ecosystem.clone(),
            is_top_level: is_top,
            parent_refs: parent_refs.get(&key).cloned().unwrap_or_default(),
            quick_analysis: quick_res.clone(),
            git_url,
            hosting_platform,
            no_git_url_notice,
            commit_analysis,
            children: Vec::new(),
            error: None,
        };

        tree.push(node);
    }

    // Add failing packages (they don't get git URL lookup or commit analysis)
    for (name, version, ecosystem, quick_res) in &failing_packages {
        let key = format!("{}@{}@{}", name, version, ecosystem);
        let is_top = top_level_keys.contains(&key);

        let node = DependencyNode {
            name: name.clone(),
            version: version.clone(),
            ecosystem: ecosystem.clone(),
            is_top_level: is_top,
            parent_refs: parent_refs.get(&key).cloned().unwrap_or_default(),
            quick_analysis: quick_res.clone(),
            git_url: None,
            hosting_platform: None,
            no_git_url_notice: false,
            commit_analysis: None,
            children: Vec::new(),
            error: None,
        };

        flagged_count += 1;
        tree.push(node);
    }

    let summary = DeepAnalysisSummary {
        total_packages: unique_packages.len(),
        flagged: flagged_count,
        threshold: "Critical".to_string(),
        cache_hits: analysis_cache.hit_count() as usize,
        api_calls_made,
    };

    let (ai_status, error) = if !llm_available {
        (AiStatus::NotConfigured, Some("LLM not configured. Set LLM_PROVIDER, PROVIDER_API_KEY, and LLM_MODEL environment variables.".to_string()))
    } else if all_commits_failed {
        (AiStatus::Failed, Some("LLM analysis failed — all commit responses could not be parsed. Check LLM configuration.".to_string()))
    } else {
        (AiStatus::Ok, None)
    };

    let output = DeepAnalysisOutput {
        analysis_timestamp: now_timestamp(),
        ai_status,
        error,
        lockfile_sources,
        summary,
        tree,
    };

    let ai_status_str = match output.ai_status {
        AiStatus::Ok => "ok",
        AiStatus::NotConfigured => "not_configured",
        AiStatus::Failed => "failed",
    };

    // Convert to JSON
    let tree_json: Vec<Value> = output.tree.iter().map(dependency_node_to_json).collect();

    json!({
        "analysis_timestamp": output.analysis_timestamp,
        "ai_status": ai_status_str,
        "error": output.error,
        "lockfile_sources": output.lockfile_sources,
        "summary": {
            "total_packages": output.summary.total_packages,
            "flagged": output.summary.flagged,
            "threshold": output.summary.threshold,
            "cache_hits": output.summary.cache_hits,
            "api_calls_made": output.summary.api_calls_made
        },
        "tree": tree_json
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecosystem_to_registry() {
        assert_eq!(ecosystem_to_registry("npm"), "npm");
        assert_eq!(ecosystem_to_registry("PyPI"), "pypi");
        assert_eq!(ecosystem_to_registry("Go"), "go");
        assert_eq!(ecosystem_to_registry("RubyGems"), "rubygems");
        assert_eq!(ecosystem_to_registry("Maven"), "maven");
        assert_eq!(ecosystem_to_registry("NuGet"), "nuget");
        assert_eq!(ecosystem_to_registry("Pub"), "pub");
        assert_eq!(ecosystem_to_registry("Hex"), "hex");
        assert_eq!(ecosystem_to_registry("Packagist"), "packagist");
        assert_eq!(ecosystem_to_registry("crates.io"), "crates.io");
    }

    #[test]
    fn test_ecosystem_to_registry_unknown() {
        assert_eq!(ecosystem_to_registry("Unknown"), "unknown");
    }

    #[test]
    fn test_build_llm_prompt() {
        let commit = CommitInfo {
            hash: "abc123".to_string(),
            author: "testuser".to_string(),
            date: "2024-01-01".to_string(),
            message: "fix: security issue".to_string(),
            diff: "--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n-old code\n+new code"
                .to_string(),
        };
        let prompt = build_llm_prompt(&commit);
        assert!(prompt.contains("abc123"));
        assert!(prompt.contains("testuser"));
        assert!(prompt.contains("2024-01-01"));
        assert!(prompt.contains("fix: security issue"));
        assert!(prompt.contains("old code"));
        assert!(prompt.contains("new code"));
        assert!(!prompt.contains("{commit_hash}"));
        assert!(!prompt.contains("{diff}"));
    }

    #[test]
    fn test_parse_llm_response_allow() {
        let json =
            r#"{"verdict": "allow", "confidence": 0.95, "reasons": [], "suspicious_patterns": []}"#;
        let result = parse_llm_response(json);
        assert!(result.is_ok());
        let detail = result.unwrap();
        assert!(matches!(detail.verdict, CommitVerdict::Allow));
        assert!((detail.confidence - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_parse_llm_response_malicious() {
        let json = r#"{"verdict": "malicious", "confidence": 0.85, "reasons": ["Obfuscated code detected"], "suspicious_patterns": ["base64 encoding"]}"#;
        let result = parse_llm_response(json);
        assert!(result.is_ok());
        let detail = result.unwrap();
        assert!(matches!(detail.verdict, CommitVerdict::Malicious));
        assert_eq!(detail.reasons, vec!["Obfuscated code detected"]);
        assert_eq!(detail.suspicious_patterns, vec!["base64 encoding"]);
    }

    #[test]
    fn test_parse_llm_response_suspicious() {
        let json = r#"{"verdict": "suspicious", "confidence": 0.6, "reasons": ["New network call to unknown host"], "suspicious_patterns": ["new_network_call"]}"#;
        let result = parse_llm_response(json);
        assert!(result.is_ok());
        let detail = result.unwrap();
        assert!(matches!(detail.verdict, CommitVerdict::Suspicious));
    }

    #[test]
    fn test_parse_llm_response_invalid_json() {
        let result = parse_llm_response("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_llm_response_missing_verdict() {
        let json = r#"{"confidence": 1.0}"#;
        let result = parse_llm_response(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_llm_response_with_extra_text() {
        let json = "Here is my analysis:\n```json\n{\"verdict\": \"allow\", \"confidence\": 0.5, \"reasons\": [\"test\"], \"suspicious_patterns\": []}\n```\nDone.";
        let result = parse_llm_response(json);
        assert!(result.is_ok());
        let detail = result.unwrap();
        assert!(matches!(detail.verdict, CommitVerdict::Allow));
    }

    #[test]
    fn test_parse_llm_response_invalid_verdict() {
        let json = r#"{"verdict": "unknown_verdict", "confidence": 0.5, "reasons": [], "suspicious_patterns": []}"#;
        let result = parse_llm_response(json);
        assert!(result.is_ok());
        let detail = result.unwrap();
        assert!(matches!(detail.verdict, CommitVerdict::Uncertain));
    }

    #[test]
    fn test_aggregate_commit_verdicts_all_allow() {
        let details = vec![
            CommitDetail {
                hash: "a".to_string(),
                verdict: CommitVerdict::Allow,
                confidence: 0.9,
                reasons: vec![],
                suspicious_patterns: vec![],
            },
            CommitDetail {
                hash: "b".to_string(),
                verdict: CommitVerdict::Allow,
                confidence: 0.8,
                reasons: vec![],
                suspicious_patterns: vec![],
            },
        ];
        let (verdict, confidence, reasons) = aggregate_commit_verdicts(&details);
        assert!(matches!(verdict, CommitVerdict::Allow));
        assert!((confidence - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_aggregate_commit_verdicts_suspicious_wins() {
        let details = vec![
            CommitDetail {
                hash: "a".to_string(),
                verdict: CommitVerdict::Allow,
                confidence: 0.9,
                reasons: vec![],
                suspicious_patterns: vec![],
            },
            CommitDetail {
                hash: "b".to_string(),
                verdict: CommitVerdict::Suspicious,
                confidence: 0.6,
                reasons: vec!["Obfuscated code".to_string()],
                suspicious_patterns: vec!["obfuscation".to_string()],
            },
        ];
        let (verdict, _confidence, reasons) = aggregate_commit_verdicts(&details);
        assert!(matches!(verdict, CommitVerdict::Suspicious));
        assert!(reasons.contains(&"Obfuscated code".to_string()));
    }

    #[test]
    fn test_aggregate_commit_verdicts_malicious_wins() {
        let details = vec![
            CommitDetail {
                hash: "a".to_string(),
                verdict: CommitVerdict::Suspicious,
                confidence: 0.6,
                reasons: vec!["suspicious".to_string()],
                suspicious_patterns: vec![],
            },
            CommitDetail {
                hash: "b".to_string(),
                verdict: CommitVerdict::Malicious,
                confidence: 0.9,
                reasons: vec!["backdoor detected".to_string()],
                suspicious_patterns: vec!["backdoor".to_string()],
            },
        ];
        let (verdict, _confidence, _reasons) = aggregate_commit_verdicts(&details);
        assert!(matches!(verdict, CommitVerdict::Malicious));
    }

    #[test]
    fn test_aggregate_commit_verdicts_empty() {
        let details: Vec<CommitDetail> = vec![];
        let (verdict, confidence, reasons) = aggregate_commit_verdicts(&details);
        assert!(matches!(verdict, CommitVerdict::Allow));
        assert!((confidence - 1.0).abs() < 0.01);
        assert!(reasons.is_empty());
    }

    #[test]
    fn test_now_timestamp_format() {
        let s = now_timestamp();
        assert!(s.contains("Z"));
        assert!(s.contains("."));
    }

    #[test]
    fn test_ai_status_partial_eq() {
        assert_eq!(AiStatus::Ok, AiStatus::Ok);
        assert_eq!(AiStatus::NotConfigured, AiStatus::NotConfigured);
        assert_eq!(AiStatus::Failed, AiStatus::Failed);
        assert_ne!(AiStatus::Ok, AiStatus::NotConfigured);
        assert_ne!(AiStatus::Ok, AiStatus::Failed);
        assert_ne!(AiStatus::NotConfigured, AiStatus::Failed);
    }

    #[test]
    fn test_ai_status_display_conversion() {
        let status_ok = AiStatus::Ok;
        let status_not_configured = AiStatus::NotConfigured;
        let status_failed = AiStatus::Failed;

        let ok_str = match status_ok {
            AiStatus::Ok => "ok",
            AiStatus::NotConfigured => "not_configured",
            AiStatus::Failed => "failed",
        };
        assert_eq!(ok_str, "ok");

        let not_configured_str = match status_not_configured {
            AiStatus::Ok => "ok",
            AiStatus::NotConfigured => "not_configured",
            AiStatus::Failed => "failed",
        };
        assert_eq!(not_configured_str, "not_configured");

        let failed_str = match status_failed {
            AiStatus::Ok => "ok",
            AiStatus::NotConfigured => "not_configured",
            AiStatus::Failed => "failed",
        };
        assert_eq!(failed_str, "failed");
    }
}
