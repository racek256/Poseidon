use std::thread;
use std::time::Instant;

use regex::Regex;
use serde_json::{Value, json};

use crate::modules::ai::{self, AiAssessment};
use crate::modules::message_memory::{MemoryLookup, MessageMemory, UnsafeMessageRecord};
use crate::modules::threat_intel::ThreatIntel;
use crate::modules::url_db::{UrlDb, UrlLookup};
use crate::modules::web::extract_urls;

#[derive(Debug)]
pub enum Decision {
    Allow,
    WarnS, // warn sender
    WarnR, // warn receiver
    WarnB, // warn both
    Block,
}

#[derive(Debug)]
pub struct Scores {
    pub phishing: u8,
    pub secret: u8,
    pub prompt_injection: u8,
    pub url_reputation: Option<u8>,
    pub impersonation: u8,
    pub slop_score: u8,
}

#[derive(Debug)]
pub struct UrlScore {
    pub url: String,
    pub risk: u8,
    pub age_days: Option<u32>,
    pub known_url_db: bool,
    pub queued_for_analysis: bool,
    pub stored_verdict: Option<String>,
    pub tags: Vec<String>,
    pub brand_impersonation: Option<BrandImpersonationScore>,
}

#[derive(Debug)]
pub struct BrandImpersonationScore {
    pub matched_brand: Option<String>,
    pub official: bool,
    pub hosting_provider: Option<String>,
    pub score: u8,
    pub confidence: u8,
    pub risk_level: String,
    pub reasons_json: String,
    pub safe_evidence_json: String,
}

#[derive(Debug)]
pub struct Scoring {
    pub decision: Decision,
    pub overall_risk: u8,
    pub scores: Scores,
    pub flags: Vec<String>,
    pub urls: Vec<UrlScore>,
    pub summary: Option<String>,
    pub message_memory: MessageMemoryResult,
}

#[derive(Debug)]
pub struct MessageMemoryResult {
    pub stored: bool,
    pub lookup: Option<MemoryLookup>,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::WarnS => "warn_sender",
            Decision::WarnR => "warn_receiver",
            Decision::WarnB => "warn_both",
            Decision::Block => "block",
        }
    }
}

impl Scoring {
    pub fn to_json(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "overall_risk": self.overall_risk,
            "scores": {
                "phishing": self.scores.phishing,
                "secret": self.scores.secret,
                "prompt_injection": self.scores.prompt_injection,
                "url_reputation": self.scores.url_reputation,
                "impersonation": self.scores.impersonation,
                "slop_score": self.scores.slop_score
            },
            "flags": self.flags,
            "urls": self.urls.iter().map(|url| json!({
                "url": url.url,
                "risk": url.risk,
                "age_days": url.age_days,
                "known_url_db": url.known_url_db,
                "queued_for_analysis": url.queued_for_analysis,
                "stored_verdict": url.stored_verdict,
                "tags": url.tags,
                "brand_impersonation": url.brand_impersonation.as_ref().map(|brand| json!({
                    "matched_brand": brand.matched_brand,
                    "official": brand.official,
                    "hosting_provider": brand.hosting_provider,
                    "score": brand.score,
                    "confidence": brand.confidence,
                    "risk_level": brand.risk_level,
                    "reasons": serde_json::from_str::<Value>(&brand.reasons_json).unwrap_or_else(|_| json!([])),
                    "safe_evidence": serde_json::from_str::<Value>(&brand.safe_evidence_json).unwrap_or_else(|_| json!([]))
                }))
            })).collect::<Vec<_>>(),
            "summary": self.summary,
            "message_memory": self.message_memory.lookup.as_ref().map(|lookup| lookup.to_json(self.message_memory.stored))
        })
    }
}

pub fn analyse(
    message: &str,
    threat_intel: &ThreatIntel,
    url_db: &UrlDb,
    message_memory: &MessageMemory,
) -> Scoring {
    let start = Instant::now();
    let mut flags = Vec::new();
    let memory_lookup = match message_memory.lookup(message) {
        Ok(lookup) => {
            if lookup.exact_match.is_some() {
                flags.push("exact unsafe message memory match".to_string());
            } else if !lookup.similar_matches.is_empty() {
                flags.push(format!(
                    "{} similar unsafe message memory matches",
                    lookup.similar_matches.len()
                ));
            }
            Some(lookup)
        }
        Err(err) => {
            flags.push(format!("message memory lookup failed: {err}"));
            None
        }
    };

    let (url_scores, ai_result) = thread::scope(|scope| {
        let ai_handle = scope.spawn(|| ai::assess_message(message));
        let url_scores = scan_known_urls(message, threat_intel, url_db, &mut flags);
        let ai_result = ai_handle
            .join()
            .unwrap_or_else(|_| Err("ai worker panicked".to_string()));
        (url_scores, ai_result)
    });

    let prompt_injection = score_prompt_injection(message, &mut flags);
    let secret = score_secrets(message, &mut flags);
    let url_reputation = url_scores.iter().map(|url| url.risk).max();
    let urgency = score_urgency(message, &mut flags);

    let (ai, ai_confidence) = match ai_result {
        Ok(ai) => {
            let confidence = ai.confidence;
            flags.extend(ai.flags.clone());
            (ai, confidence)
        }
        Err(err) => {
            flags.push(format!("ai unavailable: {err}"));
            (AiAssessment::default(), 0)
        }
    };

    let llm_weight = if prompt_injection >= 80 { 30 } else { 100 };
    let mut scores = Scores {
        phishing: weighted_score(ai.phishing.max(urgency), llm_weight),
        secret,
        prompt_injection: prompt_injection.max(weighted_score(ai.prompt_injection, llm_weight)),
        url_reputation,
        impersonation: weighted_score(ai.impersonation, llm_weight),
        slop_score: weighted_score(ai.slop_score, llm_weight),
    };
    if let Some(memory_lookup) = &memory_lookup {
        if memory_lookup.risk_adjustment > 0 {
            scores.phishing = scores
                .phishing
                .saturating_add(memory_lookup.risk_adjustment)
                .min(100);
        }
    }

    let overall_risk = overall_risk(&scores);
    let decision = decide(overall_risk, &scores);
    let urls = url_scores;
    let summary = summary_for(message, overall_risk, ai_confidence, &flags);
    observe_url_reputation(&urls, &decision, overall_risk, url_db, &mut flags);
    let stored = if should_store_unsafe(&decision, overall_risk, &scores) {
        if let Some(memory_lookup) = &memory_lookup {
            let tags = unsafe_tags(&scores, &urls, &flags);
            let url_hashes = urls
                .iter()
                .map(|url| url_db.identity(&url.url).url_hash)
                .collect::<Vec<_>>();
            match message_memory.store_unsafe(
                memory_lookup,
                UnsafeMessageRecord {
                    message,
                    decision: decision.as_str(),
                    risk_score: overall_risk,
                    confidence: ai_confidence.max(70),
                    summary: summary.as_deref(),
                    tags,
                    url_hashes,
                },
            ) {
                Ok(()) => true,
                Err(err) => {
                    flags.push(format!("message memory store failed: {err}"));
                    false
                }
            }
        } else {
            false
        }
    } else {
        false
    };

    eprintln!("analyse took {:?}", start.elapsed());

    Scoring {
        decision,
        overall_risk,
        scores,
        flags,
        urls,
        summary,
        message_memory: MessageMemoryResult {
            stored,
            lookup: memory_lookup,
        },
    }
}

fn should_store_unsafe(decision: &Decision, overall_risk: u8, scores: &Scores) -> bool {
    matches!(decision, Decision::Block | Decision::WarnB)
        || overall_risk >= 75
        || scores.secret >= 85
        || scores.prompt_injection >= 60
        || scores.url_reputation.is_some_and(|risk| risk >= 75)
}

fn observe_url_reputation(
    urls: &[UrlScore],
    decision: &Decision,
    overall_risk: u8,
    url_db: &UrlDb,
    flags: &mut Vec<String>,
) {
    if urls.is_empty() {
        return;
    }
    let safe_message = matches!(decision, Decision::Allow) && overall_risk < 35;
    let unsafe_message =
        matches!(decision, Decision::Block | Decision::WarnB) || overall_risk >= 75;
    if !safe_message && !unsafe_message {
        return;
    }

    for url in urls {
        let identity = url_db.identity(&url.url);
        let reputation = match url_db.observe_domain_reputation(&identity, safe_message) {
            Ok(reputation) => reputation,
            Err(err) => {
                flags.push(format!(
                    "domain reputation update failed for {}: {err}",
                    url.url
                ));
                continue;
            }
        };

        if safe_message && reputation.boost >= 10 {
            match url_db.enqueue_analysis(
                &identity,
                &url.url,
                40,
                "safe local reputation threshold reached",
            ) {
                Ok(true) => flags.push(format!(
                    "queued {} for brand learning after safe local reputation boost {}",
                    url.url, reputation.boost
                )),
                Ok(false) => {}
                Err(err) => flags.push(format!(
                    "url reputation requeue failed for {}: {err}",
                    url.url
                )),
            }
        }
    }
}

fn unsafe_tags(scores: &Scores, urls: &[UrlScore], flags: &[String]) -> Vec<String> {
    let mut tags = Vec::new();
    if scores.phishing >= 60 {
        tags.push("phishing".to_string());
    }
    if scores.secret >= 85 {
        tags.push("secret_leak".to_string());
    }
    if scores.prompt_injection >= 60 {
        tags.push("prompt_injection".to_string());
    }
    if scores.impersonation >= 60 {
        tags.push("impersonation".to_string());
    }
    if urls.iter().any(|url| url.risk >= 75) {
        tags.push("known_bad_url".to_string());
    }
    for url in urls {
        for tag in &url.tags {
            if !tags.contains(tag) {
                tags.push(tag.clone());
            }
        }
    }
    for flag in flags {
        if flag.contains("urgency") {
            tags.push("urgency_language".to_string());
        }
    }
    tags.sort();
    tags.dedup();
    tags
}

fn scan_known_urls(
    message: &str,
    threat_intel: &ThreatIntel,
    url_db: &UrlDb,
    flags: &mut Vec<String>,
) -> Vec<UrlScore> {
    extract_urls(message)
        .into_iter()
        .map(|url| scan_known_url(url, threat_intel, url_db, flags))
        .collect()
}

fn scan_known_url(
    url: String,
    threat_intel: &ThreatIntel,
    url_db: &UrlDb,
    flags: &mut Vec<String>,
) -> UrlScore {
    match threat_intel.lookup(&url) {
        Ok(Some(hit)) => {
            flags.push(format!(
                "known threat url: source={} threat={} confidence={:?}",
                hit.source, hit.threat_type, hit.confidence
            ));
            return UrlScore {
                url,
                risk: 100,
                age_days: None,
                known_url_db: false,
                queued_for_analysis: false,
                stored_verdict: Some("bad".to_string()),
                tags: vec!["threat_intel".to_string()],
                brand_impersonation: None,
            };
        }
        Ok(None) => {}
        Err(err) => flags.push(format!("threat intel lookup failed for {url}: {err}")),
    }

    let identity = url_db.identity(&url);
    match url_db.lookup(&identity) {
        Ok(Some(lookup)) => url_score_from_lookup(url, lookup),
        Ok(None) => {
            let queued = url_db
                .enqueue_unknown(&identity, &url, queue_priority(&url), "missing from url db")
                .unwrap_or_else(|err| {
                    flags.push(format!("url queue insert failed for {url}: {err}"));
                    false
                });
            UrlScore {
                url,
                risk: 0,
                age_days: None,
                known_url_db: false,
                queued_for_analysis: queued,
                stored_verdict: None,
                tags: Vec::new(),
                brand_impersonation: None,
            }
        }
        Err(err) => {
            flags.push(format!("url db lookup failed for {url}: {err}"));
            UrlScore {
                url,
                risk: 0,
                age_days: None,
                known_url_db: false,
                queued_for_analysis: false,
                stored_verdict: None,
                tags: Vec::new(),
                brand_impersonation: None,
            }
        }
    }
}

fn url_score_from_lookup(url: String, lookup: UrlLookup) -> UrlScore {
    UrlScore {
        url,
        risk: lookup.risk_score,
        age_days: None,
        known_url_db: true,
        queued_for_analysis: false,
        stored_verdict: Some(lookup.verdict),
        tags: lookup.tags,
        brand_impersonation: lookup
            .brand_impersonation
            .map(|brand| BrandImpersonationScore {
                matched_brand: brand.matched_brand,
                official: brand.official,
                hosting_provider: brand.hosting_provider,
                score: brand.score,
                confidence: brand.confidence,
                risk_level: brand.risk_level,
                reasons_json: brand.reasons_json,
                safe_evidence_json: brand.safe_evidence_json,
            }),
    }
}

fn queue_priority(url: &str) -> u8 {
    let lower = url.to_ascii_lowercase();
    let has_brand = [
        "paypal",
        "google",
        "microsoft",
        "apple",
        "amazon",
        "facebook",
        "instagram",
        "coinbase",
        "binance",
        "metamask",
    ]
    .iter()
    .any(|brand| lower.contains(brand));
    let has_intent = [
        "login", "verify", "account", "password", "wallet", "payment",
    ]
    .iter()
    .any(|keyword| lower.contains(keyword));

    if has_brand && has_intent {
        90
    } else if has_brand {
        80
    } else if has_intent {
        70
    } else {
        50
    }
}

fn score_secrets(message: &str, flags: &mut Vec<String>) -> u8 {
    let re =
        Regex::new(r"(?i)(api[_-]?key|token|secret|password)[^a-zA-Z0-9]{0,10}[A-Za-z0-9_\-]{16,}")
            .unwrap();
    if re.is_match(message) {
        flags.push("possible secret in message".to_string());
        85
    } else {
        0
    }
}

fn score_prompt_injection(message: &str, flags: &mut Vec<String>) -> u8 {
    let patterns = [
        "ignore previous instructions",
        "disregard previous instructions",
        "system prompt",
        "developer message",
        "jailbreak",
        "act as",
    ];
    let lower = message.to_ascii_lowercase();
    let hits = count_hits(&lower, &patterns);
    if hits > 0 {
        flags.push("prompt injection language detected".to_string());
    }
    ((hits as u8) * 35).min(100)
}

fn score_urgency(message: &str, flags: &mut Vec<String>) -> u8 {
    let patterns = [
        "urgent",
        "immediately",
        "suspended",
        "verify",
        "account",
        "credit",
    ];
    let lower = message.to_ascii_lowercase();
    let hits = count_hits(&lower, &patterns);
    if hits >= 2 {
        flags.push("phishing urgency/account language detected".to_string());
    }
    ((hits as u8) * 15).min(80)
}

fn count_hits(message: &str, patterns: &[&str]) -> usize {
    patterns
        .iter()
        .filter(|pattern| message.contains(**pattern))
        .count()
}

fn weighted_score(score: u8, weight_percent: u8) -> u8 {
    ((score as u16 * weight_percent as u16) / 100).min(100) as u8
}

fn overall_risk(scores: &Scores) -> u8 {
    let mut risk = scores
        .phishing
        .max(scores.secret)
        .max(scores.prompt_injection)
        .max(scores.impersonation)
        .max(scores.slop_score);
    if let Some(url_risk) = scores.url_reputation {
        risk = risk.max(url_risk);
    }
    risk
}

fn decide(overall_risk: u8, scores: &Scores) -> Decision {
    if overall_risk >= 90 || scores.secret >= 85 {
        Decision::Block
    } else if overall_risk >= 75 {
        Decision::WarnB
    } else if scores.prompt_injection >= 60 {
        Decision::WarnS
    } else if overall_risk >= 45 {
        Decision::WarnR
    } else {
        Decision::Allow
    }
}

fn summary_for(
    message: &str,
    overall_risk: u8,
    ai_confidence: u8,
    flags: &[String],
) -> Option<String> {
    if overall_risk < 75 {
        return None;
    }

    ai::summarize_danger(message, overall_risk, flags)
        .or_else(|_| Ok::<_, String>(fallback_summary(overall_risk, ai_confidence, flags)))
        .ok()
}

fn fallback_summary(overall_risk: u8, ai_confidence: u8, flags: &[String]) -> String {
    format!(
        "High-risk message ({overall_risk}/100, AI confidence {ai_confidence}/100): {}.",
        flags.join(", ")
    )
}
