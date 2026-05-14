use chrono::{DateTime, NaiveDateTime, Utc};
use regex::Regex;
use whois_rust::{WhoIs, WhoIsLookupOptions};

use crate::modules::threat_intel::{ThreatIntel, normalize_domain};

#[derive(Debug)]
pub struct WhoisData {
    pub creation_date: Option<String>,
    pub expiry_date: Option<String>,
    pub registrar: Option<String>,
    pub privacy_protected: bool,
    pub age_days: Option<i64>,
    pub risk: u8,
}

#[derive(Debug)]
pub struct UrlRisk {
    pub url: String,
    pub risk: u8,
    pub age_days: Option<i64>,
}

pub fn scan(message: String, threat_intel: &ThreatIntel) -> Vec<UrlRisk> {
    let whois = WhoIs::from_path("servers.json").unwrap();
    let urls = extract_urls(&message);
    let mut results = Vec::new();
    for url in urls {
        match threat_intel.lookup(&url) {
            Ok(Some(hit)) => {
                println!(
                    "known threat: {} ({}) source={} threat={} confidence={:?}",
                    hit.indicator, hit.indicator_type, hit.source, hit.threat_type, hit.confidence
                );
                let data = known_threat_whois_data();
                results.push(UrlRisk {
                    url,
                    risk: data.risk,
                    age_days: data.age_days,
                });
                continue;
            }
            Ok(None) => {}
            Err(err) => eprintln!("threat intel lookup failed for {url}: {err}"),
        }

        let domain = normalize_domain(&url);
        let result = whois
            .lookup(WhoIsLookupOptions::from_str(domain).unwrap())
            .unwrap();
        let data = parse_whois(&result);
        results.push(UrlRisk {
            url,
            risk: data.risk,
            age_days: data.age_days,
        });
    }
    results
}

fn known_threat_whois_data() -> WhoisData {
    WhoisData {
        creation_date: None,
        expiry_date: None,
        registrar: None,
        privacy_protected: false,
        age_days: None,
        risk: 100,
    }
}

pub fn parse_whois(raw: &str) -> WhoisData {
    let creation = extract_first(
        raw,
        &[
            r"(?im)^Creation Date:\s*(.+)",
            r"(?im)^created:\s*(.+)",
            r"(?im)^registered:\s*(.+)",
            r"(?im)^Created on\s*(.+)",
        ],
    );
    let expiry = extract_first(
        raw,
        &[
            r"(?im)^Registry Expiry Date:\s*(.+)",
            r"(?im)^expire:\s*(.+)",
            r"(?im)^Expiry Date:\s*(.+)",
        ],
    );
    let registrar = extract_first(
        raw,
        &[r"(?im)^Registrar:\s*(.+)", r"(?im)^registrar:\s*(.+)"],
    );
    let privacy_protected = raw.contains("privacy") || raw.contains("REDACTED");
    let age_days = creation.as_deref().and_then(domain_age_days);
    let risk = score_whois(age_days, privacy_protected);

    WhoisData {
        creation_date: creation,
        expiry_date: expiry,
        registrar,
        privacy_protected,
        age_days,
        risk,
    }
}

fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    s.parse::<DateTime<Utc>>()
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%d.%m.%Y %H:%M:%S")
                .ok()
                .map(|nd| nd.and_utc())
        })
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
                .ok()
                .map(|nd| nd.and_utc())
        })
}

fn domain_age_days(creation_date: &str) -> Option<i64> {
    let dt = parse_date(creation_date)?;
    Some((Utc::now() - dt).num_days())
}

fn score_whois(age_days: Option<i64>, privacy: bool) -> u8 {
    let mut score: u8 = 0;

    if let Some(age) = age_days {
        if age < 30 {
            score += 60
        } else if age < 90 {
            score += 40
        } else if age < 180 {
            score += 20
        } else if age < 365 {
            score += 10
        }
    } else {
        score += 20;
    }

    if privacy {
        score = score.saturating_add(20)
    }

    score.min(100)
}

fn extract_first(text: &str, patterns: &[&str]) -> Option<String> {
    for pattern in patterns {
        let re = Regex::new(pattern).ok()?;
        if let Some(caps) = re.captures(text) {
            return caps.get(1).map(|m| m.as_str().trim().to_string());
        }
    }
    None
}

pub fn extract_urls(text: &str) -> Vec<String> {
    let re =
        Regex::new(r#"https?://[^\s<>"]+|[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?"#)
            .unwrap();
    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}
