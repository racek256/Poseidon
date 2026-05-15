use std::fs;
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use regex::Regex;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::redirect::Policy;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use whois_rust::{WhoIs, WhoIsLookupOptions};

use crate::modules::url_analysis::brand::{self, BrandImpersonation, RuntimeBrand};
use crate::modules::url_analysis::domain::parse_url_parts;

const HTTP_BODY_LIMIT: usize = 512 * 1024;
const ONLINE_DETECTION_THRESHOLD: u8 = 60;
const DEFAULT_FAVICON_HASHES_PATH: &str = "data/favicon_hashes.json";

#[derive(Debug)]
pub struct OnlineBrandAnalysis {
    pub score: u8,
    pub confidence: u8,
    pub detected: bool,
    pub deterministic: BrandImpersonation,
    pub evidence: OnlineEvidence,
    pub timings: OnlineTimings,
    pub reasons: Vec<String>,
}

#[derive(Debug, Default)]
pub struct OnlineEvidence {
    pub dns_resolved: bool,
    pub ip_addresses: Vec<String>,
    pub ip_provider: Option<String>,
    pub dns_error: Option<String>,
    pub whois_age_days: Option<i64>,
    pub whois_privacy: bool,
    pub whois_error: Option<String>,
    pub http_status: Option<u16>,
    pub final_url: Option<String>,
    pub redirect_count: usize,
    pub final_domain_changed: bool,
    pub title: Option<String>,
    pub has_password_field: bool,
    pub has_otp_field: bool,
    pub has_card_field: bool,
    pub form_count: usize,
    pub external_form_action: bool,
    pub page_brand_match: bool,
    pub favicon_hash: Option<String>,
    pub favicon_brand_match: bool,
    pub http_error: Option<String>,
}

#[derive(Debug, Default)]
pub struct OnlineTimings {
    pub deterministic: Duration,
    pub dns: Duration,
    pub whois: Duration,
    pub http_page: Duration,
    pub total: Duration,
}

impl OnlineBrandAnalysis {
    pub fn to_json(&self) -> Value {
        json!({
            "score": self.score,
            "confidence": self.confidence,
            "detected": self.detected,
            "matched_brand": self.deterministic.matched_brand,
            "official": self.deterministic.official,
            "hosting_provider": self.deterministic.hosting_provider,
            "reasons": self.reasons,
            "evidence": {
                "dns_resolved": self.evidence.dns_resolved,
                "ip_addresses": self.evidence.ip_addresses,
                "ip_provider": self.evidence.ip_provider,
                "dns_error": self.evidence.dns_error,
                "whois_age_days": self.evidence.whois_age_days,
                "whois_privacy": self.evidence.whois_privacy,
                "whois_error": self.evidence.whois_error,
                "http_status": self.evidence.http_status,
                "final_url": self.evidence.final_url,
                "redirect_count": self.evidence.redirect_count,
                "final_domain_changed": self.evidence.final_domain_changed,
                "title": self.evidence.title,
                "has_password_field": self.evidence.has_password_field,
                "has_otp_field": self.evidence.has_otp_field,
                "has_card_field": self.evidence.has_card_field,
                "form_count": self.evidence.form_count,
                "external_form_action": self.evidence.external_form_action,
                "page_brand_match": self.evidence.page_brand_match,
                "favicon_hash": self.evidence.favicon_hash,
                "favicon_brand_match": self.evidence.favicon_brand_match,
                "http_error": self.evidence.http_error
            },
            "timings_ms": {
                "deterministic": self.timings.deterministic.as_secs_f64() * 1000.0,
                "dns": self.timings.dns.as_secs_f64() * 1000.0,
                "whois": self.timings.whois.as_secs_f64() * 1000.0,
                "http_page": self.timings.http_page.as_secs_f64() * 1000.0,
                "total": self.timings.total.as_secs_f64() * 1000.0
            }
        })
    }
}

pub fn analyse_online(url: &str) -> OnlineBrandAnalysis {
    analyse_online_with_runtime_brands(url, &[])
}

pub fn analyse_online_with_runtime_brands(
    url: &str,
    runtime_brands: &[RuntimeBrand],
) -> OnlineBrandAnalysis {
    let total_start = Instant::now();
    let deterministic_start = Instant::now();
    let deterministic = brand::analyse_with_runtime_brands(url, runtime_brands);
    let deterministic_elapsed = deterministic_start.elapsed();
    let parts = parse_url_parts(url);

    if deterministic.official {
        return OnlineBrandAnalysis {
            score: deterministic.score,
            confidence: deterministic.confidence,
            detected: false,
            evidence: OnlineEvidence::default(),
            timings: OnlineTimings {
                deterministic: deterministic_elapsed,
                total: total_start.elapsed(),
                ..OnlineTimings::default()
            },
            reasons: deterministic.reasons.clone(),
            deterministic,
        };
    }

    let (dns, whois, http) = thread::scope(|scope| {
        let dns_handle = scope.spawn(|| collect_dns(&parts.host));
        let whois_handle = scope.spawn(|| collect_whois(&parts.registrable_domain));
        let http_handle = scope.spawn(|| {
            collect_http_page(
                url,
                &parts.registrable_domain,
                deterministic.matched_brand.as_deref(),
            )
        });
        (
            dns_handle
                .join()
                .unwrap_or_else(|_| Timed::err("dns worker panicked")),
            whois_handle
                .join()
                .unwrap_or_else(|_| Timed::err("whois worker panicked")),
            http_handle
                .join()
                .unwrap_or_else(|_| Timed::err("http worker panicked")),
        )
    });

    let mut evidence = OnlineEvidence::default();
    evidence.dns_resolved = dns.value.dns_resolved;
    evidence.ip_addresses = dns.value.ip_addresses;
    evidence.ip_provider = dns.value.ip_provider;
    evidence.dns_error = dns.value.dns_error;
    evidence.whois_age_days = whois.value.whois_age_days;
    evidence.whois_privacy = whois.value.whois_privacy;
    evidence.whois_error = whois.value.whois_error;
    evidence.http_status = http.value.http_status;
    evidence.final_url = http.value.final_url;
    evidence.redirect_count = http.value.redirect_count;
    evidence.final_domain_changed = http.value.final_domain_changed;
    evidence.title = http.value.title;
    evidence.has_password_field = http.value.has_password_field;
    evidence.has_otp_field = http.value.has_otp_field;
    evidence.has_card_field = http.value.has_card_field;
    evidence.form_count = http.value.form_count;
    evidence.external_form_action = http.value.external_form_action;
    evidence.page_brand_match = http.value.page_brand_match;
    evidence.favicon_hash = http.value.favicon_hash;
    evidence.favicon_brand_match = http.value.favicon_brand_match;
    evidence.http_error = http.value.http_error;

    let (score, reasons) = score_online(&deterministic, &evidence);
    let confidence = confidence_for(score, &evidence);

    OnlineBrandAnalysis {
        score,
        confidence,
        detected: score >= ONLINE_DETECTION_THRESHOLD,
        deterministic,
        evidence,
        timings: OnlineTimings {
            deterministic: deterministic_elapsed,
            dns: dns.elapsed,
            whois: whois.elapsed,
            http_page: http.elapsed,
            total: total_start.elapsed(),
        },
        reasons,
    }
}

fn score_online(
    deterministic: &BrandImpersonation,
    evidence: &OnlineEvidence,
) -> (u8, Vec<String>) {
    let mut score = deterministic.score;
    let mut reasons = deterministic.reasons.clone();
    let credential_fields =
        evidence.has_password_field || evidence.has_otp_field || evidence.has_card_field;
    let brand_signal = deterministic.matched_brand.is_some()
        || evidence.page_brand_match
        || evidence.favicon_brand_match;
    let weak_page_only = !credential_fields
        && !evidence.favicon_brand_match
        && !evidence.external_form_action
        && !(evidence.final_domain_changed && deterministic.matched_brand.is_some());

    if credential_fields {
        reasons.push("credential collection fields found on page".to_string());
        if deterministic.matched_brand.is_some() {
            score = score.max(90);
        } else {
            score = score.max(60);
        }
    }

    if evidence.page_brand_match && credential_fields && !deterministic.official {
        reasons.push("page content matches brand and collects credentials".to_string());
        score = score.max(85);
    }

    if evidence.favicon_brand_match && !deterministic.official {
        reasons.push("favicon hash matches known brand favicon".to_string());
        score = score.max(85);
    }

    if evidence.external_form_action {
        reasons.push("form posts to a different domain".to_string());
        if credential_fields || brand_signal {
            score = score.saturating_add(10).min(95);
        } else {
            score = score.max(45);
        }
    }

    if evidence.final_domain_changed && deterministic.matched_brand.is_some() {
        reasons.push("redirect chain changes registrable domain".to_string());
        score = score.saturating_add(10).min(95);
    }

    if evidence.whois_age_days.is_some_and(|age| age < 30) && deterministic.matched_brand.is_some()
    {
        reasons.push("domain appears recently registered".to_string());
        score = score.saturating_add(10).min(95);
    }

    if let Some(provider) = &evidence.ip_provider {
        if deterministic.matched_brand.is_some() {
            reasons.push(format!("resolved IP belongs to known provider: {provider}"));
            score = score.saturating_add(5).min(95);
        }
    }

    if weak_page_only {
        if evidence.whois_age_days.is_some_and(|age| age > 180) && evidence.http_status.is_some() {
            reasons.push("older live domain without credential collection".to_string());
            score = score.min(35);
        } else if !brand_signal {
            score = score.min(40);
        } else {
            score = score.min(60);
        }
    }

    if deterministic.matched_brand.is_none() && !evidence.page_brand_match {
        score = score.min(40);
    }

    (score, reasons)
}

fn confidence_for(score: u8, evidence: &OnlineEvidence) -> u8 {
    let mut confidence: u8 = if score >= 85 {
        90
    } else if score >= 60 {
        75
    } else {
        60
    };
    if evidence.http_error.is_some() {
        confidence = confidence.saturating_sub(15);
    }
    if evidence.whois_error.is_some() {
        confidence = confidence.saturating_sub(5);
    }
    confidence
}

#[derive(Debug)]
struct Timed<T> {
    value: T,
    elapsed: Duration,
}

impl Timed<OnlineEvidence> {
    fn err(message: &str) -> Self {
        let mut evidence = OnlineEvidence::default();
        evidence.http_error = Some(message.to_string());
        Self {
            value: evidence,
            elapsed: Duration::default(),
        }
    }
}

fn collect_dns(host: &str) -> Timed<OnlineEvidence> {
    let start = Instant::now();
    let mut evidence = OnlineEvidence::default();
    match (host, 443).to_socket_addrs() {
        Ok(addrs) => {
            let mut ips = Vec::new();
            for addr in addrs {
                let ip = addr.ip();
                let ip_string = ip.to_string();
                if !ips.contains(&ip_string) {
                    ips.push(ip_string);
                }
                if evidence.ip_provider.is_none() {
                    evidence.ip_provider = ip_provider(ip).map(str::to_string);
                }
            }
            evidence.dns_resolved = !ips.is_empty();
            evidence.ip_addresses = ips;
        }
        Err(err) => evidence.dns_error = Some(err.to_string()),
    }
    Timed {
        value: evidence,
        elapsed: start.elapsed(),
    }
}

fn collect_whois(domain: &str) -> Timed<OnlineEvidence> {
    let start = Instant::now();
    let mut evidence = OnlineEvidence::default();
    match WhoIs::from_path("servers.json")
        .map_err(|err| err.to_string())
        .and_then(|whois| {
            whois
                .lookup(WhoIsLookupOptions::from_str(domain).map_err(|err| err.to_string())?)
                .map_err(|err| err.to_string())
        }) {
        Ok(raw) => {
            evidence.whois_age_days = whois_age_days(&raw);
            let lower = raw.to_ascii_lowercase();
            evidence.whois_privacy = lower.contains("privacy") || lower.contains("redacted");
        }
        Err(err) => evidence.whois_error = Some(err),
    }
    Timed {
        value: evidence,
        elapsed: start.elapsed(),
    }
}

fn collect_http_page(
    url: &str,
    original_domain: &str,
    matched_brand: Option<&str>,
) -> Timed<OnlineEvidence> {
    let start = Instant::now();
    let mut evidence = OnlineEvidence::default();
    let client = match ClientBuilder::new()
        .timeout(Duration::from_secs(8))
        .redirect(Policy::limited(5))
        .user_agent("Poseidon-url-analysis/0.1")
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            evidence.http_error = Some(err.to_string());
            return Timed {
                value: evidence,
                elapsed: start.elapsed(),
            };
        }
    };

    match fetch_page(&client, url) {
        Ok((status, final_url, body)) => {
            evidence.http_status = Some(status);
            evidence.final_domain_changed =
                parse_url_parts(&final_url).registrable_domain != original_domain;
            collect_favicon(&client, &final_url, matched_brand, &mut evidence);
            evidence.final_url = Some(final_url);
            let page_domain = evidence
                .final_url
                .as_deref()
                .map(|url| parse_url_parts(url).registrable_domain)
                .unwrap_or_else(|| original_domain.to_string());
            analyse_html(&body, matched_brand, &page_domain, &mut evidence);
        }
        Err(err) => evidence.http_error = Some(err),
    }

    Timed {
        value: evidence,
        elapsed: start.elapsed(),
    }
}

fn collect_favicon(
    client: &Client,
    final_url: &str,
    matched_brand: Option<&str>,
    evidence: &mut OnlineEvidence,
) {
    let favicon_url = favicon_url(final_url);
    let Ok(response) = client.get(&favicon_url).send() else {
        return;
    };
    if !response.status().is_success() {
        return;
    }
    let Ok(bytes) = response.bytes() else {
        return;
    };
    if bytes.is_empty() || bytes.len() > 256 * 1024 {
        return;
    }

    let hash = sha256_hex(&bytes);
    evidence.favicon_brand_match = matched_brand
        .and_then(|brand| known_favicon_hashes_for(brand))
        .is_some_and(|hashes| hashes.iter().any(|known| known == &hash));
    evidence.favicon_hash = Some(hash);
}

fn favicon_url(url: &str) -> String {
    let trimmed = url.trim();
    let scheme = if trimmed.starts_with("http://") {
        "http://"
    } else {
        "https://"
    };
    let without_scheme = trimmed
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    format!("{scheme}{host}/favicon.ico")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn fetch_page(client: &Client, url: &str) -> Result<(u16, String, String), String> {
    let response = client.get(url).send().map_err(|err| err.to_string())?;
    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let body = response.text().map_err(|err| err.to_string())?;
    Ok((
        status,
        final_url,
        body.chars().take(HTTP_BODY_LIMIT).collect(),
    ))
}

fn analyse_html(
    body: &str,
    matched_brand: Option<&str>,
    page_domain: &str,
    evidence: &mut OnlineEvidence,
) {
    let lower = body.to_ascii_lowercase();
    evidence.title = extract_title(body);
    evidence.has_password_field =
        lower.contains("type=\"password\"") || lower.contains("type='password'");
    evidence.has_otp_field = lower.contains("otp")
        || lower.contains("one-time")
        || lower.contains("2fa")
        || lower.contains("mfa");
    evidence.has_card_field =
        lower.contains("card number") || lower.contains("credit card") || lower.contains("cvv");
    evidence.form_count = lower.matches("<form").count();
    evidence.external_form_action = external_form_action_domain(&lower)
        .is_some_and(|action_domain| action_domain != page_domain);
    if let Some(brand) = matched_brand {
        evidence.page_brand_match = lower.contains(&brand.to_ascii_lowercase());
    }
}

fn external_form_action_domain(lower_html: &str) -> Option<String> {
    let re = Regex::new(r#"(?is)<form[^>]+action\s*=\s*['\"](https?://[^'\"\s>]+)['\"]"#).ok()?;
    re.captures_iter(lower_html).find_map(|caps| {
        caps.get(1)
            .map(|action| parse_url_parts(action.as_str()).registrable_domain)
            .filter(|domain| !domain.is_empty())
    })
}

fn extract_title(body: &str) -> Option<String> {
    let re = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").ok()?;
    re.captures(body).and_then(|caps| {
        caps.get(1).map(|title| {
            title
                .as_str()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(160)
                .collect()
        })
    })
}

fn whois_age_days(raw: &str) -> Option<i64> {
    let creation = extract_first(
        raw,
        &[
            r"(?im)^Creation Date:\s*(.+)",
            r"(?im)^created:\s*(.+)",
            r"(?im)^registered:\s*(.+)",
            r"(?im)^Created on\s*(.+)",
        ],
    )?;
    let parsed = chrono::DateTime::parse_from_rfc3339(&creation)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(&creation, "%Y-%m-%dT%H:%M:%SZ")
                .map(|dt| dt.and_utc())
        })
        .ok()?;
    Some((chrono::Utc::now() - parsed).num_days())
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

fn ip_provider(ip: IpAddr) -> Option<&'static str> {
    let IpAddr::V4(ip) = ip else {
        return None;
    };

    IP_PROVIDER_RANGES
        .iter()
        .find(|range| ipv4_in_cidr(ip, range.network, range.prefix))
        .map(|range| range.provider)
}

fn ipv4_in_cidr(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(network) & mask
}

struct IpProviderRange {
    network: Ipv4Addr,
    prefix: u8,
    provider: &'static str,
}

const IP_PROVIDER_RANGES: &[IpProviderRange] = &[
    IpProviderRange {
        network: Ipv4Addr::new(76, 76, 21, 0),
        prefix: 24,
        provider: "vercel",
    },
    IpProviderRange {
        network: Ipv4Addr::new(75, 2, 60, 0),
        prefix: 24,
        provider: "aws-global-accelerator/netlify",
    },
    IpProviderRange {
        network: Ipv4Addr::new(99, 83, 128, 0),
        prefix: 17,
        provider: "aws-global-accelerator/netlify",
    },
    IpProviderRange {
        network: Ipv4Addr::new(104, 16, 0, 0),
        prefix: 12,
        provider: "cloudflare",
    },
    IpProviderRange {
        network: Ipv4Addr::new(172, 64, 0, 0),
        prefix: 13,
        provider: "cloudflare",
    },
    IpProviderRange {
        network: Ipv4Addr::new(131, 103, 20, 160),
        prefix: 27,
        provider: "github-pages",
    },
    IpProviderRange {
        network: Ipv4Addr::new(185, 199, 108, 0),
        prefix: 22,
        provider: "github-pages",
    },
    IpProviderRange {
        network: Ipv4Addr::new(199, 232, 0, 0),
        prefix: 16,
        provider: "fastly",
    },
    IpProviderRange {
        network: Ipv4Addr::new(151, 101, 0, 0),
        prefix: 16,
        provider: "fastly",
    },
];

fn known_favicon_hashes_for(brand: &str) -> Option<&'static [String]> {
    let key = normalize_key(brand);
    favicon_catalog()
        .iter()
        .find(|(brand_key, _)| brand_key == &key)
        .map(|(_, hashes)| hashes.as_slice())
}

fn favicon_catalog() -> &'static [(String, Vec<String>)] {
    static CATALOG: OnceLock<Vec<(String, Vec<String>)>> = OnceLock::new();
    CATALOG.get_or_init(load_favicon_catalog)
}

fn load_favicon_catalog() -> Vec<(String, Vec<String>)> {
    let Some(path) = std::env::var("POSEIDON_FAVICON_HASHES_PATH")
        .ok()
        .or_else(|| default_file(DEFAULT_FAVICON_HASHES_PATH))
    else {
        return Vec::new();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return Vec::new();
    };
    let Some(map) = value.as_object() else {
        return Vec::new();
    };

    map.iter()
        .filter_map(|(brand, hashes)| {
            let hashes = hashes
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .map(|hash| hash.trim().to_ascii_lowercase())
                .filter(|hash| hash.len() == 64)
                .collect::<Vec<_>>();
            if hashes.is_empty() {
                None
            } else {
                Some((normalize_key(brand), hashes))
            }
        })
        .collect()
}

fn default_file(path: &str) -> Option<String> {
    std::path::Path::new(path)
        .exists()
        .then(|| path.to_string())
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}
