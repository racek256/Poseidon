use std::fs;
use std::sync::OnceLock;

use serde_json::Value;

use crate::modules::url_analysis::domain::{DomainParts, parse_url_parts};
use crate::modules::url_analysis::hosting::hosting_provider_domain;

const DEFAULT_BRAND_CATALOG_PATH: &str = "data/brand_catalog.json";

#[derive(Debug)]
pub struct BrandImpersonation {
    pub score: u8,
    pub confidence: u8,
    pub risk_level: String,
    pub matched_brand: Option<String>,
    pub official: bool,
    pub hosting_provider: Option<String>,
    pub reasons: Vec<String>,
    pub safe_evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RuntimeBrand {
    pub name: String,
    pub official_domains: Vec<String>,
}

#[derive(Debug)]
struct Brand {
    name: String,
    tokens: Vec<String>,
    official_domains: Vec<String>,
    common_word: bool,
}

pub fn analyse(url: &str) -> BrandImpersonation {
    analyse_with_runtime_brands(url, &[])
}

pub fn analyse_with_runtime_brands(
    url: &str,
    runtime_brands: &[RuntimeBrand],
) -> BrandImpersonation {
    let extra_brands = runtime_brands
        .iter()
        .filter_map(|brand| brand_from_domains(&brand.name, brand.official_domains.clone()))
        .collect::<Vec<_>>();
    analyse_with_brands(url, &extra_brands)
}

fn analyse_with_brands(url: &str, extra_brands: &[Brand]) -> BrandImpersonation {
    let parts = parse_url_parts(url);
    let hosting_provider = hosting_provider_domain(&parts.registrable_domain).map(str::to_string);
    let haystack = format!(
        "{} {} {}",
        parts.host,
        parts.subdomain.as_deref().unwrap_or_default(),
        parts.path_query
    );
    let phishing_keywords = phishing_keyword_hits(&haystack);

    let mut best = BrandImpersonation {
        score: 0,
        confidence: 90,
        risk_level: "low".to_string(),
        matched_brand: None,
        official: false,
        hosting_provider,
        reasons: Vec::new(),
        safe_evidence: Vec::new(),
    };

    if best.hosting_provider.is_some() && !phishing_keywords.is_empty() {
        best.score = 55;
        best.confidence = 70;
        best.risk_level = "medium".to_string();
        best.reasons
            .push("registrable domain is a known hosting provider".to_string());
        best.reasons.push(format!(
            "phishing intent keywords present: {}",
            phishing_keywords.join(", ")
        ));
    }

    for brand in brands().iter().chain(extra_brands.iter()) {
        if brand.official_domains.iter().any(|domain| {
            parts.registrable_domain == *domain || parts.host.ends_with(&format!(".{domain}"))
        }) {
            return BrandImpersonation {
                score: 5,
                confidence: 95,
                risk_level: "low".to_string(),
                matched_brand: Some(brand.name.clone()),
                official: true,
                hosting_provider: best.hosting_provider,
                reasons: vec!["official brand domain".to_string()],
                safe_evidence: vec!["official allowlist match".to_string()],
            };
        }

        let token_match = brand
            .tokens
            .iter()
            .find(|token| token_matches_url_parts(&parts, token));
        let typo_match = brand
            .tokens
            .iter()
            .any(|token| domain_label_is_typo(&parts.registrable_domain, token));
        let subdomain_typo_match = parts.subdomain.as_deref().is_some_and(|subdomain| {
            brand
                .tokens
                .iter()
                .any(|token| text_label_is_typo(subdomain, token))
        });

        if token_match.is_none() && !typo_match && !subdomain_typo_match {
            continue;
        }

        let mut score: u8 = 20;
        let mut reasons = Vec::new();
        let mut host_or_domain_signal = typo_match || subdomain_typo_match;
        let mut path_only_signal = false;

        if let Some(token) = token_match {
            if domain_label_contains_token(&parts.registrable_domain, token) {
                score = score.max(50);
                host_or_domain_signal = true;
                reasons.push("brand token appears in unrelated registrable domain".to_string());
            }
            if parts
                .subdomain
                .as_deref()
                .is_some_and(|sub| subdomain_contains_token(sub, token))
            {
                score = score.max(60);
                host_or_domain_signal = true;
                reasons.push("brand token appears in subdomain or tenant".to_string());
            }
            if parts.path_query.contains(token) {
                score = score.max(25);
                path_only_signal = !host_or_domain_signal;
                reasons.push("brand token appears in path or query".to_string());
            }
        }

        if typo_match {
            if !phishing_keywords.is_empty() {
                score = score.max(65);
            } else {
                score = score.max(30);
            }
            reasons.push("registrable domain is visually close to brand token".to_string());
        }

        if subdomain_typo_match {
            if !phishing_keywords.is_empty() {
                score = score.max(65);
            } else {
                score = score.max(30);
            }
            reasons.push("subdomain is visually close to brand token".to_string());
        }

        if best.hosting_provider.is_some() {
            reasons.push("registrable domain is a known hosting provider".to_string());
        }

        if !phishing_keywords.is_empty() {
            reasons.push(format!(
                "phishing intent keywords present: {}",
                phishing_keywords.join(", ")
            ));
            if brand.common_word {
                score = score.max(55);
            } else {
                score = score.saturating_add(20).min(90);
            }
        } else if brand.common_word {
            score = score.min(35);
            reasons.push("brand is a common word, requiring stronger evidence".to_string());
        }

        if path_only_signal && !host_or_domain_signal {
            score = score.min(35);
            reasons.push("brand appears only in path, capping risk".to_string());
        }

        let candidate = BrandImpersonation {
            score,
            confidence: confidence_for(score),
            risk_level: risk_level(score).to_string(),
            matched_brand: Some(brand.name.clone()),
            official: false,
            hosting_provider: best.hosting_provider.clone(),
            reasons,
            safe_evidence: Vec::new(),
        };

        if candidate.score > best.score {
            best = candidate;
        }
    }

    best
}

fn token_matches_url_parts(parts: &DomainParts, token: &str) -> bool {
    domain_label_contains_token(&parts.registrable_domain, token)
        || parts
            .subdomain
            .as_deref()
            .is_some_and(|subdomain| subdomain_contains_token(subdomain, token))
        || parts.path_query.contains(token)
}

fn domain_label_contains_token(registrable_domain: &str, token: &str) -> bool {
    let label = registrable_domain.split('.').next().unwrap_or_default();
    label_contains_token(label, token)
}

fn subdomain_contains_token(subdomain: &str, token: &str) -> bool {
    subdomain
        .split('.')
        .any(|label| label_contains_token(label, token))
}

fn label_contains_token(label: &str, token: &str) -> bool {
    if token.len() <= 4 {
        return label == token
            || label.starts_with(&format!("{token}-"))
            || label.ends_with(&format!("-{token}"));
    }
    label.contains(token)
}

fn phishing_keyword_hits(text: &str) -> Vec<String> {
    PHISHING_KEYWORDS
        .iter()
        .filter(|keyword| text.contains(**keyword))
        .map(|keyword| keyword.to_string())
        .collect()
}

fn domain_label_is_typo(registrable_domain: &str, brand_token: &str) -> bool {
    let label = registrable_domain.split('.').next().unwrap_or_default();
    label_is_typo(label, brand_token)
}

fn text_label_is_typo(text: &str, brand_token: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|label| !is_ignored_subdomain_label(label))
        .any(|label| label_is_typo(label, brand_token))
}

fn label_is_typo(label: &str, brand_token: &str) -> bool {
    if label.len() < 4 || brand_token.len() < 5 {
        return false;
    }
    if label == brand_token {
        return false;
    }

    let normalized_label = normalize_typos(label);
    let normalized_brand = normalize_typos(brand_token);
    if normalized_label == normalized_brand {
        return true;
    }

    if normalized_label.len().abs_diff(normalized_brand.len()) > 2 {
        return false;
    }

    let distance = levenshtein(&normalized_label, &normalized_brand);
    if normalized_brand.len() <= 6 {
        distance == 1
    } else {
        distance <= 2
    }
}

fn is_ignored_subdomain_label(label: &str) -> bool {
    matches!(
        label,
        "www" | "www1" | "www2" | "mail" | "m" | "web" | "dev" | "app"
    )
}

fn normalize_typos(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '5' => 's',
            '@' => 'a',
            _ => ch,
        })
        .collect()
}

fn levenshtein(a: &str, b: &str) -> usize {
    let mut costs: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut last = i;
        costs[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let old = costs[j + 1];
            costs[j + 1] = if ca == cb {
                last
            } else {
                1 + last.min(costs[j]).min(costs[j + 1])
            };
            last = old;
        }
    }
    costs[b.len()]
}

fn confidence_for(score: u8) -> u8 {
    if score >= 75 {
        85
    } else if score >= 45 {
        70
    } else {
        55
    }
}

fn risk_level(score: u8) -> &'static str {
    if score >= 75 {
        "high"
    } else if score >= 45 {
        "medium"
    } else {
        "low"
    }
}

fn brands() -> &'static [Brand] {
    static BRANDS: OnceLock<Vec<Brand>> = OnceLock::new();
    BRANDS.get_or_init(load_brands)
}

fn load_brands() -> Vec<Brand> {
    std::env::var("POSEIDON_BRAND_CATALOG_PATH")
        .ok()
        .or_else(|| default_file(DEFAULT_BRAND_CATALOG_PATH))
        .and_then(|path| load_brand_catalog(&path).ok())
        .filter(|brands| !brands.is_empty())
        .unwrap_or_else(fallback_brands)
}

fn default_file(path: &str) -> Option<String> {
    std::path::Path::new(path)
        .exists()
        .then(|| path.to_string())
}

fn load_brand_catalog(path: &str) -> Result<Vec<Brand>, String> {
    let raw = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let value: Value = serde_json::from_str(&raw).map_err(|err| err.to_string())?;

    if let Some(map) = value.as_object() {
        return Ok(map
            .iter()
            .filter_map(|(name, domains)| {
                let domains = domains
                    .as_array()?
                    .iter()
                    .filter_map(Value::as_str)
                    .map(normalize_domain_value)
                    .filter(|domain| !domain.is_empty())
                    .collect::<Vec<_>>();
                brand_from_domains(name, domains)
            })
            .collect());
    }

    if let Some(items) = value.as_array() {
        return Ok(items
            .iter()
            .filter_map(|item| {
                let name = item.get("name").and_then(Value::as_str)?;
                let domains = item
                    .get("official_domains")
                    .or_else(|| item.get("domains"))?
                    .as_array()?
                    .iter()
                    .filter_map(Value::as_str)
                    .map(normalize_domain_value)
                    .filter(|domain| !domain.is_empty())
                    .collect::<Vec<_>>();
                brand_from_domains(name, domains)
            })
            .collect());
    }

    Err("unsupported brand catalog format".to_string())
}

fn brand_from_domains(name: &str, official_domains: Vec<String>) -> Option<Brand> {
    if official_domains.is_empty() {
        return None;
    }

    let mut tokens = Vec::new();
    let name_token = brand_token(name);
    if name_token.len() >= 3 {
        tokens.push(name_token);
    }
    tokens.extend(official_domains.iter().filter_map(|domain| {
        domain
            .split('.')
            .next()
            .map(|label| label.to_ascii_lowercase())
            .filter(|token| token.len() >= 3)
    }));
    tokens.extend(official_domains.iter().filter_map(|domain| {
        domain
            .split('.')
            .next()
            .map(brand_token)
            .filter(|token| token.len() >= 3)
    }));
    tokens.extend(aliases_for(name).iter().map(|alias| alias.to_string()));
    tokens.sort();
    tokens.dedup();

    Some(Brand {
        name: name.to_string(),
        tokens,
        official_domains,
        common_word: is_common_brand_word(name),
    })
}

fn normalize_domain_value(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_start_matches("www.")
        .to_ascii_lowercase()
}

fn brand_token(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn is_common_brand_word(name: &str) -> bool {
    matches!(
        brand_token(name).as_str(),
        "apple" | "meta" | "box" | "x" | "discoveryinc"
    )
}

fn aliases_for(name: &str) -> &'static [&'static str] {
    match brand_token(name).as_str() {
        "apple" => &["appleid"],
        "facebook" => &["fb"],
        "ledger" => &["ledgr", "liveledgr"],
        "tmobile" => &["t-mobile"],
        _ => &[],
    }
}

fn fallback_brands() -> Vec<Brand> {
    [
        ("PayPal", &["paypal.com", "paypal.me"][..]),
        ("Google", &["google.com", "gmail.com"][..]),
        (
            "Microsoft",
            &["microsoft.com", "live.com", "office.com", "outlook.com"][..],
        ),
        ("Apple", &["apple.com", "icloud.com"][..]),
        ("Amazon", &["amazon.com", "amazon.co.uk"][..]),
        ("Facebook", &["facebook.com", "meta.com"][..]),
        ("Instagram", &["instagram.com"][..]),
        ("X", &["x.com", "twitter.com"][..]),
        ("LinkedIn", &["linkedin.com"][..]),
        ("GitHub", &["github.com"][..]),
        ("Coinbase", &["coinbase.com"][..]),
        ("Binance", &["binance.com"][..]),
        ("MetaMask", &["metamask.io"][..]),
        ("Dropbox", &["dropbox.com"][..]),
        ("DocuSign", &["docusign.com"][..]),
        ("Adobe", &["adobe.com"][..]),
        ("Netflix", &["netflix.com"][..]),
        ("Ledger", &["ledger.com"][..]),
        ("T-Mobile", &["t-mobile.com"][..]),
        ("Barclays", &["barclays.co.uk", "barclays.com"][..]),
        ("Roblox", &["roblox.com"][..]),
        ("Airbnb", &["airbnb.com"][..]),
    ]
    .into_iter()
    .filter_map(|(name, domains)| {
        brand_from_domains(
            name,
            domains.iter().map(|domain| domain.to_string()).collect(),
        )
    })
    .collect()
}

const PHISHING_KEYWORDS: &[&str] = &[
    "login",
    "verify",
    "secure",
    "account",
    "password",
    "wallet",
    "payment",
    "invoice",
    "support",
    "update",
    "suspended",
    "recover",
];
