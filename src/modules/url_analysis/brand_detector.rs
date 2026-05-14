use serde_json::json;

use crate::modules::url_analysis::domain::parse_url_parts;
use crate::modules::url_analysis::hosting::hosting_provider_domain;
use crate::modules::url_analysis::page_metadata::{PageMetadata, fetch_page_metadata};
use crate::modules::url_db::UrlDb;

#[derive(Debug)]
pub struct BrandCandidate {
    pub brand_key: String,
    pub display_name: String,
    pub primary_domain: String,
    pub status: String,
    pub confidence: u8,
    pub tranco_rank: Option<u32>,
    pub evidence_json: String,
}

#[derive(Debug)]
pub struct DomainRelationship {
    pub source_domain: String,
    pub related_domain: String,
    pub relation_type: String,
    pub confidence: u8,
    pub evidence_json: String,
}

#[derive(Debug)]
pub struct BrandDetection {
    pub candidate: Option<BrandCandidate>,
    pub relationships: Vec<DomainRelationship>,
    pub metadata: PageMetadata,
}

pub fn detect_brand_identity(url: &str, tranco_rank: Option<u32>) -> BrandDetection {
    detect_brand_identity_with_reputation(url, tranco_rank, 0)
}

pub fn detect_brand_identity_with_reputation(
    url: &str,
    tranco_rank: Option<u32>,
    local_reputation_boost: u8,
) -> BrandDetection {
    let source_domain = parse_url_parts(url).registrable_domain;
    let metadata = fetch_page_metadata(url);
    let identity_name = best_identity_name(&metadata);
    let mut relationships = related_domains(&source_domain, &metadata);

    let candidate = identity_name.and_then(|display_name| {
        let confidence = confidence_for(
            &source_domain,
            tranco_rank,
            local_reputation_boost,
            &metadata,
        );
        if confidence < 55
            || !candidate_allowed(
                &source_domain,
                tranco_rank,
                local_reputation_boost,
                &metadata,
                &display_name,
            )
        {
            return None;
        }
        let status = if confidence >= 85 {
            "verified"
        } else {
            "candidate"
        };
        let evidence = json!({
            "signals": signals(&metadata),
            "tranco_rank": tranco_rank,
            "local_reputation_boost": local_reputation_boost,
            "final_domain": metadata.final_domain,
            "canonical_domain": metadata.canonical_domain,
            "organization_domains": metadata.organization_domains,
            "same_as_domains": metadata.same_as_domains,
            "analytics_ids_seen": metadata.analytics_ids.len(),
            "forms": metadata.form_count,
            "has_credentials": metadata.has_password_field || metadata.has_credential_field
        })
        .to_string();

        Some(BrandCandidate {
            brand_key: normalize_key(&display_name),
            display_name,
            primary_domain: source_domain.clone(),
            status: status.to_string(),
            confidence,
            tranco_rank,
            evidence_json: evidence,
        })
    });

    if metadata.analytics_ids.len() > 0 {
        for analytics_id in &metadata.analytics_ids {
            relationships.push(DomainRelationship {
                source_domain: source_domain.clone(),
                related_domain: source_domain.clone(),
                relation_type: "analytics_id_seen".to_string(),
                confidence: 35,
                evidence_json: json!({ "analytics_id_hash": hashish(analytics_id) }).to_string(),
            });
        }
    }

    BrandDetection {
        candidate,
        relationships,
        metadata,
    }
}

pub fn run_real_page_benchmark(url_db: &UrlDb) -> duckdb::Result<()> {
    let urls = [
        "https://www.spotify.com/",
        "https://www.netflix.com/",
        "https://www.paypal.com/",
        "https://github.com/",
        "https://www.microsoft.com/",
        "https://www.apple.com/",
        "https://example.com/",
        "https://my-project.vercel.app/",
    ];

    for url in urls {
        let domain = parse_url_parts(url).registrable_domain;
        let tranco_rank = url_db.tranco_rank(&domain)?;
        let detection = detect_brand_identity(url, tranco_rank);
        println!("url: {url}");
        println!("domain: {domain} tranco_rank: {tranco_rank:?}");
        if let Some(candidate) = &detection.candidate {
            println!(
                "candidate: {} key={} status={} confidence={} evidence={}",
                candidate.display_name,
                candidate.brand_key,
                candidate.status,
                candidate.confidence,
                candidate.evidence_json
            );
        } else {
            println!("candidate: none");
        }
        println!("relationships: {}", detection.relationships.len());
        for relationship in detection.relationships.iter().take(5) {
            println!(
                "relationship: {} -> {} type={} confidence={}",
                relationship.source_domain,
                relationship.related_domain,
                relationship.relation_type,
                relationship.confidence
            );
        }
        println!(
            "metadata: status={:?} title={:?} og_site={:?} orgs={:?} canonical={:?} same_as_count={} analytics_count={} fetch_error={:?}",
            detection.metadata.status,
            detection.metadata.title,
            detection.metadata.og_site_name,
            detection.metadata.organization_names,
            detection.metadata.canonical_domain,
            detection.metadata.same_as_domains.len(),
            detection.metadata.analytics_ids.len(),
            detection.metadata.fetch_error
        );
        println!();
    }

    Ok(())
}

fn best_identity_name(metadata: &PageMetadata) -> Option<String> {
    metadata
        .organization_names
        .first()
        .cloned()
        .or_else(|| metadata.og_site_name.clone())
        .or_else(|| metadata.application_name.clone())
        .or_else(|| metadata.apple_app_title.clone())
        .or_else(|| metadata.og_title.clone())
        .or_else(|| metadata.title.clone())
        .map(clean_brand_name)
        .filter(|value| normalize_key(value).len() >= 3)
}

fn confidence_for(
    source_domain: &str,
    tranco_rank: Option<u32>,
    local_reputation_boost: u8,
    metadata: &PageMetadata,
) -> u8 {
    if metadata.form_count > 0
        && (metadata.has_password_field || metadata.has_credential_field)
        && !has_authoritative_signal(source_domain, metadata)
        && !canonical_matches_domain_label(source_domain, metadata)
        && !(local_reputation_boost >= 10 && tranco_rank.is_some_and(|rank| rank <= 100_000))
    {
        return 0;
    }
    let mut confidence: u8 = 0;
    if let Some(rank) = tranco_rank {
        if rank <= 10_000 {
            confidence += 45;
        } else if rank <= 100_000 {
            confidence += 35;
        } else {
            confidence += 20;
        }
    }
    confidence = confidence.saturating_add(local_reputation_boost.min(15));
    if !metadata.organization_names.is_empty() {
        confidence += 25;
    }
    if metadata.og_site_name.is_some() || metadata.application_name.is_some() {
        confidence += 15;
    }
    if tranco_rank.is_some_and(|rank| rank <= 10_000) && metadata.title.is_some() {
        confidence += 10;
    }
    if local_reputation_boost >= 10
        && tranco_rank.is_some_and(|rank| rank <= 100_000)
        && metadata.title.is_some()
    {
        confidence += 10;
    }
    if metadata.canonical_domain.as_deref() == Some(source_domain)
        || metadata
            .organization_domains
            .iter()
            .any(|domain| domain == source_domain)
    {
        confidence += 15;
    }
    if canonical_matches_domain_label(source_domain, metadata) {
        confidence += 15;
    }
    if tranco_rank.is_some_and(|rank| rank <= 100)
        && metadata.canonical_domain.as_deref() == Some(source_domain)
    {
        confidence += 15;
    }
    if !metadata.same_as_domains.is_empty() {
        confidence += 10;
    }
    confidence.min(95)
}

fn candidate_allowed(
    source_domain: &str,
    tranco_rank: Option<u32>,
    local_reputation_boost: u8,
    metadata: &PageMetadata,
    display_name: &str,
) -> bool {
    if matches!(source_domain, "example.com" | "example.org" | "example.net") {
        return false;
    }
    if hosting_provider_domain(source_domain).is_some()
        && !has_authoritative_signal(source_domain, metadata)
    {
        return false;
    }
    if has_authoritative_signal(source_domain, metadata) {
        return true;
    }
    if canonical_matches_domain_label(source_domain, metadata) {
        return true;
    }
    if local_reputation_boost >= 10
        && tranco_rank.is_some_and(|rank| rank <= 100_000)
        && metadata.title.is_some()
    {
        return true;
    }
    if !title_matches_domain_label(source_domain, display_name) {
        return false;
    }
    if tranco_rank.is_some_and(|rank| rank <= 1_000) {
        return true;
    }
    if local_reputation_boost >= 10 && tranco_rank.is_some_and(|rank| rank <= 100_000) {
        return true;
    }
    tranco_rank.is_some_and(|rank| rank <= 10_000)
        && (metadata.og_site_name.is_some() || metadata.application_name.is_some())
}

fn has_authoritative_signal(source_domain: &str, metadata: &PageMetadata) -> bool {
    metadata.canonical_domain.as_deref() == Some(source_domain)
        || metadata
            .organization_domains
            .iter()
            .any(|domain| domain == source_domain)
        || metadata
            .same_as_domains
            .iter()
            .any(|domain| domain == source_domain)
}

fn canonical_matches_domain_label(source_domain: &str, metadata: &PageMetadata) -> bool {
    let Some(canonical_domain) = metadata.canonical_domain.as_deref() else {
        return false;
    };
    let Some(source_label) = source_domain.split('.').next() else {
        return false;
    };
    let Some(canonical_label) = canonical_domain.split('.').next() else {
        return false;
    };
    source_label == canonical_label
}

fn title_matches_domain_label(source_domain: &str, display_name: &str) -> bool {
    let Some(label) = source_domain.split('.').next() else {
        return false;
    };
    let label = normalize_key(label);
    !label.is_empty() && normalize_key(display_name).contains(&label)
}

fn signals(metadata: &PageMetadata) -> Vec<&'static str> {
    let mut signals = Vec::new();
    if !metadata.organization_names.is_empty() {
        signals.push("jsonld_organization");
    }
    if metadata.og_site_name.is_some() {
        signals.push("og_site_name");
    }
    if metadata.application_name.is_some() {
        signals.push("application_name");
    }
    if metadata.canonical_domain.is_some() {
        signals.push("canonical_domain");
    }
    if !metadata.same_as_domains.is_empty() {
        signals.push("same_as_domains");
    }
    signals
}

fn related_domains(source_domain: &str, metadata: &PageMetadata) -> Vec<DomainRelationship> {
    let mut relationships = Vec::new();
    for domain in metadata
        .organization_domains
        .iter()
        .chain(metadata.same_as_domains.iter())
        .chain(metadata.canonical_domain.iter())
        .chain(metadata.manifest_domain.iter())
    {
        if domain == source_domain || domain.is_empty() {
            continue;
        }
        relationships.push(DomainRelationship {
            source_domain: source_domain.to_string(),
            related_domain: domain.clone(),
            relation_type: "page_metadata".to_string(),
            confidence: 55,
            evidence_json: json!({ "source": "page_metadata" }).to_string(),
        });
    }
    relationships
}

fn clean_brand_name(value: String) -> String {
    let parts = value
        .split(['|', ':', ',', '-', '–', '—'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let selected = parts
        .iter()
        .find(|part| !is_generic_title_prefix(part))
        .copied()
        .or_else(|| parts.first().copied())
        .unwrap_or(&value);

    selected
        .trim()
        .trim_end_matches(".com")
        .trim_end_matches(".org")
        .trim_end_matches(".net")
        .chars()
        .take(80)
        .collect()
}

fn is_generic_title_prefix(value: &str) -> bool {
    matches!(
        normalize_key(value).as_str(),
        "home" | "homepage" | "index" | "uvod" | "vod"
    )
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter_map(fold_key_char)
        .collect::<String>()
        .to_ascii_lowercase()
}

fn fold_key_char(ch: char) -> Option<char> {
    if ch.is_ascii_alphanumeric() {
        return Some(ch);
    }
    match ch {
        'á' | 'à' | 'ä' | 'â' | 'ã' | 'å' | 'Á' | 'À' | 'Ä' | 'Â' | 'Ã' | 'Å' => {
            Some('a')
        }
        'č' | 'ç' | 'Č' | 'Ç' => Some('c'),
        'ď' | 'Ď' => Some('d'),
        'é' | 'ě' | 'è' | 'ë' | 'ê' | 'É' | 'Ě' | 'È' | 'Ë' | 'Ê' => Some('e'),
        'í' | 'ì' | 'ï' | 'î' | 'Í' | 'Ì' | 'Ï' | 'Î' => Some('i'),
        'ň' | 'ñ' | 'Ň' | 'Ñ' => Some('n'),
        'ó' | 'ò' | 'ö' | 'ô' | 'õ' | 'Ó' | 'Ò' | 'Ö' | 'Ô' | 'Õ' => Some('o'),
        'ř' | 'Ř' => Some('r'),
        'š' | 'Š' => Some('s'),
        'ť' | 'Ť' => Some('t'),
        'ú' | 'ů' | 'ù' | 'ü' | 'û' | 'Ú' | 'Ů' | 'Ù' | 'Ü' | 'Û' => Some('u'),
        'ý' | 'ÿ' | 'Ý' | 'Ÿ' => Some('y'),
        'ž' | 'Ž' => Some('z'),
        _ => None,
    }
}

fn hashish(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}
