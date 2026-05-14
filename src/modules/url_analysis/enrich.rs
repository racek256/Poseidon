use crate::modules::url_analysis::brand::BrandImpersonation;
use crate::modules::url_analysis::brand_detector;
use crate::modules::url_analysis::domain::parse_url_parts;
use crate::modules::url_analysis::online;
use crate::modules::url_db::{QueuedUrl, UrlDb};

const SOURCE: &str = "brand_impersonation_v1";

pub fn process_pending(url_db: &UrlDb, limit: usize) -> duckdb::Result<usize> {
    let queued = url_db.claim_pending(limit)?;
    let count = queued.len();

    for item in queued {
        if let Err(err) = process_one(url_db, &item) {
            let _ = url_db.mark_failed(item.id, &err.to_string());
            eprintln!("url enrichment failed for queue id {}: {err}", item.id);
        }
    }

    Ok(count)
}

fn process_one(url_db: &UrlDb, item: &QueuedUrl) -> duckdb::Result<()> {
    let identity = url_db.identity(&item.raw_url);
    let learned_brands = url_db.learned_runtime_brands()?;
    let online = online::analyse_online_with_runtime_brands(&item.raw_url, &learned_brands);
    let brand = online.deterministic;
    let risk_score = brand.score.max(online.score);
    let confidence = brand.confidence.max(online.confidence);
    let verdict = verdict_for(risk_score, brand.official);

    url_db.store_observation(&identity, verdict, confidence, risk_score, SOURCE)?;
    url_db.store_brand_impersonation(&identity, &brand)?;
    store_tags(url_db, &identity, &brand)?;
    store_evidence(url_db, &identity, &brand)?;
    url_db.add_evidence(
        &identity,
        "online",
        "score",
        None,
        Some(online.score),
        SOURCE,
    )?;
    url_db.add_evidence(
        &identity,
        "online",
        "timing_total_ms",
        Some(&format!(
            "{:.1}",
            online.timings.total.as_secs_f64() * 1000.0
        )),
        None,
        SOURCE,
    )?;

    url_db.add_evidence(
        &identity,
        "dns",
        "resolved",
        Some(&online.evidence.dns_resolved.to_string()),
        None,
        SOURCE,
    )?;
    if let Some(provider) = &online.evidence.ip_provider {
        url_db.add_evidence(
            &identity,
            "dns",
            "ip_provider",
            Some(provider),
            None,
            SOURCE,
        )?;
    }
    if let Some(error) = &online.evidence.dns_error {
        url_db.add_evidence(&identity, "dns", "error", Some(error), None, SOURCE)?;
    }

    if let Some(age) = online.evidence.whois_age_days {
        url_db.add_evidence(
            &identity,
            "whois",
            "age_days",
            Some(&age.to_string()),
            None,
            SOURCE,
        )?;
    }
    url_db.add_evidence(
        &identity,
        "whois",
        "privacy",
        Some(&online.evidence.whois_privacy.to_string()),
        None,
        SOURCE,
    )?;
    if let Some(error) = &online.evidence.whois_error {
        url_db.add_evidence(&identity, "whois", "error", Some(error), None, SOURCE)?;
    }

    if risk_score < 45 && !brand.official {
        learn_brand_identity(url_db, &item.raw_url)?;
    }

    url_db.mark_done(item.id)?;

    Ok(())
}

fn verdict_for(score: u8, official: bool) -> &'static str {
    if official {
        "good"
    } else if score >= 90 {
        "bad"
    } else if score >= 45 {
        "suspicious"
    } else {
        "unknown"
    }
}

fn learn_brand_identity(url_db: &UrlDb, url: &str) -> duckdb::Result<()> {
    let domain = parse_url_parts(url).registrable_domain;
    let tranco_rank = url_db.tranco_rank(&domain)?;
    let local_reputation = url_db.domain_reputation(&domain)?;
    let detection = brand_detector::detect_brand_identity_with_reputation(
        url,
        tranco_rank,
        local_reputation.boost,
    );
    if let Some(candidate) = &detection.candidate {
        url_db.store_brand_candidate(candidate)?;
    }
    for relationship in &detection.relationships {
        url_db.store_domain_relationship(relationship)?;
    }
    Ok(())
}

fn store_tags(
    url_db: &UrlDb,
    identity: &crate::modules::url_db::UrlIdentity,
    brand: &BrandImpersonation,
) -> duckdb::Result<()> {
    url_db.add_tag(
        identity,
        &format!("risk_level:{}", brand.risk_level),
        Some(brand.confidence),
        SOURCE,
    )?;

    if let Some(matched_brand) = &brand.matched_brand {
        url_db.add_tag(identity, "brand_seen", Some(brand.confidence), SOURCE)?;
        url_db.add_tag(
            identity,
            &format!("brand:{}", tag_value(matched_brand)),
            Some(brand.confidence),
            SOURCE,
        )?;
    }
    if brand.official {
        url_db.add_tag(
            identity,
            "official_brand_domain",
            Some(brand.confidence),
            SOURCE,
        )?;
    }
    if brand.score >= 45 {
        url_db.add_tag(
            identity,
            "brand_impersonation",
            Some(brand.confidence),
            SOURCE,
        )?;
    }
    if let Some(provider) = &brand.hosting_provider {
        url_db.add_tag(identity, "known_hosting_provider", Some(80), SOURCE)?;
        url_db.add_tag(
            identity,
            &format!("hosting_provider:{}", tag_value(provider)),
            Some(80),
            SOURCE,
        )?;
    }

    Ok(())
}

fn store_evidence(
    url_db: &UrlDb,
    identity: &crate::modules::url_db::UrlIdentity,
    brand: &BrandImpersonation,
) -> duckdb::Result<()> {
    url_db.add_evidence(identity, "brand", "score", None, Some(brand.score), SOURCE)?;
    if let Some(matched_brand) = &brand.matched_brand {
        url_db.add_evidence(
            identity,
            "brand",
            "matched_brand",
            Some(matched_brand),
            Some(brand.score),
            SOURCE,
        )?;
    }
    if let Some(provider) = &brand.hosting_provider {
        url_db.add_evidence(
            identity,
            "hosting",
            "provider",
            Some(provider),
            None,
            SOURCE,
        )?;
    }
    for reason in &brand.reasons {
        url_db.add_evidence(
            identity,
            "brand",
            "reason",
            Some(reason),
            Some(brand.score),
            SOURCE,
        )?;
    }
    for evidence in &brand.safe_evidence {
        url_db.add_evidence(
            identity,
            "brand",
            "safe_evidence",
            Some(evidence),
            None,
            SOURCE,
        )?;
    }
    Ok(())
}

fn tag_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}
