use Poseidon::modules;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("worker") {
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        let limit = std::env::var("POSEIDON_WORKER_LIMIT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(100);
        let processed = modules::url_analysis::enrich::process_pending(&url_db, limit)
            .expect("url enrichment worker failed");
        println!("processed {processed} queued urls");
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("benchmark-brand") {
        modules::url_analysis::benchmark::run_brand_benchmark();
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("benchmark-online-brand") {
        modules::url_analysis::online_benchmark::run_online_brand_benchmark();
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("benchmark-message-memory") {
        modules::message_memory::run_benchmark().expect("message memory benchmark failed");
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("benchmark-phishing") {
        modules::phishing_benchmark::run().expect("phishing benchmark failed");
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("benchmark-brand-learning") {
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        modules::url_analysis::brand_detector::run_real_page_benchmark(&url_db)
            .expect("brand learning benchmark failed");
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("inspect-brand-learning") {
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        url_db
            .print_brand_learning_summary()
            .expect("failed to inspect brand learning tables");
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("enqueue-url") {
        let url = std::env::args()
            .nth(2)
            .expect("usage: cargo run -- enqueue-url <url>");
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        let identity = url_db.identity(&url);
        let queued = url_db
            .enqueue_unknown(&identity, &url, 50, "manual enqueue")
            .expect("failed to enqueue url");
        println!("queued={queued} url={url}");
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("detect-brand-url") {
        let url = std::env::args()
            .nth(2)
            .expect("usage: cargo run -- detect-brand-url <url>");
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        let domain = modules::url_analysis::domain::parse_url_parts(&url).registrable_domain;
        let tranco_rank = url_db
            .tranco_rank(&domain)
            .expect("failed to query Tranco rank");
        let local_reputation = url_db
            .domain_reputation(&domain)
            .expect("failed to query local domain reputation");
        let detection =
            modules::url_analysis::brand_detector::detect_brand_identity_with_reputation(
                &url,
                tranco_rank,
                local_reputation.boost,
            );
        println!("url: {url}");
        println!(
            "domain: {domain} tranco_rank: {tranco_rank:?} local_reputation_boost: {}",
            local_reputation.boost
        );
        if let Some(candidate) = detection.candidate {
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
        println!(
            "metadata: status={:?} title={:?} og_site={:?} orgs={:?} canonical={:?} fetch_error={:?}",
            detection.metadata.status,
            detection.metadata.title,
            detection.metadata.og_site_name,
            detection.metadata.organization_names,
            detection.metadata.canonical_domain,
            detection.metadata.fetch_error
        );
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("detect-impersonation-url") {
        let url = std::env::args()
            .nth(2)
            .expect("usage: cargo run -- detect-impersonation-url <url>");
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        let learned_brands = url_db
            .learned_runtime_brands()
            .expect("failed to load learned brands");
        let result =
            modules::url_analysis::brand::analyse_with_runtime_brands(&url, &learned_brands);
        println!(
            "url={url} learned_brands={} matched_brand={:?} official={} score={} confidence={} risk_level={} reasons={:?} safe_evidence={:?}",
            learned_brands.len(),
            result.matched_brand,
            result.official,
            result.score,
            result.confidence,
            result.risk_level,
            result.reasons,
            result.safe_evidence
        );
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("observe-safe-url") {
        let url = std::env::args()
            .nth(2)
            .expect("usage: cargo run -- observe-safe-url <url> [count] [user_prefix]");
        let count = std::env::args()
            .nth(3)
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        let user_prefix = std::env::args()
            .nth(4)
            .unwrap_or_else(|| "manual-user".to_string());
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        let identity = url_db.identity(&url);
        let mut reputation = modules::url_db::DomainReputation::default();
        for index in 0..count {
            let user_id = format!("{user_prefix}-{index}");
            reputation = url_db
                .observe_domain_reputation(&identity, Some(&user_id), true)
                .expect("failed to observe safe url");
        }
        if reputation.boost >= 10 {
            let _ = url_db
                .enqueue_analysis(
                    &identity,
                    &url,
                    40,
                    "manual safe local reputation threshold reached",
                )
                .expect("failed to enqueue url after safe observation");
        }
        println!(
            "url={url} safe_observations={} bad_observations={} boost={}",
            reputation.safe_observations, reputation.bad_observations, reputation.boost
        );
        return;
    }

    if std::env::args().nth(1).as_deref() == Some("inspect-domain-reputation") {
        let domain = std::env::args()
            .nth(2)
            .expect("usage: cargo run -- inspect-domain-reputation <domain>");
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        url_db
            .print_domain_reputation(&domain)
            .expect("failed to inspect domain reputation");
        return;
    }

    let threat_intel = modules::threat_intel::ThreatIntel::from_env()
        .expect("failed to initialize threat intel database");
    let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
    let message_memory = modules::message_memory::MessageMemory::from_env()
        .expect("failed to initialize message memory database");
    threat_intel.update_if_due();
    if let Err(err) = modules::ai::warmup() {
        eprintln!("ollama warmup failed: {err}");
    }
    let addr = std::env::var("POSEIDON_API_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    modules::api::serve(&addr, &threat_intel, &url_db, &message_memory).expect("api server failed");
}

/*
 * 1. extract URLs and whois check them ( network reliant )
 * 2. REGEX secrets check
 * 3. check for known prompt injection strings
 * 4. urgency keywords ( not sure about this one )
 * 5. pass message to LLM for analysis
 * 6. verify LLM output
 * 7. based on score do Decision
 * 8. if score low do AI summary
 * 9. Store hashed data in Database
*/
