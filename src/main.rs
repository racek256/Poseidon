use Poseidon::modules;

fn main() {
    // Check for --interactive flag early, before subcommand processing
    let args: Vec<String> = std::env::args().collect();
    let interactive_mode = args.iter().any(|arg| arg == "--interactive");

    // Filter out --interactive from args for subcommand processing
    let filtered_args: Vec<String> = if interactive_mode {
        args.iter()
            .filter(|&&ref arg| arg != "--interactive")
            .cloned()
            .collect()
    } else {
        args.clone()
    };

    // Create a new args iterator that uses the filtered args
    let mut arg_iter = filtered_args.iter().map(|s| s.as_str());

    // Check first argument (subcommand)
    let first_arg = arg_iter.clone().nth(1);

    if first_arg == Some("worker") {
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

    if first_arg == Some("benchmark-brand") {
        modules::url_analysis::benchmark::run_brand_benchmark();
        return;
    }

    if first_arg == Some("benchmark-online-brand") {
        modules::url_analysis::online_benchmark::run_online_brand_benchmark();
        return;
    }

    if first_arg == Some("benchmark-message-memory") {
        modules::message_memory::run_benchmark().expect("message memory benchmark failed");
        return;
    }

    if first_arg == Some("benchmark-phishing") {
        modules::phishing_benchmark::run().expect("phishing benchmark failed");
        return;
    }

    if first_arg == Some("benchmark-phishing-full") {
        modules::phishing_benchmark::run_full().expect("full phishing benchmark failed");
        return;
    }

    if first_arg == Some("benchmark-phishing-full-online") {
        modules::phishing_benchmark::run_full_online()
            .expect("full online phishing benchmark failed");
        return;
    }

    if first_arg == Some("download-phishing-benchmark") {
        modules::phishing_benchmark::download_huggingface_dataset()
            .expect("phishing benchmark download failed");
        return;
    }

    if first_arg == Some("benchmark-brand-learning") {
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        modules::url_analysis::brand_detector::run_real_page_benchmark(&url_db)
            .expect("brand learning benchmark failed");
        return;
    }

    if first_arg == Some("inspect-brand-learning") {
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        url_db
            .print_brand_learning_summary()
            .expect("failed to inspect brand learning tables");
        return;
    }

    if first_arg == Some("enqueue-url") {
        // For args that need position 2, we need to account for --interactive
        let url = arg_iter
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

    if first_arg == Some("detect-brand-url") {
        let url = arg_iter
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

    if first_arg == Some("detect-impersonation-url") {
        let url = arg_iter
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

    if first_arg == Some("observe-safe-url") {
        let url = arg_iter
            .nth(2)
            .expect("usage: cargo run -- observe-safe-url <url> [count] [user_prefix]");
        let count = arg_iter
            .nth(3)
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        let user_prefix = arg_iter
            .nth(4)
            .unwrap_or("manual-user");
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

    if first_arg == Some("inspect-domain-reputation") {
        let domain = arg_iter
            .nth(2)
            .expect("usage: cargo run -- inspect-domain-reputation <domain>");
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        url_db
            .print_domain_reputation(&domain)
            .expect("failed to inspect domain reputation");
        return;
    }

    // Default mode: start server or TUI
    let addr = std::env::var("POSEIDON_API_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    if interactive_mode {
        modules::tui::run_tui(&addr);
    } else {
        check_api_addr_available(&addr).expect("api bind address unavailable");
        modules::llm_server::ensure();
        if let Err(err) = modules::ai::warmup() {
            eprintln!("llm warmup failed: {err}");
        }

        let threat_intel = modules::threat_intel::ThreatIntel::from_env()
            .expect("failed to initialize threat intel database");
        let url_db = modules::url_db::UrlDb::from_env().expect("failed to initialize url database");
        let message_memory = modules::message_memory::MessageMemory::from_env()
            .expect("failed to initialize message memory database");
        threat_intel.update_if_due();
        modules::api::serve(&addr, &threat_intel, &url_db, &message_memory)
            .expect("api server failed");
    }
}

fn check_api_addr_available(addr: &str) -> std::io::Result<()> {
    std::net::TcpListener::bind(addr).map(|_| ())
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
