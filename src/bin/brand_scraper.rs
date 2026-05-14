use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use reqwest::blocking::{Client, ClientBuilder};
use reqwest::redirect::Policy;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const WIKIDATA_SPARQL_URL: &str = "https://query.wikidata.org/sparql";
const DEFAULT_BRAND_CATALOG_PATH: &str = "data/brand_catalog.json";
const DEFAULT_FAVICON_HASHES_PATH: &str = "data/favicon_hashes.json";
const DEFAULT_BRAND_INFO_PATH: &str = "data/brand_info.json";
const MAX_FAVICON_BYTES: usize = 256 * 1024;

fn main() {
    if let Err(err) = run() {
        eprintln!("brand scraper failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let catalog_path = std::env::var("POSEIDON_BRAND_CATALOG_OUT")
        .unwrap_or_else(|_| DEFAULT_BRAND_CATALOG_PATH.to_string());
    let favicon_path = std::env::var("POSEIDON_FAVICON_HASHES_OUT")
        .unwrap_or_else(|_| DEFAULT_FAVICON_HASHES_PATH.to_string());
    let info_path = std::env::var("POSEIDON_BRAND_INFO_OUT")
        .unwrap_or_else(|_| DEFAULT_BRAND_INFO_PATH.to_string());
    let min_sitelinks = env_usize("POSEIDON_WIKIDATA_MIN_SITELINKS", 10);
    let brand_limit = env_usize("POSEIDON_BRAND_LIMIT", 2_000);
    let workers = env_usize("POSEIDON_FAVICON_WORKERS", 24).max(1);
    let max_domains_per_brand = env_usize("POSEIDON_MAX_DOMAINS_PER_BRAND", 2).max(1);

    ensure_parent(&catalog_path)?;
    ensure_parent(&favicon_path)?;
    ensure_parent(&info_path)?;

    let client = client(Duration::from_secs(45))?;
    eprintln!("querying Wikidata brand catalog: min_sitelinks={min_sitelinks} limit={brand_limit}");
    let brands = fetch_wikidata_brands(&client, min_sitelinks, brand_limit)?;
    if brands.len() < 1_000 {
        return Err(format!(
            "brand catalog too small: expected >=1000 brands, got {}",
            brands.len()
        ));
    }

    let catalog_json = catalog_json(&brands);
    fs::write(
        &catalog_path,
        serde_json::to_string_pretty(&catalog_json).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;

    eprintln!(
        "scraping favicons: brands={} workers={} max_domains_per_brand={}",
        brands.len(),
        workers,
        max_domains_per_brand
    );
    let favicon_results = scrape_favicons(&brands, workers, max_domains_per_brand)?;

    let mut favicon_hashes = serde_json::Map::new();
    let mut brand_info = serde_json::Map::new();
    let mut attempts = 0_usize;
    let mut successes = 0_usize;

    for brand in &brands {
        let result = favicon_results.get(&brand.key);
        let hashes = result
            .map(|result| result.hashes.clone())
            .unwrap_or_default();
        attempts += result.map(|result| result.attempts).unwrap_or_default();
        successes += result.map(|result| result.successes).unwrap_or_default();
        if !hashes.is_empty() {
            favicon_hashes.insert(brand.key.clone(), json!(hashes));
        }

        brand_info.insert(
            brand.key.clone(),
            json!({
                "name": brand.name,
                "wikidata_id": brand.wikidata_id,
                "sitelinks": brand.sitelinks,
                "domains": brand.domains,
                "source": "wikidata",
                "favicon_hash_count": result.map(|result| result.hashes.len()).unwrap_or_default(),
                "favicon_attempts": result.map(|result| result.attempts).unwrap_or_default(),
                "favicon_successes": result.map(|result| result.successes).unwrap_or_default()
            }),
        );
    }

    fs::write(
        &favicon_path,
        serde_json::to_string_pretty(&Value::Object(favicon_hashes))
            .map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;
    fs::write(
        &info_path,
        serde_json::to_string_pretty(&Value::Object(brand_info)).map_err(|err| err.to_string())?,
    )
    .map_err(|err| err.to_string())?;

    println!("brand catalog: {catalog_path} ({} brands)", brands.len());
    println!("favicon hashes: {favicon_path} ({successes}/{attempts} fetched)");
    println!("brand info: {info_path}");
    Ok(())
}

fn fetch_wikidata_brands(
    client: &Client,
    min_sitelinks: usize,
    limit: usize,
) -> Result<Vec<BrandEntry>, String> {
    let query = wikidata_query(min_sitelinks, limit);
    let raw = client
        .post(WIKIDATA_SPARQL_URL)
        .header("accept", "application/sparql-results+json")
        .form(&[("query", query.as_str()), ("format", "json")])
        .send()
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?
        .text()
        .map_err(|err| err.to_string())?;
    let value: Value = serde_json::from_str(&raw).map_err(|err| err.to_string())?;

    let rows = value
        .get("results")
        .and_then(|results| results.get("bindings"))
        .and_then(Value::as_array)
        .ok_or_else(|| "wikidata response missing results.bindings".to_string())?;

    let mut by_key: HashMap<String, BrandEntry> = HashMap::new();
    for row in rows {
        let Some(name) = binding_value(row, "itemLabel") else {
            continue;
        };
        if name.starts_with('Q') && name[1..].chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let Some(website) = binding_value(row, "website") else {
            continue;
        };
        let domain = normalize_domain(&website);
        if domain.is_empty() || domain == "wikidata.org" {
            continue;
        }
        let key = normalize_key(&name);
        if key.len() < 3 {
            continue;
        }
        let sitelinks = binding_value(row, "sitelinks")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_default();
        let wikidata_id = binding_value(row, "item")
            .and_then(|item| item.rsplit('/').next().map(str::to_string))
            .unwrap_or_default();

        by_key
            .entry(key.clone())
            .and_modify(|brand| {
                if !brand.domains.contains(&domain) {
                    brand.domains.push(domain.clone());
                }
                brand.sitelinks = brand.sitelinks.max(sitelinks);
            })
            .or_insert_with(|| BrandEntry {
                name,
                key,
                wikidata_id,
                sitelinks,
                domains: vec![domain],
            });
    }

    let mut brands = by_key.into_values().collect::<Vec<_>>();
    brands.sort_by(|a, b| {
        b.sitelinks
            .cmp(&a.sitelinks)
            .then_with(|| a.key.cmp(&b.key))
    });
    Ok(brands)
}

fn wikidata_query(min_sitelinks: usize, limit: usize) -> String {
    format!(
        r#"
SELECT DISTINCT ?item ?itemLabel ?website ?sitelinks WHERE {{
  ?item wdt:P856 ?website .
  ?item wikibase:sitelinks ?sitelinks .
  {{ ?item wdt:P31/wdt:P279* wd:Q431289 . }}      # brand
  UNION
  {{ ?item wdt:P31/wdt:P279* wd:Q4830453 . }}    # business
  FILTER(?sitelinks >= {min_sitelinks})
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
ORDER BY DESC(?sitelinks)
LIMIT {limit}
"#
    )
}

fn binding_value(row: &Value, key: &str) -> Option<String> {
    row.get(key)
        .and_then(|value| value.get("value"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn scrape_favicons(
    brands: &[BrandEntry],
    workers: usize,
    max_domains_per_brand: usize,
) -> Result<HashMap<String, FaviconResult>, String> {
    let queue = Arc::new(Mutex::new(VecDeque::from(brands.to_vec())));
    let results = Arc::new(Mutex::new(HashMap::new()));
    let completed = Arc::new(Mutex::new(0_usize));
    let total = brands.len();

    thread::scope(|scope| {
        for _ in 0..workers {
            let queue = Arc::clone(&queue);
            let results = Arc::clone(&results);
            let completed = Arc::clone(&completed);
            scope.spawn(move || {
                let Ok(client) = client(Duration::from_secs(5)) else {
                    return;
                };
                loop {
                    let brand = {
                        let mut queue = queue.lock().expect("favicon queue poisoned");
                        queue.pop_front()
                    };
                    let Some(brand) = brand else {
                        break;
                    };

                    let result = scrape_brand_favicons(&client, &brand, max_domains_per_brand);
                    {
                        let mut results = results.lock().expect("favicon results poisoned");
                        results.insert(brand.key.clone(), result);
                    }

                    let done = {
                        let mut completed = completed.lock().expect("favicon counter poisoned");
                        *completed += 1;
                        *completed
                    };
                    if done % 100 == 0 || done == total {
                        eprintln!("favicon scrape: {done}/{total} brands");
                    }
                }
            });
        }
    });

    Arc::try_unwrap(results)
        .map_err(|_| "favicon results still shared".to_string())?
        .into_inner()
        .map_err(|_| "favicon results poisoned".to_string())
}

fn scrape_brand_favicons(
    client: &Client,
    brand: &BrandEntry,
    max_domains_per_brand: usize,
) -> FaviconResult {
    let mut hashes = Vec::new();
    let mut attempts = 0_usize;
    let mut successes = 0_usize;

    for domain in brand.domains.iter().take(max_domains_per_brand) {
        attempts += 1;
        if let Some(hash) = fetch_favicon_hash(client, domain) {
            successes += 1;
            if !hashes.contains(&hash) {
                hashes.push(hash);
            }
        }
    }

    FaviconResult {
        hashes,
        attempts,
        successes,
    }
}

fn catalog_json(brands: &[BrandEntry]) -> Value {
    let mut map = serde_json::Map::new();
    for brand in brands {
        map.insert(brand.name.clone(), json!(brand.domains));
    }
    Value::Object(map)
}

fn client(timeout: Duration) -> Result<Client, String> {
    ClientBuilder::new()
        .timeout(timeout)
        .redirect(Policy::limited(5))
        .user_agent("Poseidon-brand-scraper/0.1 (Wikidata brand catalog builder)")
        .build()
        .map_err(|err| err.to_string())
}

fn ensure_parent(path: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct BrandEntry {
    name: String,
    key: String,
    wikidata_id: String,
    sitelinks: usize,
    domains: Vec<String>,
}

#[derive(Debug)]
struct FaviconResult {
    hashes: Vec<String>,
    attempts: usize,
    successes: usize,
}

fn fetch_favicon_hash(client: &Client, domain: &str) -> Option<String> {
    let urls = [
        format!("https://{domain}/favicon.ico"),
        format!("https://www.{domain}/favicon.ico"),
        format!("http://{domain}/favicon.ico"),
    ];

    for url in urls {
        let Ok(response) = client.get(&url).send() else {
            continue;
        };
        if !response.status().is_success() {
            continue;
        }
        let Ok(bytes) = response.bytes() else {
            continue;
        };
        if bytes.is_empty() || bytes.len() > MAX_FAVICON_BYTES {
            continue;
        }
        return Some(sha256_hex(&bytes));
    }

    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn normalize_domain(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_start_matches("www.")
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}
