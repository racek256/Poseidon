use std::error::Error;
use std::io::{Cursor, Read};

use csv::ReaderBuilder;
use flate2::read::GzDecoder;
use regex::Regex;
use reqwest::blocking::Client;
use serde_json::Value;
use tar::Archive;
use zip::ZipArchive;

use super::db::{normalize_domain, normalize_url};
use super::sources::{FeedFormat, FeedSource};

type FeedResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug)]
pub struct ThreatRecord {
    pub indicator: String,
    pub indicator_type: String,
    pub threat_type: String,
    pub source: String,
    pub source_ref: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub confidence: Option<u8>,
    pub tags: Vec<String>,
}

pub fn fetch_source(source: &FeedSource) -> FeedResult<Vec<ThreatRecord>> {
    let client = Client::builder()
        .user_agent("Poseidon threat intel/0.1")
        .build()?;
    match source.format {
        FeedFormat::UrlhausZipJson => {
            let body = download_bytes(&client, source.url)?;
            let mut zip = ZipArchive::new(Cursor::new(body))?;
            let mut json = String::new();
            zip.by_name("urlhaus_full.json")?
                .read_to_string(&mut json)?;
            parse_urlhaus_json(source, &json)
        }
        FeedFormat::UrlhausJson => parse_urlhaus_json(source, &download_text(&client, source.url)?),
        FeedFormat::PhishuntJson => parse_phishunt(source, &download_text(&client, source.url)?),
        FeedFormat::StringArrayJson => {
            parse_string_array(source, &download_text(&client, source.url)?)
        }
        FeedFormat::MetamaskJson => parse_metamask(source, &download_text(&client, source.url)?),
        FeedFormat::TweetFeedJson => parse_tweetfeed(source, &download_text(&client, source.url)?),
        FeedFormat::SpmediaJson => parse_spmedia(source, &download_text(&client, source.url)?),
        FeedFormat::PhishTankGzipJson => {
            let body = download_bytes(&client, source.url)?;
            let mut json = String::new();
            GzDecoder::new(Cursor::new(body)).read_to_string(&mut json)?;
            parse_phishtank(source, &json)
        }
        FeedFormat::MispDirectory => parse_misp_directory(&client, source),
        FeedFormat::MispManifest => parse_misp_manifest(&client, source),
        FeedFormat::HostsFile => Ok(parse_hosts(source, &download_text(&client, source.url)?)),
        FeedFormat::PlainLines => Ok(parse_plain_lines(
            source,
            &download_text(&client, source.url)?,
        )),
        FeedFormat::TarGzLines => {
            let body = download_bytes(&client, source.url)?;
            parse_tar_gz_lines(source, &body)
        }
        FeedFormat::ViribackCsv => parse_viriback(source, &download_text(&client, source.url)?),
        FeedFormat::Adguard => Ok(parse_adguard(source, &download_text(&client, source.url)?)),
    }
}

fn parse_urlhaus_json(source: &FeedSource, text: &str) -> FeedResult<Vec<ThreatRecord>> {
    let json: Value = serde_json::from_str(text)?;
    let mut records = Vec::new();
    if let Some(map) = json.as_object() {
        for entries in map.values() {
            for item in entries.as_array().into_iter().flatten() {
                if let Some(url) = item.get("url").and_then(Value::as_str) {
                    records.push(
                        record(source, url, "url")
                            .with_last_seen(item.get("last_online").and_then(Value::as_str))
                            .with_first_seen(item.get("dateadded").and_then(Value::as_str))
                            .with_tags(json_strings(item.get("tags")))
                            .with_source_ref(item.get("urlhaus_link").and_then(Value::as_str)),
                    );
                }
            }
        }
    }
    Ok(records)
}

fn parse_phishunt(source: &FeedSource, text: &str) -> FeedResult<Vec<ThreatRecord>> {
    let json: Value = serde_json::from_str(text)?;
    let mut records = Vec::new();
    for item in json.as_array().into_iter().flatten() {
        if let Some(url) = item.get("url").and_then(Value::as_str) {
            records.push(
                record(source, url, "url")
                    .with_first_seen(item.get("first_seen").and_then(Value::as_str))
                    .with_last_seen(item.get("date").and_then(Value::as_str))
                    .with_tags(optional_strings([
                        item.get("company"),
                        item.get("country"),
                        item.get("asn"),
                    ])),
            );
        }
    }
    Ok(records)
}

fn parse_string_array(source: &FeedSource, text: &str) -> FeedResult<Vec<ThreatRecord>> {
    let json: Value = serde_json::from_str(text)?;
    Ok(json
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|value| record(source, value, source.default_indicator_type))
        .collect())
}

fn parse_metamask(source: &FeedSource, text: &str) -> FeedResult<Vec<ThreatRecord>> {
    let json: Value = serde_json::from_str(text)?;
    let mut records = Vec::new();
    for field in ["blacklist", "fuzzylist"] {
        for value in json
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            records.push(record(source, value, "domain").with_tags(vec![field.to_string()]));
        }
    }
    Ok(records)
}

fn parse_tweetfeed(source: &FeedSource, text: &str) -> FeedResult<Vec<ThreatRecord>> {
    let json: Value = serde_json::from_str(text)?;
    let mut records = Vec::new();
    for item in json.as_array().into_iter().flatten() {
        let Some(value) = item.get("value").and_then(Value::as_str) else {
            continue;
        };
        let kind = item
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or(source.default_indicator_type);
        if !matches!(kind, "url" | "domain" | "ip") {
            continue;
        }
        records.push(
            record(source, value, kind)
                .with_first_seen(item.get("date").and_then(Value::as_str))
                .with_source_ref(item.get("tweet").and_then(Value::as_str))
                .with_tags(json_strings(item.get("tags"))),
        );
    }
    Ok(records)
}

fn parse_spmedia(source: &FeedSource, text: &str) -> FeedResult<Vec<ThreatRecord>> {
    let json: Value = serde_json::from_str(text)?;
    Ok(json
        .get("detected_urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|value| record(source, value, "domain"))
        .collect())
}

fn parse_phishtank(source: &FeedSource, text: &str) -> FeedResult<Vec<ThreatRecord>> {
    let json: Value = serde_json::from_str(text)?;
    let mut records = Vec::new();
    for item in json.as_array().into_iter().flatten() {
        if let Some(url) = item.get("url").and_then(Value::as_str) {
            records.push(
                record(source, url, "url")
                    .with_first_seen(item.get("submission_time").and_then(Value::as_str))
                    .with_last_seen(item.get("verification_time").and_then(Value::as_str))
                    .with_source_ref(item.get("phish_detail_url").and_then(Value::as_str))
                    .with_tags(optional_strings([item.get("target")])),
            );
        }
    }
    Ok(records)
}

fn parse_misp_directory(client: &Client, source: &FeedSource) -> FeedResult<Vec<ThreatRecord>> {
    let html = download_text(client, source.url)?;
    let re = Regex::new(r#"href=[\"']([^\"']+\.json)[\"']"#)?;
    let mut records = Vec::new();
    for cap in re.captures_iter(&html).take(7) {
        let link = cap.get(1).unwrap().as_str();
        let url = if link.starts_with("http") {
            link.to_string()
        } else {
            format!("{}{}", source.url, link)
        };
        let Ok(text) = download_text(client, &url) else {
            continue;
        };
        records.extend(parse_misp_event(source, &text)?);
    }
    Ok(records)
}

fn parse_misp_manifest(client: &Client, source: &FeedSource) -> FeedResult<Vec<ThreatRecord>> {
    let text = download_text(client, source.url)?;
    let json: Value = serde_json::from_str(&text)?;
    let mut records = Vec::new();
    for item in json.as_array().into_iter().flatten().take(50) {
        let Some(uuid) = item
            .get("uuid")
            .or_else(|| item.get("id"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let url = format!(
            "https://raw.githubusercontent.com/infobloxopen/threat-intelligence/main/indicators/misp/{uuid}.json"
        );
        let Ok(event_text) = download_text(client, &url) else {
            continue;
        };
        records.extend(parse_misp_event(source, &event_text)?);
    }
    Ok(records)
}

fn parse_misp_event(source: &FeedSource, text: &str) -> FeedResult<Vec<ThreatRecord>> {
    let json: Value = serde_json::from_str(text)?;
    let Some(attributes) = json.pointer("/Event/Attribute").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for attr in attributes {
        let kind = attr.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(kind, "url" | "domain" | "ip-dst" | "ip-src") {
            continue;
        }
        let Some(value) = attr.get("value").and_then(Value::as_str) else {
            continue;
        };
        let indicator_type = if kind.starts_with("ip-") { "ip" } else { kind };
        records.push(
            record(source, value, indicator_type)
                .with_first_seen(attr.get("first_seen").and_then(Value::as_str))
                .with_source_ref(attr.get("uuid").and_then(Value::as_str))
                .with_confidence(extract_confidence(
                    attr.get("comment").and_then(Value::as_str),
                )),
        );
    }
    Ok(records)
}

fn parse_hosts(source: &FeedSource, text: &str) -> Vec<ThreatRecord> {
    text.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("0.0.0.0 ")
                .or_else(|| line.trim().strip_prefix("127.0.0.1 "))
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| record(source, value, "domain"))
        .collect()
}

fn parse_plain_lines(source: &FeedSource, text: &str) -> Vec<ThreatRecord> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('!'))
        .map(|value| record(source, value, source.default_indicator_type))
        .collect()
}

fn parse_tar_gz_lines(source: &FeedSource, body: &[u8]) -> FeedResult<Vec<ThreatRecord>> {
    let decoder = GzDecoder::new(Cursor::new(body));
    let mut archive = Archive::new(decoder);
    let mut records = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let mut text = String::new();
        entry.read_to_string(&mut text)?;
        records.extend(parse_plain_lines(source, &text));
    }
    Ok(records)
}

fn parse_viriback(source: &FeedSource, text: &str) -> FeedResult<Vec<ThreatRecord>> {
    let mut reader = ReaderBuilder::new().from_reader(text.as_bytes());
    let mut records = Vec::new();
    for row in reader.records() {
        let row = row?;
        let Some(url) = row.get(1) else {
            continue;
        };
        records.push(
            record(source, url, "url")
                .with_tags(
                    row.get(0)
                        .map(|family| vec![family.to_string()])
                        .unwrap_or_default(),
                )
                .with_first_seen(row.get(3)),
        );
    }
    Ok(records)
}

fn parse_adguard(source: &FeedSource, text: &str) -> Vec<ThreatRecord> {
    text.lines()
        .map(str::trim)
        .filter(|line| line.starts_with("||") && line.ends_with('^'))
        .map(|line| line.trim_start_matches("||").trim_end_matches('^'))
        .map(|value| record(source, value, "domain"))
        .collect()
}

fn record(source: &FeedSource, value: &str, indicator_type: &str) -> ThreatRecord {
    let indicator = match indicator_type {
        "url" => normalize_url(value),
        _ => normalize_domain(value),
    };
    ThreatRecord {
        indicator,
        indicator_type: indicator_type.to_string(),
        threat_type: source.threat_type.to_string(),
        source: source.name.to_string(),
        source_ref: None,
        first_seen: None,
        last_seen: None,
        confidence: None,
        tags: Vec::new(),
    }
}

impl ThreatRecord {
    fn with_first_seen(mut self, value: Option<&str>) -> Self {
        self.first_seen = value.map(str::to_string);
        self
    }
    fn with_last_seen(mut self, value: Option<&str>) -> Self {
        self.last_seen = value.map(str::to_string);
        self
    }
    fn with_source_ref(mut self, value: Option<&str>) -> Self {
        self.source_ref = value.map(str::to_string);
        self
    }
    fn with_confidence(mut self, value: Option<u8>) -> Self {
        self.confidence = value;
        self
    }
    fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

fn download_text(client: &Client, url: &str) -> FeedResult<String> {
    Ok(String::from_utf8(download_bytes(client, url)?)?)
}

fn download_bytes(client: &Client, url: &str) -> FeedResult<Vec<u8>> {
    let mut response = client.get(url).send()?.error_for_status()?;
    let mut body = Vec::new();
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        let read = response.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buffer[..read]);
    }
    Ok(body)
}

fn json_strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn optional_strings<'a>(values: impl IntoIterator<Item = Option<&'a Value>>) -> Vec<String> {
    values
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn extract_confidence(comment: Option<&str>) -> Option<u8> {
    let re = Regex::new(r"confidence level:\s*(\d+)%").ok()?;
    let comment = comment?;
    re.captures(comment)
        .and_then(|cap| cap.get(1))
        .and_then(|value| value.as_str().parse().ok())
}
