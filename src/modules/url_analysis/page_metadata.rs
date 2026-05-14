use std::time::Duration;

use regex::Regex;
use reqwest::blocking::ClientBuilder;
use reqwest::redirect::Policy;
use serde_json::Value;

use crate::modules::url_analysis::domain::parse_url_parts;

const BODY_LIMIT: usize = 512 * 1024;

#[derive(Debug, Default)]
pub struct PageMetadata {
    pub final_url: Option<String>,
    pub final_domain: Option<String>,
    pub status: Option<u16>,
    pub title: Option<String>,
    pub og_site_name: Option<String>,
    pub og_title: Option<String>,
    pub application_name: Option<String>,
    pub apple_app_title: Option<String>,
    pub canonical_domain: Option<String>,
    pub manifest_domain: Option<String>,
    pub organization_names: Vec<String>,
    pub organization_domains: Vec<String>,
    pub same_as_domains: Vec<String>,
    pub analytics_ids: Vec<String>,
    pub form_count: usize,
    pub has_password_field: bool,
    pub has_credential_field: bool,
    pub fetch_error: Option<String>,
}

pub fn fetch_page_metadata(url: &str) -> PageMetadata {
    let client = match ClientBuilder::new()
        .timeout(Duration::from_secs(8))
        .redirect(Policy::limited(5))
        .user_agent("Poseidon-page-metadata/0.1")
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return PageMetadata {
                fetch_error: Some(err.to_string()),
                ..PageMetadata::default()
            };
        }
    };

    let response = match client.get(url).send() {
        Ok(response) => response,
        Err(err) => {
            return PageMetadata {
                fetch_error: Some(err.to_string()),
                ..PageMetadata::default()
            };
        }
    };

    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !content_type.is_empty()
        && !content_type.contains("text/html")
        && !content_type.contains("application/xhtml")
    {
        return PageMetadata {
            status: Some(status),
            final_domain: Some(parse_url_parts(&final_url).registrable_domain),
            final_url: Some(final_url),
            fetch_error: Some(format!("unsupported content-type: {content_type}")),
            ..PageMetadata::default()
        };
    }

    let body = match response.text() {
        Ok(body) => body.chars().take(BODY_LIMIT).collect::<String>(),
        Err(err) => {
            return PageMetadata {
                status: Some(status),
                final_url: Some(final_url),
                fetch_error: Some(err.to_string()),
                ..PageMetadata::default()
            };
        }
    };

    let mut metadata = parse_html_metadata(&body);
    metadata.status = Some(status);
    metadata.final_domain = Some(parse_url_parts(&final_url).registrable_domain);
    metadata.final_url = Some(final_url);
    metadata
}

fn parse_html_metadata(body: &str) -> PageMetadata {
    let lower = body.to_ascii_lowercase();
    let mut metadata = PageMetadata {
        title: extract_title(body),
        og_site_name: extract_meta(body, "property", "og:site_name"),
        og_title: extract_meta(body, "property", "og:title"),
        application_name: extract_meta(body, "name", "application-name"),
        apple_app_title: extract_meta(body, "name", "apple-mobile-web-app-title"),
        canonical_domain: extract_link_domain(body, "canonical"),
        manifest_domain: extract_link_domain(body, "manifest"),
        analytics_ids: extract_analytics_ids(body),
        form_count: lower.matches("<form").count(),
        has_password_field: lower.contains("type=\"password\"")
            || lower.contains("type='password'"),
        has_credential_field: lower.contains("otp")
            || lower.contains("one-time")
            || lower.contains("credit card")
            || lower.contains("cvv")
            || lower.contains("seed phrase"),
        ..PageMetadata::default()
    };
    parse_jsonld(body, &mut metadata);
    dedup(&mut metadata.organization_names);
    dedup(&mut metadata.organization_domains);
    dedup(&mut metadata.same_as_domains);
    dedup(&mut metadata.analytics_ids);
    metadata
}

fn extract_title(body: &str) -> Option<String> {
    let re = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").ok()?;
    re.captures(body)
        .and_then(|caps| clean_text(caps.get(1)?.as_str()))
}

fn extract_meta(body: &str, attr: &str, key: &str) -> Option<String> {
    let pattern = format!(
        r#"(?is)<meta[^>]+{}=["']{}["'][^>]+content=["']([^"']+)["'][^>]*>|<meta[^>]+content=["']([^"']+)["'][^>]+{}=["']{}["'][^>]*>"#,
        regex::escape(attr),
        regex::escape(key),
        regex::escape(attr),
        regex::escape(key)
    );
    let re = Regex::new(&pattern).ok()?;
    re.captures(body).and_then(|caps| {
        caps.get(1)
            .or_else(|| caps.get(2))
            .and_then(|value| clean_text(value.as_str()))
    })
}

fn extract_link_domain(body: &str, rel: &str) -> Option<String> {
    let pattern = format!(
        r#"(?is)<link[^>]+rel=["'][^"']*{}[^"']*["'][^>]+href=["']([^"']+)["'][^>]*>"#,
        regex::escape(rel)
    );
    let re = Regex::new(&pattern).ok()?;
    let href = re.captures(body)?.get(1)?.as_str();
    domain_from_url(href)
}

fn parse_jsonld(body: &str, metadata: &mut PageMetadata) {
    let Ok(re) =
        Regex::new(r#"(?is)<script[^>]+type=["']application/ld\+json["'][^>]*>(.*?)</script>"#)
    else {
        return;
    };
    for caps in re.captures_iter(body) {
        let Some(raw) = caps.get(1).map(|value| value.as_str().trim()) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        parse_jsonld_value(&value, metadata);
    }
}

fn parse_jsonld_value(value: &Value, metadata: &mut PageMetadata) {
    if let Some(items) = value.as_array() {
        for item in items {
            parse_jsonld_value(item, metadata);
        }
        return;
    }
    if let Some(graph) = value.get("@graph") {
        parse_jsonld_value(graph, metadata);
    }
    let type_text = value
        .get("@type")
        .map(|value| value.to_string().to_ascii_lowercase())
        .unwrap_or_default();
    if type_text.contains("organization")
        || type_text.contains("corporation")
        || type_text.contains("brand")
    {
        if let Some(name) = value
            .get("name")
            .and_then(Value::as_str)
            .and_then(clean_text)
        {
            metadata.organization_names.push(name);
        }
        if let Some(url) = value
            .get("url")
            .and_then(Value::as_str)
            .and_then(domain_from_url)
        {
            metadata.organization_domains.push(url);
        }
        if let Some(same_as) = value.get("sameAs") {
            collect_same_as(same_as, metadata);
        }
    }
}

fn collect_same_as(value: &Value, metadata: &mut PageMetadata) {
    if let Some(url) = value.as_str().and_then(domain_from_url) {
        metadata.same_as_domains.push(url);
    }
    if let Some(items) = value.as_array() {
        for item in items {
            collect_same_as(item, metadata);
        }
    }
}

fn extract_analytics_ids(body: &str) -> Vec<String> {
    let patterns = [
        r"GTM-[A-Z0-9]+",
        r"G-[A-Z0-9]+",
        r"UA-\d+-\d+",
        r#"clarity\(['\"]set['\"],\s*['\"]([a-z0-9]+)['\"]"#,
    ];
    let mut ids = Vec::new();
    for pattern in patterns {
        let Ok(re) = Regex::new(pattern) else {
            continue;
        };
        for caps in re.captures_iter(body) {
            if let Some(value) = caps.get(1).or_else(|| caps.get(0)) {
                ids.push(value.as_str().to_string());
            }
        }
    }
    ids
}

fn clean_text(value: &str) -> Option<String> {
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let value = html_unescape(&value)
        .trim()
        .chars()
        .take(120)
        .collect::<String>();
    (!value.is_empty()).then_some(value)
}

fn html_unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn domain_from_url(value: &str) -> Option<String> {
    if value.starts_with('/') || value.starts_with('#') || value.starts_with("mailto:") {
        return None;
    }
    Some(parse_url_parts(value).registrable_domain).filter(|domain| !domain.is_empty())
}

fn dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}
