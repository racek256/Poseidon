use crate::modules::threat_intel::normalize_domain;

#[derive(Debug)]
pub struct DomainParts {
    pub host: String,
    pub registrable_domain: String,
    pub subdomain: Option<String>,
    pub path_query: String,
}

pub fn parse_url_parts(url: &str) -> DomainParts {
    let trimmed = url.trim().trim_end_matches(&['.', ',', ';', ')', ']'][..]);
    let without_scheme = trimmed
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let (host_port, path_query) = without_scheme
        .split_once('/')
        .map(|(host, path)| (host, format!("/{path}")))
        .unwrap_or((without_scheme, String::new()));
    let host = normalize_domain(host_port);
    let registrable_domain = registrable_domain(&host);
    let subdomain = host
        .strip_suffix(&format!(".{registrable_domain}"))
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    DomainParts {
        host,
        registrable_domain,
        subdomain,
        path_query: path_query.to_ascii_lowercase(),
    }
}

fn registrable_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
    if labels.len() <= 2 {
        return host.to_string();
    }

    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if TWO_PART_PUBLIC_SUFFIXES.contains(&last_two.as_str()) && labels.len() >= 3 {
        return format!(
            "{}.{}.{}",
            labels[labels.len() - 3],
            labels[labels.len() - 2],
            labels[labels.len() - 1]
        );
    }

    last_two
}

const TWO_PART_PUBLIC_SUFFIXES: &[&str] = &["co.uk", "com.au", "co.za", "co.jp", "com.br"];
