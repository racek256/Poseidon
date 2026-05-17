use std::time::Duration;

use reqwest::blocking::Client;
use serde_json::Value;

use crate::modules::tui::bridge;

const USER_AGENT: &str = "Poseidon/0.1.0";

#[derive(Debug)]
pub struct RegistryChecker {
    http_client: Client,
}

impl RegistryChecker {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(USER_AGENT)
            .build()
            .expect("failed to create HTTP client for registry checker");
        Self {
            http_client: client,
        }
    }

    pub fn check_package(&self, name: &str, version: &str, ecosystem: &str) -> Vec<String> {
        let mut warnings = Vec::new();

        match ecosystem.to_lowercase().as_str() {
            "pypi" | "pip" | "pyproject" => {
                warnings.extend(self.check_pypi(name, version));
            }
            "npm" | "nodejs" | "yarn" | "pnpm" => {
                warnings.extend(self.check_npm(name, version));
            }
            "crates.io" | "crates" | "cargo" | "rust" => {
                warnings.extend(self.check_cratesio(name, version));
            }
            _ => {
                warnings.extend(self.check_generic_registry(name, version, ecosystem));
            }
        }

        warnings
    }

    fn check_pypi(&self, name: &str, version: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let url = format!("https://pypi.org/pypi/{}/{}/json", name, version);

        let body = match self.http_client.get(&url).send() {
            Ok(response) => match response.error_for_status() {
                Ok(resp) => resp.text(),
                Err(e) => {
                    bridge::elog(&format!("PyPI error for {}/{}: {}", name, version, e));
                    return warnings;
                }
            },
            Err(e) => {
                bridge::elog(&format!(
                    "PyPI request failed for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        let body = match body {
            Ok(text) => text,
            Err(e) => {
                bridge::elog(&format!("PyPI read error for {}/{}: {}", name, version, e));
                return warnings;
            }
        };

        let json: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                bridge::elog(&format!("PyPI parse error for {}/{}: {}", name, version, e));
                return warnings;
            }
        };

        if let Some(upload_time) = json.pointer("/upload_time") {
            if let Some(time_str) = upload_time.as_str() {
                if let Ok(upload_date) = chrono::DateTime::parse_from_rfc3339(time_str) {
                    let days_since = chrono::Utc::now()
                        .signed_duration_since(upload_date)
                        .num_days();
                    if days_since < 7 {
                        warnings.push(format!(
                            "PyPI package {}/{} is very new (uploaded {} days ago)",
                            name, version, days_since
                        ));
                    }
                }
            }
        }

        if let Some(vulns) = json.pointer("/vulnerabilities") {
            if let Some(arr) = vulns.as_array() {
                if !arr.is_empty() {
                    warnings.push(format!(
                        "PyPI package {}/{} has {} known vulnerabilities",
                        name,
                        version,
                        arr.len()
                    ));
                }
            }
        }

        if let Some(yanked) = json.pointer("/yanked") {
            if yanked.as_bool() == Some(true) {
                warnings.push(format!(
                    "PyPI package {}/{} has been YANKED from the registry",
                    name, version
                ));
            }
        }

        warnings
    }

    fn check_npm(&self, name: &str, version: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let url = format!("https://registry.npmjs.org/{}", name);

        let body = match self.http_client.get(&url).send() {
            Ok(response) => match response.error_for_status() {
                Ok(resp) => resp.text(),
                Err(e) => {
                    bridge::elog(&format!(
                        "npm registry error for {}/{}: {}",
                        name, version, e
                    ));
                    return warnings;
                }
            },
            Err(e) => {
                bridge::elog(&format!(
                    "npm registry request failed for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        let body = match body {
            Ok(text) => text,
            Err(e) => {
                bridge::elog(&format!(
                    "npm registry read error for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        let json: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                bridge::elog(&format!(
                    "npm registry parse error for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        // Check if the version exists in the versions map
        let version_exists = json.get("versions").and_then(|v| v.get(version)).is_some();

        if !version_exists {
            warnings.push(format!(
                "npm package {} version {} was not found in the registry",
                name, version
            ));
            return warnings;
        }

        if let Some(time_obj) = json.get("time") {
            if let Some(published) = time_obj.get("published") {
                if let Some(date_str) = published.as_str() {
                    if let Ok(publish_date) = chrono::DateTime::parse_from_rfc3339(date_str) {
                        let days_since = chrono::Utc::now()
                            .signed_duration_since(publish_date)
                            .num_days();
                        if days_since < 7 {
                            warnings.push(format!(
                                "npm package {}/{} is very new (published {} days ago)",
                                name, version, days_since
                            ));
                        }
                    }
                }
            }
        }

        // npm deprecated is per-version: versions.{version}.deprecated
        if let Some(deprecated) = json["versions"][version].get("deprecated") {
            if let Some(msg) = deprecated.as_str() {
                if !msg.is_empty() {
                    warnings.push(format!(
                        "npm package {}/{} is deprecated: {}",
                        name, version, msg
                    ));
                }
            }
        }

        warnings
    }

    fn check_cratesio(&self, name: &str, version: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let url = format!("https://crates.io/api/v1/crates/{}/{}", name, version);

        let body = match self.http_client.get(&url).send() {
            Ok(response) => match response.error_for_status() {
                Ok(resp) => resp.text(),
                Err(e) => {
                    bridge::elog(&format!("crates.io error for {}/{}: {}", name, version, e));
                    return warnings;
                }
            },
            Err(e) => {
                bridge::elog(&format!(
                    "crates.io request failed for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        let body = match body {
            Ok(text) => text,
            Err(e) => {
                bridge::elog(&format!(
                    "crates.io read error for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        let json: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                bridge::elog(&format!(
                    "crates.io parse error for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        if let Some(updated_at) = json.pointer("/crate/updated_at") {
            if let Some(date_str) = updated_at.as_str() {
                if let Ok(update_date) = chrono::DateTime::parse_from_rfc3339(date_str) {
                    let days_since = chrono::Utc::now()
                        .signed_duration_since(update_date)
                        .num_days();
                    if days_since < 7 {
                        warnings.push(format!(
                            "crates.io crate {}/{} updated very recently ({} days ago)",
                            name, version, days_since
                        ));
                    }
                }
            }
        }

        if let Some(version_obj) = json.get("version") {
            if let Some(yanked) = version_obj.get("yanked") {
                if yanked.as_bool() == Some(true) {
                    warnings.push(format!(
                        "crates.io version {}/{} has been YANKED",
                        name, version
                    ));
                }
            }
        }

        warnings
    }

    fn check_rubygems(&self, name: &str, version: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let url = format!("https://rubygems.org/api/v1/gems/{}.json", name);

        let body = match self.http_client.get(&url).send() {
            Ok(response) => {
                match response.error_for_status() {
                    Ok(resp) => resp.text(),
                    Err(e) => {
                        bridge::elog(&format!("RubyGems error for {}/{}: {}", name, version, e));
                        return warnings;
                    }
                }
            }
            Err(e) => {
                bridge::elog(&format!(
                    "RubyGems request failed for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        let body = match body {
            Ok(text) => text,
            Err(e) => {
                bridge::elog(&format!("RubyGems read error for {}/{}: {}", name, version, e));
                return warnings;
            }
        };

        let json: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                bridge::elog(&format!(
                    "RubyGems parse error for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        if let Some(created_at) = json.get("created_at").or(json.pointer("/gem/raw_created_at")) {
            if let Some(date_str) = created_at.as_str() {
                if let Ok(created_date) = chrono::DateTime::parse_from_rfc3339(date_str) {
                    let days_since =
                        chrono::Utc::now().signed_duration_since(created_date).num_days();
                    if days_since < 7 {
                        warnings.push(format!(
                            "RubyGems gem {}/{} is very new (created {} days ago)",
                            name, version, days_since
                        ));
                    }
                }
            }
        }

        // Check if version matches (RubyGems returns latest version in info, not specific version)
        if let Some(info_version) = json.get("version").and_then(|v| v.as_str()) {
            if info_version != version {
                warnings.push(format!(
                    "RubyGems gem {}/{} requested but latest is {}",
                    name, version, info_version
                ));
            }
        }

        warnings
    }

    fn check_packagist(&self, name: &str, version: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        let url = format!("https://packagist.org/packages/{}.json", name);

        let body = match self.http_client.get(&url).send() {
            Ok(response) => {
                match response.error_for_status() {
                    Ok(resp) => resp.text(),
                    Err(e) => {
                        bridge::elog(&format!("Packagist error for {}/{}: {}", name, version, e));
                        return warnings;
                    }
                }
            }
            Err(e) => {
                bridge::elog(&format!(
                    "Packagist request failed for {}/{}: {}",
                    name, version, e
                ));
                return warnings;
            }
        };

        let body = match body {
            Ok(text) => text,
            Err(e) => {
                bridge::elog(&format!("Packagist read error for {}/{}: {}", name, version, e));
                return warnings;
            }
        };

        let json: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                bridge::elog(&format!("Packagist parse error for {}/{}: {}", name, version, e));
                return warnings;
            }
        };

        // Packagist JSON: { "package": { "name": "...", "description": "...", "versions": { ... } } }
        let package = match json.get("package") {
            Some(p) => p,
            None => {
                warnings.push(format!(
                    "Packagist package {}/{} not found in registry",
                    name, version
                ));
                return warnings;
            }
        };

        // Check if specific version exists
        if let Some(versions) = package.get("versions").and_then(|v| v.as_object()) {
            if !versions.contains_key(version) {
                warnings.push(format!(
                    "Packagist package {}/{} version not found in registry",
                    name, version
                ));
            }

            // Check for recent publish time
            if let Some(version_info) = versions.get(version).or_else(|| versions.values().next()) {
                if let Some(time_obj) = version_info.get("time") {
                    if let Some(date_str) = time_obj.as_str() {
                        if let Ok(publish_date) = chrono::DateTime::parse_from_rfc3339(date_str) {
                            let days_since =
                                chrono::Utc::now().signed_duration_since(publish_date).num_days();
                            if days_since < 7 {
                                warnings.push(format!(
                                    "Packagist package {}/{} is very new (published {} days ago)",
                                    name, version, days_since
                                ));
                            }
                        }
                    }
                }
            }
        }

        warnings
    }

    fn check_go(&self, name: &str, version: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        // Go module names contain slashes, pass them as-is in the URL path
        let url = format!("https://proxy.golang.org/{}/@v/{}.info", name, version);

        let body = match self.http_client.get(&url).send() {
            Ok(response) => {
                match response.error_for_status() {
                    Ok(resp) => resp.text(),
                    Err(e) => {
                        bridge::elog(&format!("Go registry error for {}/{}: {}", name, version, e));
                        return warnings;
                    }
                }
            }
            Err(e) => {
                bridge::elog(&format!("Go registry request failed for {}/{}: {}", name, version, e));
                return warnings;
            }
        };

        let body = match body {
            Ok(text) => text,
            Err(e) => {
                bridge::elog(&format!("Go registry read error for {}/{}: {}", name, version, e));
                return warnings;
            }
        };

        let json: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => {
                bridge::elog(&format!("Go registry parse error for {}/{}: {}", name, version, e));
                return warnings;
            }
        };

        // Go proxy JSON: { "Name": "v1.0.0", "Version": "v1.0.0", "Time": "2023-01-01T00:00:00Z" }
        if let Some(time_val) = json.get("Time") {
            if let Some(date_str) = time_val.as_str() {
                if let Ok(publish_date) = chrono::DateTime::parse_from_rfc3339(date_str) {
                    let days_since =
                        chrono::Utc::now().signed_duration_since(publish_date).num_days();
                    if days_since < 7 {
                        warnings.push(format!(
                            "Go module {}/{} is very new (published {} days ago)",
                            name, version, days_since
                        ));
                    }
                }
            }
        }

        warnings
    }

    fn check_generic_registry(&self, _name: &str, _version: &str, _ecosystem: &str) -> Vec<String> {
        Vec::new()
    }
}

impl Default for RegistryChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_checker_creation() {
        let checker = RegistryChecker::new();
        assert!(format!("{:?}", checker).contains("RegistryChecker"));
    }

    #[test]
    fn test_check_pypi_response_parsing() {
        let json_str = r#"{
            "info": {
                "name": "requests",
                "version": "2.28.0"
            },
            "upload_time": "2022-06-29T10:00:00Z",
            "vulnerabilities": [],
            "yanked": false
        }"#;
        let json: Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            json.pointer("/upload_time").and_then(|v| v.as_str()),
            Some("2022-06-29T10:00:00Z")
        );
    }

    #[test]
    fn test_check_npm_response_parsing() {
        let json_str = r#"{
            "name": "lodash",
            "versions": {
                "4.17.21": {
                    "name": "lodash",
                    "version": "4.17.21"
                }
            },
            "time": {
                "published": "2020-01-15T09:00:00Z"
            }
        }"#;
        let json: Value = serde_json::from_str(json_str).unwrap();
        assert!(
            json.get("versions")
                .and_then(|v| v.get("4.17.21"))
                .is_some()
        );
        assert_eq!(
            json.pointer("/time/published").and_then(|v| v.as_str()),
            Some("2020-01-15T09:00:00Z")
        );
    }

    #[test]
    fn test_check_cratesio_response_parsing() {
        let json_str = r#"{
            "crate": {
                "name": "serde",
                "updated_at": "2023-01-01T00:00:00Z"
            },
            "version": {
                "num": "1.0.0",
                "yanked": false
            }
        }"#;
        let json: Value = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            json.pointer("/version/yanked").and_then(|v| v.as_bool()),
            Some(false)
        );
    }
}
