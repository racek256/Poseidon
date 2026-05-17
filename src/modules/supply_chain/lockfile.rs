//! Lockfile detection and parsing for supply chain scanning.
//!
//! Supports: Cargo.lock, package-lock.json, yarn.lock, pnpm-lock.yaml,
//! poetry.lock, Pipfile.lock, requirements.txt, go.sum, Gemfile.lock,
//! composer.lock, pom.xml, maven-lockfile.json, gradle.lockfile,
//! packages.lock.json, pubspec.lock, mix.lock

use serde::Deserialize;

/// OSV ecosystem identifier for each package ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    CratesIo,  // Rust
    PyPI,      // Python
    Npm,       // JavaScript/TypeScript
    Go,        // Go
    RubyGems,  // Ruby
    Packagist, // PHP
    Maven,     // Java
    NuGet,     // .NET
    Pub,       // Dart
    Hex,       // Elixir
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::CratesIo => "crates.io",
            Ecosystem::PyPI => "PyPI",
            Ecosystem::Npm => "npm",
            Ecosystem::Go => "Go",
            Ecosystem::RubyGems => "RubyGems",
            Ecosystem::Packagist => "Packagist",
            Ecosystem::Maven => "Maven",
            Ecosystem::NuGet => "NuGet",
            Ecosystem::Pub => "Pub",
            Ecosystem::Hex => "Hex",
        }
    }
}

/// Lockfile type detected by filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockfileType {
    CargoLock,         // Rust
    PackageLockJson,   // npm
    YarnLock,          // Yarn
    PnpmLockYaml,      // pnpm
    PoetryLock,        // Poetry
    PipfileLock,       // Pipenv
    RequirementsTxt,   // pip-tools
    GoSum,             // Go modules
    GemfileLock,       // Ruby
    ComposerLock,      // PHP
    PomXml,            // Maven (pom.xml)
    MavenLockfileJson, // Maven (maven-lockfile.json)
    GradleLockfile,    // Gradle
    PackagesLockJson,  // NuGet
    PubSpecLock,       // Dart
    MixLock,           // Elixir
}

impl LockfileType {
    pub fn ecosystem(&self) -> Ecosystem {
        match self {
            LockfileType::CargoLock => Ecosystem::CratesIo,
            LockfileType::PackageLockJson | LockfileType::YarnLock | LockfileType::PnpmLockYaml => {
                Ecosystem::Npm
            }
            LockfileType::PoetryLock
            | LockfileType::PipfileLock
            | LockfileType::RequirementsTxt => Ecosystem::PyPI,
            LockfileType::GoSum => Ecosystem::Go,
            LockfileType::GemfileLock => Ecosystem::RubyGems,
            LockfileType::ComposerLock => Ecosystem::Packagist,
            LockfileType::PomXml
            | LockfileType::MavenLockfileJson
            | LockfileType::GradleLockfile => Ecosystem::Maven,
            LockfileType::PackagesLockJson => Ecosystem::NuGet,
            LockfileType::PubSpecLock => Ecosystem::Pub,
            LockfileType::MixLock => Ecosystem::Hex,
        }
    }
}

/// A package extracted from a lockfile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
}

impl Package {
    pub fn new(name: String, version: String, ecosystem: Ecosystem) -> Self {
        Self {
            name,
            version,
            ecosystem,
        }
    }
}

/// Detect lockfile type from filename.
///
/// Returns `Some(LockfileType)` if the filename matches a known lockfile,
/// or `None` if the filename is not recognized.
pub fn detect_lockfile_type(filename: &str) -> Option<LockfileType> {
    match filename {
        "Cargo.lock" => Some(LockfileType::CargoLock),
        "package-lock.json" => Some(LockfileType::PackageLockJson),
        "yarn.lock" => Some(LockfileType::YarnLock),
        "pnpm-lock.yaml" | "pnpm-lock.yml" => Some(LockfileType::PnpmLockYaml),
        "poetry.lock" => Some(LockfileType::PoetryLock),
        "Pipfile.lock" => Some(LockfileType::PipfileLock),
        "requirements.txt" => Some(LockfileType::RequirementsTxt),
        "go.sum" => Some(LockfileType::GoSum),
        "Gemfile.lock" => Some(LockfileType::GemfileLock),
        "composer.lock" => Some(LockfileType::ComposerLock),
        "pom.xml" => Some(LockfileType::PomXml),
        "maven-lockfile.json" => Some(LockfileType::MavenLockfileJson),
        "gradle.lockfile" => Some(LockfileType::GradleLockfile),
        "packages.lock.json" => Some(LockfileType::PackagesLockJson),
        "pubspec.lock" => Some(LockfileType::PubSpecLock),
        "mix.lock" => Some(LockfileType::MixLock),
        _ => None,
    }
}

/// Parse a lockfile and return the list of packages.
///
/// The `filename` is used to determine the lockfile format.
/// The `content` is the raw text content of the lockfile.
///
/// # Errors
///
/// Returns an error string if parsing fails.
pub fn parse_lockfile(filename: &str, content: &str) -> Result<Vec<Package>, String> {
    let lockfile_type = detect_lockfile_type(filename)
        .ok_or_else(|| format!("unknown lockfile type: {}", filename))?;

    match lockfile_type {
        LockfileType::CargoLock => parse_cargo_lock(content),
        LockfileType::PackageLockJson => parse_package_lock_json(content),
        LockfileType::YarnLock => parse_yarn_lock(content),
        LockfileType::PnpmLockYaml => parse_pnpm_lock_yaml(content),
        LockfileType::PoetryLock => parse_poetry_lock(content),
        LockfileType::PipfileLock => parse_pipfile_lock(content),
        LockfileType::RequirementsTxt => parse_requirements_txt(content),
        LockfileType::GoSum => parse_go_sum(content),
        LockfileType::GemfileLock => parse_gemfile_lock(content),
        LockfileType::ComposerLock => parse_composer_lock(content),
        LockfileType::PomXml => parse_pom_xml(content),
        LockfileType::MavenLockfileJson => parse_maven_lockfile_json(content),
        LockfileType::GradleLockfile => parse_gradle_lockfile(content),
        LockfileType::PackagesLockJson => parse_packages_lock_json(content),
        LockfileType::PubSpecLock => parse_pubspec_lock(content),
        LockfileType::MixLock => parse_mix_lock(content),
    }
}

// ---------------------------------------------------------------------------
// Cargo.lock (Rust)
// ---------------------------------------------------------------------------

/// Parse `Cargo.lock` (TOML-like format).
///
/// Looks for `[package]` sections with `name = "..."` and `version = "..."`.
fn parse_cargo_lock(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::CratesIo;
    let mut packages = Vec::new();
    let mut in_package = false;
    let mut name = String::new();
    let mut version = String::new();

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("[[package]]") {
            // Save previous package before starting new one
            if in_package && !name.is_empty() && !version.is_empty() {
                packages.push(Package::new(name.clone(), version.clone(), ecosystem));
            }
            in_package = true;
            name.clear();
            version.clear();
        } else if line.starts_with('[') && line.ends_with(']') && in_package {
            // End of this package block
            if !name.is_empty() && !version.is_empty() {
                packages.push(Package::new(name.clone(), version.clone(), ecosystem));
            }
            in_package = false;
            name.clear();
            version.clear();
        } else if in_package {
            if let Some(val) = line.strip_prefix("name = ") {
                name = parse_toml_string(val);
            } else if let Some(val) = line.strip_prefix("version = ") {
                version = parse_toml_string(val);
            }
        }
    }

    // Handle last package in file
    if in_package && !name.is_empty() && !version.is_empty() {
        packages.push(Package::new(name, version, ecosystem));
    }

    Ok(packages)
}

/// Parse a TOML string value (strips quotes).
fn parse_toml_string(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// package-lock.json (npm)
// ---------------------------------------------------------------------------

fn parse_package_lock_json(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::Npm;
    let mut packages = Vec::new();
    let mut in_packages = false;
    let mut current_path = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("\"packages\":") {
            in_packages = true;
            continue;
        }

        if !in_packages {
            continue;
        }

        if trimmed == "}" || trimmed == "}," {
            if current_path.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
                in_packages = false;
            }
            continue;
        }

        if trimmed.starts_with("\"node_modules/")
            && (trimmed.ends_with("\":") || trimmed.ends_with("\": {"))
        {
            if let Some(end_quote) = trimmed[1..].find('\"') {
                current_path = trimmed[1..1 + end_quote].to_string();
            }
            continue;
        }

        if !current_path.is_empty() && trimmed.starts_with("\"version\":") {
            let version_raw = trimmed.strip_prefix("\"version\":").unwrap_or("").trim();
            let version = version_raw.trim_matches(|c| c == '"' || c == ',');

            if !version.is_empty() {
                let rest = current_path
                    .strip_prefix("node_modules/")
                    .unwrap_or(&current_path);
                let name = if rest.contains('/') {
                    rest.split('/').next().unwrap_or(rest)
                } else {
                    rest
                };
                if !name.is_empty() {
                    packages.push(Package::new(
                        name.to_string(),
                        version.to_string(),
                        ecosystem,
                    ));
                }
            }
            current_path.clear();
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// yarn.lock (Yarn)
// ---------------------------------------------------------------------------

/// Parse `yarn.lock` (custom Yarn format: `name@version:`).
fn parse_yarn_lock(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::Npm;
    let mut packages = Vec::new();
    let mut in_block = false;
    let mut current_name = String::new();
    let mut current_version = String::new();

    for line in content.lines() {
        let line = line.trim();

        // Yarn format: `package-name@version:`
        if let Some(at_pos) = line.find('@') {
            let before_at = line[..at_pos].trim();
            let rest = &line[at_pos + 1..];
            if let Some(colon_pos) = rest.find(':') {
                let version = rest[..colon_pos].trim();
                if !before_at.is_empty() && !version.is_empty() {
                    // Avoid duplicates
                    if current_name != before_at.to_string()
                        || current_version != version.to_string()
                    {
                        packages.push(Package::new(
                            before_at.to_string(),
                            version.to_string(),
                            ecosystem,
                        ));
                    }
                    current_name = before_at.to_string();
                    current_version = version.to_string();
                    in_block = true;
                }
            }
        } else if line.is_empty() || line.starts_with('#') {
            in_block = false;
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// pnpm-lock.yaml (pnpm)
// ---------------------------------------------------------------------------

/// Parse `pnpm-lock.yaml` (YAML-like, `packages: { name: { version: ... } }`).
fn parse_pnpm_lock_yaml(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::Npm;
    let mut packages = Vec::new();
    let mut in_packages = false;
    let mut current_name = String::new();

    for line in content.lines() {
        let line = line.trim();

        if line == "packages:" {
            in_packages = true;
            continue;
        }

        if in_packages {
            if let Some(at_pos) = line.find('@') {
                if at_pos > 0 {
                    current_name = line[..at_pos].trim_start_matches('/').to_string();
                }
            }

            // Look for version: or version:
            if line.starts_with("version:") {
                let version = line.strip_prefix("version:").unwrap_or("").trim();
                if !current_name.is_empty() && !version.is_empty() {
                    packages.push(Package::new(
                        current_name.clone(),
                        version.to_string(),
                        ecosystem,
                    ));
                }
                current_name.clear();
            } else if line.starts_with("specification:") || line.starts_with("resolution:") {
                current_name.clear();
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// poetry.lock (Poetry)
// ---------------------------------------------------------------------------

/// Parse `poetry.lock` (TOML-like, `[[package]]` with `name = "..."` and `version = "..."`).
fn parse_poetry_lock(content: &str) -> Result<Vec<Package>, String> {
    parse_toml_like_lockfile(content, Ecosystem::PyPI)
}

// ---------------------------------------------------------------------------
// Pipfile.lock (Pipenv)
// ---------------------------------------------------------------------------

fn parse_pipfile_lock(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::PyPI;
    let mut packages = Vec::new();
    let mut in_default = false;
    let mut current_name = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("\"default\":") || trimmed.starts_with("default:") {
            in_default = true;
            continue;
        }

        if !in_default {
            continue;
        }

        if trimmed == "}" || trimmed == "}," {
            if current_name.is_empty() && !line.starts_with(' ') && !line.starts_with('\t') {
                in_default = false;
            }
            continue;
        }

        if (trimmed.starts_with('"') || trimmed.starts_with('\''))
            && (trimmed.ends_with("\":")
                || trimmed.ends_with("\": {")
                || trimmed.ends_with("':")
                || trimmed.ends_with("': {"))
        {
            let quote = if trimmed.starts_with('"') { '"' } else { '\'' };
            if let Some(end_quote) = trimmed[1..].find(quote) {
                current_name = trimmed[1..1 + end_quote].to_string();
            }
            continue;
        }

        if !current_name.is_empty() && trimmed.starts_with("\"version\":") {
            let version_raw = trimmed.strip_prefix("\"version\":").unwrap_or("").trim();
            let version = version_raw.trim_matches('"').trim_matches(',');

            if !version.is_empty() && !current_name.is_empty() {
                packages.push(Package::new(
                    current_name.clone(),
                    version.to_string(),
                    ecosystem,
                ));
            }
            current_name.clear();
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// requirements.txt (pip-tools)
// ---------------------------------------------------------------------------

/// Parse `requirements.txt` (lines like `package==version` or `package>=version`).
fn parse_requirements_txt(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::PyPI;
    let mut packages = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Skip flags and options
        if line.starts_with('-') || line.starts_with('\\') {
            continue;
        }

        // Parse package==version or package>=version etc.
        if let Some(eq_pos) = line.find("==") {
            let name = line[..eq_pos].trim();
            let version = line[eq_pos + 2..].trim();
            if !name.is_empty() && !version.is_empty() {
                packages.push(Package::new(
                    name.to_string(),
                    version.to_string(),
                    ecosystem,
                ));
            }
        } else if let Some((name, version)) = parse_requirement_line(line) {
            if !name.is_empty() && !version.is_empty() {
                packages.push(Package::new(name, version, ecosystem));
            }
        }
    }

    Ok(packages)
}

/// Parse a requirement line with various comparison operators.
fn parse_requirement_line(line: &str) -> Option<(String, String)> {
    for op in &[
        "~=", ">=", "<=", "!=", "=== ", ">= ", "<= ", "== ", "!= ", "> ", "< ",
    ] {
        if let Some(pos) = line.find(*op) {
            let name = line[..pos].trim();
            let version = line[pos + op.len()..].trim();
            if !name.is_empty() && !version.is_empty() {
                return Some((name.to_string(), version.to_string()));
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// go.sum (Go)
// ---------------------------------------------------------------------------

/// Parse `go.sum` (lines like `name version`).
fn parse_go_sum(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::Go;
    let mut packages = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let name = parts[0];
            let version = parts[1];
            // go.sum entries are often duplicated; deduplicate by (name, version)
            let key = format!("{}@{}", name, version);
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
            packages.push(Package::new(
                name.to_string(),
                version.to_string(),
                ecosystem,
            ));
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// Gemfile.lock (Ruby)
// ---------------------------------------------------------------------------

/// Parse `Gemfile.lock` (GEM section, `name (version)`).
fn parse_gemfile_lock(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::RubyGems;
    let mut packages = Vec::new();
    let mut in_gem = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "GEM" {
            in_gem = true;
            continue;
        }

        if in_gem {
            if trimmed.is_empty() {
                in_gem = false;
                continue;
            }

            // GEM entries are indented and look like: `    foo (1.2.3)`
            if line.starts_with("    ") && !line.starts_with("        ") {
                if let Some(paren_pos) = trimmed.find(" (") {
                    let name = trimmed[..paren_pos].trim();
                    let rest = &trimmed[paren_pos + 2..];
                    if let Some(end_paren) = rest.find(')') {
                        let version = &rest[..end_paren];
                        if !name.is_empty() && !version.is_empty() {
                            packages.push(Package::new(
                                name.to_string(),
                                version.to_string(),
                                ecosystem,
                            ));
                        }
                    }
                }
            } else if trimmed == "PLATFORMS" || trimmed == "DEPENDENCIES" {
                in_gem = false;
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// composer.lock (PHP)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ComposerLock {
    packages: Option<Vec<ComposerPackage>>,
}

#[derive(Deserialize)]
struct ComposerPackage {
    name: Option<String>,
    version: Option<String>,
}

fn parse_composer_lock(content: &str) -> Result<Vec<Package>, String> {
    let lockfile: ComposerLock =
        serde_json::from_str(content).map_err(|e| format!("JSON parse error: {}", e))?;

    let ecosystem = Ecosystem::Packagist;
    let mut packages = Vec::new();

    if let Some(pkgs) = lockfile.packages {
        for pkg in pkgs {
            if let (Some(name), Some(version)) = (pkg.name, pkg.version) {
                if !name.is_empty() && !version.is_empty() {
                    packages.push(Package::new(name, version, ecosystem));
                }
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// pom.xml (Maven)
// ---------------------------------------------------------------------------

/// Parse `pom.xml` (XML, extract `<dependency>` entries with `<artifactId>` and `<version>`).
fn parse_pom_xml(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::Maven;
    let mut packages = Vec::new();

    let mut in_dependency = false;
    let mut current_artifact = String::new();
    let mut current_version = String::new();

    let mut i = 0;
    let bytes = content.as_bytes();

    while i < bytes.len() {
        // Simple tag detection
        if bytes[i] == b'<' {
            // Check for <dependency>
            if content[i..].starts_with("<dependency>") {
                in_dependency = true;
                current_artifact.clear();
                current_version.clear();
                i += "<dependency>".len();
                continue;
            } else if content[i..].starts_with("</dependency>") {
                if in_dependency && !current_artifact.is_empty() && !current_version.is_empty() {
                    packages.push(Package::new(
                        current_artifact.clone(),
                        current_version.clone(),
                        ecosystem,
                    ));
                }
                in_dependency = false;
                i += "</dependency>".len();
                continue;
            } else if in_dependency {
                if content[i..].starts_with("<artifactId>") {
                    if let Some(end) = content[i..].find("</artifactId>") {
                        let tag_content = &content[i + "<artifactId>".len()..i + end];
                        current_artifact = tag_content.trim().to_string();
                        i += end + "</artifactId>".len();
                        continue;
                    }
                } else if content[i..].starts_with("<version>") {
                    if let Some(end) = content[i..].find("</version>") {
                        let tag_content = &content[i + "<version>".len()..i + end];
                        current_version = tag_content.trim().to_string();
                        i += end + "</version>".len();
                        continue;
                    }
                }
            }
        }
        i += 1;
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// maven-lockfile.json (Maven)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct MavenLockfile {
    dependencies: Option<Vec<MavenDependency>>,
}

#[derive(Deserialize)]
struct MavenDependency {
    artifactId: Option<String>,
    version: Option<String>,
}

fn parse_maven_lockfile_json(content: &str) -> Result<Vec<Package>, String> {
    let lockfile: MavenLockfile =
        serde_json::from_str(content).map_err(|e| format!("JSON parse error: {}", e))?;

    let ecosystem = Ecosystem::Maven;
    let mut packages = Vec::new();

    if let Some(deps) = lockfile.dependencies {
        for dep in deps {
            if let (Some(artifact), Some(version)) = (dep.artifactId, dep.version) {
                if !artifact.is_empty() && !version.is_empty() {
                    packages.push(Package::new(artifact, version, ecosystem));
                }
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// gradle.lockfile (Gradle)
// ---------------------------------------------------------------------------

/// Parse `gradle.lockfile` (lines like `name:version`).
fn parse_gradle_lockfile(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::Maven;
    let mut packages = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(colon_pos) = line.rfind(':') {
            let name = line[..colon_pos].trim();
            let version = line[colon_pos + 1..].trim();
            if !name.is_empty() && !version.is_empty() {
                packages.push(Package::new(
                    name.to_string(),
                    version.to_string(),
                    ecosystem,
                ));
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// packages.lock.json (NuGet)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct NuGetPackagesLock {
    dependencies: Option<serde_json::Map<String, serde_json::Value>>,
}

fn parse_packages_lock_json(content: &str) -> Result<Vec<Package>, String> {
    let lockfile: NuGetPackagesLock =
        serde_json::from_str(content).map_err(|e| format!("JSON parse error: {}", e))?;

    let ecosystem = Ecosystem::NuGet;
    let mut packages = Vec::new();

    if let Some(deps) = lockfile.dependencies {
        for (name, info) in deps {
            let version = info.get("resolved").and_then(|v| v.as_str()).unwrap_or("");

            if !name.is_empty() && !version.is_empty() {
                packages.push(Package::new(name, version.to_string(), ecosystem));
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// pubspec.lock (Dart)
// ---------------------------------------------------------------------------

/// Parse `pubspec.lock` (YAML-like, `packages: { name: { version: ... } }`).
fn parse_pubspec_lock(content: &str) -> Result<Vec<Package>, String> {
    let ecosystem = Ecosystem::Pub;
    let mut packages = Vec::new();
    let mut in_packages = false;
    let mut current_name = String::new();

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }

        if in_packages {
            // Package entry: 2-space indent, ends with colon
            if line.starts_with("  ") && !line.starts_with("    ") && line.ends_with(':') {
                let name = line.trim().trim_end_matches(':');
                current_name = name.to_string();
            } else if line.starts_with("    version:") && !current_name.is_empty() {
                let version = line.strip_prefix("    version:").unwrap_or("").trim();
                let version = version.trim_matches('"');
                if !version.is_empty() {
                    packages.push(Package::new(
                        current_name.clone(),
                        version.to_string(),
                        ecosystem,
                    ));
                }
                current_name.clear();
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// mix.lock (Elixir)
// ---------------------------------------------------------------------------

/// Parse `mix.lock` (JSON format: `"name": "=> {:hex, :name, version}"`).
fn parse_mix_lock(content: &str) -> Result<Vec<Package>, String> {
    let v: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("JSON parse error: {}", e))?;

    let ecosystem = Ecosystem::Hex;
    let mut packages = Vec::new();

    let obj = v.as_object().ok_or("expected JSON object")?;

    for (name, value) in obj {
        let value_str = value.as_str().unwrap_or("");
        // value_str looks like: => {:hex, :name, "version"}
        // Extract version from the last quoted string
        if let Some(last_quote) = value_str.rfind('"') {
            if let Some(prev_quote) = value_str[..last_quote].rfind('"') {
                let version = &value_str[prev_quote + 1..last_quote];
                if !version.is_empty() {
                    packages.push(Package::new(name.clone(), version.to_string(), ecosystem));
                }
            }
        }
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// Shared TOML-like lockfile parser (used by Poetry)
// ---------------------------------------------------------------------------

/// Parse a TOML-like lockfile with `[[package]]` sections.
fn parse_toml_like_lockfile(content: &str, ecosystem: Ecosystem) -> Result<Vec<Package>, String> {
    let mut packages = Vec::new();
    let mut in_package = false;
    let mut name = String::new();
    let mut version = String::new();

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("[[package]]") {
            // Finish previous package
            if in_package && !name.is_empty() && !version.is_empty() {
                packages.push(Package::new(name.clone(), version.clone(), ecosystem));
            }
            in_package = true;
            name.clear();
            version.clear();
        } else if line.starts_with('[') && line.ends_with(']') && in_package {
            // End of this package block
            if !name.is_empty() && !version.is_empty() {
                packages.push(Package::new(name.clone(), version.clone(), ecosystem));
            }
            in_package = false;
            name.clear();
            version.clear();
        } else if in_package {
            if let Some(val) = line.strip_prefix("name = ") {
                name = parse_toml_string(val);
            } else if let Some(val) = line.strip_prefix("version = ") {
                version = parse_toml_string(val);
            }
        }
    }

    // Handle last package
    if in_package && !name.is_empty() && !version.is_empty() {
        packages.push(Package::new(name, version, ecosystem));
    }

    Ok(packages)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_cargo_lock() {
        assert_eq!(
            detect_lockfile_type("Cargo.lock"),
            Some(LockfileType::CargoLock)
        );
    }

    #[test]
    fn test_detect_package_lock_json() {
        assert_eq!(
            detect_lockfile_type("package-lock.json"),
            Some(LockfileType::PackageLockJson)
        );
    }

    #[test]
    fn test_detect_yarn_lock() {
        assert_eq!(
            detect_lockfile_type("yarn.lock"),
            Some(LockfileType::YarnLock)
        );
    }

    #[test]
    fn test_detect_pnpm_lock_yaml() {
        assert_eq!(
            detect_lockfile_type("pnpm-lock.yaml"),
            Some(LockfileType::PnpmLockYaml)
        );
    }

    #[test]
    fn test_detect_unknown() {
        assert_eq!(detect_lockfile_type("random.txt"), None);
    }

    #[test]
    fn test_parse_cargo_lock() {
        let content = r#"
[[package]]
name = "once"
version = "2.4.0"

[[package]]
name = "log"
version = "0.4.19"
"#;
        let packages = parse_cargo_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "once");
        assert_eq!(packages[0].version, "2.4.0");
        assert_eq!(packages[0].ecosystem, Ecosystem::CratesIo);
        assert_eq!(packages[1].name, "log");
        assert_eq!(packages[1].version, "0.4.19");
    }

    #[test]
    fn test_parse_package_lock_json() {
        let content = r#"{
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    },
    "node_modules/express": {
      "version": "4.18.2"
    }
  }
}"#;
        let packages = parse_package_lock_json(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "lodash");
        assert_eq!(packages[0].version, "4.17.21");
        assert_eq!(packages[0].ecosystem, Ecosystem::Npm);
        assert_eq!(packages[1].name, "express");
        assert_eq!(packages[1].version, "4.18.2");
    }

    #[test]
    fn test_parse_requirements_txt() {
        let content = r#"
# This is a requirements file
requests==2.28.0
numpy>=1.21.0
pip>=19.0
"#;
        let packages = parse_requirements_txt(content).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "requests");
        assert_eq!(packages[0].version, "2.28.0");
        assert_eq!(packages[0].ecosystem, Ecosystem::PyPI);
        assert_eq!(packages[2].name, "pip");
    }

    #[test]
    fn test_parse_go_sum() {
        let content = r#"
github.com/pkg/errors v0.9.0
github.com/stretchr/testify v1.8.0
"#;
        let packages = parse_go_sum(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "github.com/pkg/errors");
        assert_eq!(packages[0].version, "v0.9.0");
        assert_eq!(packages[0].ecosystem, Ecosystem::Go);
    }

    #[test]
    fn test_parse_pipfile_lock() {
        let content = r#"{
  "default": {
    "requests": {
      "version": "==2.28.0"
    },
    "numpy": {
      "version": ">=1.21.0"
    }
  }
}"#;
        let packages = parse_pipfile_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "requests");
        assert_eq!(packages[0].version, "==2.28.0");
        assert_eq!(packages[0].ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn test_parse_gemfile_lock() {
        let content = r#"GEM
    remote: https://rubygems.org/
    specs:
      rails (6.1.4.1)
      concurrent-ruby (1.1.9)

PLATFORMS
  ruby

DEPENDENCIES
  rails
"#;
        let packages = parse_gemfile_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "rails");
        assert_eq!(packages[0].version, "6.1.4.1");
        assert_eq!(packages[0].ecosystem, Ecosystem::RubyGems);
    }

    #[test]
    fn test_parse_composer_lock() {
        let content = r#"{
  "packages": [
    {"name": "monolog/monolog", "version": "2.3.0"},
    {"name": "phpunit/phpunit", "version": "9.5.0"}
  ]
}"#;
        let packages = parse_composer_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "monolog/monolog");
        assert_eq!(packages[0].version, "2.3.0");
        assert_eq!(packages[0].ecosystem, Ecosystem::Packagist);
    }

    #[test]
    fn test_parse_gradle_lockfile() {
        let content = r#"# Gradle lockfile
commons-codec:commons-codec:1.15
guava:guava:31.0-jre
"#;
        let packages = parse_gradle_lockfile(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "commons-codec:commons-codec");
        assert_eq!(packages[0].version, "1.15");
        assert_eq!(packages[0].ecosystem, Ecosystem::Maven);
    }

    #[test]
    fn test_parse_maven_lockfile_json() {
        let content = r#"{
  "dependencies": [
    {"artifactId": "commons-codec", "version": "1.15"},
    {"artifactId": "guava", "version": "31.0-jre"}
  ]
}"#;
        let packages = parse_maven_lockfile_json(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "commons-codec");
        assert_eq!(packages[0].version, "1.15");
        assert_eq!(packages[0].ecosystem, Ecosystem::Maven);
    }

    #[test]
    fn test_parse_pubspec_lock() {
        let content = r#"packages:
  flutter:
    version: "1.0.0"
  http:
    version: "0.13.4"
"#;
        let packages = parse_pubspec_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "flutter");
        assert_eq!(packages[0].version, "1.0.0");
        assert_eq!(packages[0].ecosystem, Ecosystem::Pub);
    }

    #[test]
    fn test_parse_mix_lock() {
        let content = r#"{
  "httpoison": "=> {:hex, :httpoison, \"1.1.0\"}",
  "poison": "=> {:hex, :poison, \"5.3.0\"}"
}"#;
        let packages = parse_mix_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "httpoison");
        assert_eq!(packages[0].version, "1.1.0");
        assert_eq!(packages[0].ecosystem, Ecosystem::Hex);
    }

    #[test]
    fn test_parse_pom_xml() {
        let content = r#"<project>
  <dependencies>
    <dependency>
      <artifactId>commons-codec</artifactId>
      <version>1.15</version>
    </dependency>
    <dependency>
      <artifactId>guava</artifactId>
      <version>31.0-jre</version>
    </dependency>
  </dependencies>
</project>"#;
        let packages = parse_pom_xml(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "commons-codec");
        assert_eq!(packages[0].version, "1.15");
        assert_eq!(packages[0].ecosystem, Ecosystem::Maven);
    }

    #[test]
    fn test_parse_packages_lock_json() {
        let content = r#"{
  "dependencies": {
    "Newtonsoft.Json": {
      "resolved": "13.0.1"
    }
  }
}"#;
        let packages = parse_packages_lock_json(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "Newtonsoft.Json");
        assert_eq!(packages[0].version, "13.0.1");
        assert_eq!(packages[0].ecosystem, Ecosystem::NuGet);
    }

    #[test]
    fn test_parse_yarn_lock() {
        let content = r#"
lodash@4.17.21:
  version "4.17.21"
  resolved "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"

express@4.18.2:
  version "4.18.2"
  resolved "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
"#;
        let packages = parse_yarn_lock(content).unwrap();
        assert!(packages.len() >= 2);
        assert_eq!(packages[0].ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn test_parse_poetry_lock() {
        let content = r#"
[[package]]
name = "requests"
version = "2.28.0"

[[package]]
name = "numpy"
version = "1.21.0"
"#;
        let packages = parse_poetry_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "requests");
        assert_eq!(packages[0].version, "2.28.0");
        assert_eq!(packages[0].ecosystem, Ecosystem::PyPI);
    }

    #[test]
    fn test_parse_pnpm_lock_yaml() {
        let content = r#"
packages:
  /lodash@4.17.21:
    version: 4.17.21
    resolution:
      url: https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz
  /express@4.18.2:
    version: 4.18.2
    resolution:
      url: https://registry.npmjs.org/express/-/express-4.18.2.tgz
"#;
        let packages = parse_pnpm_lock_yaml(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "lodash");
        assert_eq!(packages[0].version, "4.17.21");
        assert_eq!(packages[0].ecosystem, Ecosystem::Npm);
    }

    #[test]
    fn test_ecosystem_as_str() {
        assert_eq!(Ecosystem::CratesIo.as_str(), "crates.io");
        assert_eq!(Ecosystem::PyPI.as_str(), "PyPI");
        assert_eq!(Ecosystem::Npm.as_str(), "npm");
        assert_eq!(Ecosystem::Go.as_str(), "Go");
        assert_eq!(Ecosystem::RubyGems.as_str(), "RubyGems");
        assert_eq!(Ecosystem::Packagist.as_str(), "Packagist");
        assert_eq!(Ecosystem::Maven.as_str(), "Maven");
        assert_eq!(Ecosystem::NuGet.as_str(), "NuGet");
        assert_eq!(Ecosystem::Pub.as_str(), "Pub");
        assert_eq!(Ecosystem::Hex.as_str(), "Hex");
    }

    #[test]
    fn test_lockfile_type_ecosystem() {
        assert_eq!(LockfileType::CargoLock.ecosystem(), Ecosystem::CratesIo);
        assert_eq!(LockfileType::PackageLockJson.ecosystem(), Ecosystem::Npm);
        assert_eq!(LockfileType::PoetryLock.ecosystem(), Ecosystem::PyPI);
        assert_eq!(LockfileType::GoSum.ecosystem(), Ecosystem::Go);
        assert_eq!(LockfileType::GemfileLock.ecosystem(), Ecosystem::RubyGems);
        assert_eq!(LockfileType::ComposerLock.ecosystem(), Ecosystem::Packagist);
        assert_eq!(LockfileType::PomXml.ecosystem(), Ecosystem::Maven);
        assert_eq!(LockfileType::PackagesLockJson.ecosystem(), Ecosystem::NuGet);
        assert_eq!(LockfileType::PubSpecLock.ecosystem(), Ecosystem::Pub);
        assert_eq!(LockfileType::MixLock.ecosystem(), Ecosystem::Hex);
    }

    #[test]
    fn test_package_new() {
        let pkg = Package::new("test".to_string(), "1.0.0".to_string(), Ecosystem::Npm);
        assert_eq!(pkg.name, "test");
        assert_eq!(pkg.version, "1.0.0");
        assert_eq!(pkg.ecosystem, Ecosystem::Npm);
    }
}
