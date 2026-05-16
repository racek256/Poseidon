//! Typosquatting detection for supply chain packages.
//!
//! Detects potential typosquatting attacks by comparing package names against
//! known popular packages and generating common mutation patterns.

use std::collections::HashSet;

/// Popular packages per ecosystem.
mod popular_packages {
    /// npm (Node.js) popular packages.
    pub const NPM: &[&str] = &[
        "lodash",
        "express",
        "react",
        "axios",
        "chalk",
        "debug",
        "async",
        "request",
        "commander",
        "react-dom",
        "@types/node",
        "uuid",
        "fs-extra",
        "moment",
        "prop-types",
        "gulp",
        "webpack",
        "typescript",
        "eslint",
        "jest",
        "vue",
        "core-js",
        "redux",
        "mongoose",
        "passport",
        "socket.io",
        "body-parser",
        "express-async-handler",
        "dotenv",
        "cors",
        "bcrypt",
        "jsonwebtoken",
        "mysql",
        "pg",
        "redis",
        "winston",
        "dotenv",
        "morgan",
        "helmet",
        "joi",
        "zod",
        "yup",
        "class-validator",
        "ioredis",
        "node-fetch",
        "axios",
        "ramda",
        "underscore",
        "moment-timezone",
        "validator",
        "nconf",
        "path",
        "crypto",
        "stream",
        "events",
        "http",
        "https",
        "url",
        "querystring",
        "string_decoder",
        "streamroller",
        "archiver",
        "extract-zip",
        "mkdirp",
        "rimraf",
        "mkdirp",
        "glob",
        "minimatch",
        "rimraf",
        "nopt",
        "semver",
        "tar",
        "https-proxy-agent",
        "agent-base",
        "ansi-regex",
        "ansi-styles",
        "supports-color",
        "chalk",
        "debug",
        "ms",
        "eslint-plugin-import",
        "eslint-plugin-react",
        "babel-core",
        "@babel/core",
        "@babel/preset-env",
        "@babel/preset-react",
        "@babel/cli",
        "@babel/node",
        "webpack-cli",
        "webpack-dev-server",
        "html-webpack-plugin",
        "css-loader",
        "style-loader",
        "file-loader",
        "url-loader",
        "terser-webpack-plugin",
        "css-minimizer-webpack-plugin",
    ];

    /// PyPI (Python) popular packages.
    pub const PYPI: &[&str] = &[
        "requests",
        "urllib3",
        "setuptools",
        "six",
        "certifi",
        "idna",
        "python-dateutil",
        "boto3",
        "botocore",
        "s3transfer",
        "pyjwt",
        "numpy",
        "pandas",
        "flask",
        "django",
        "sqlalchemy",
        "pillow",
        "matplotlib",
        "pytest",
        "scipy",
        "scikit-learn",
        "pandas",
        "ipython",
        "jinja2",
        "werkzeug",
        "markupsafe",
        "click",
        "itsdangerous",
        "blinker",
        "flask-cors",
        "flask-sqlalchemy",
        "psycopg2",
        "pyyaml",
        "pyyaml",
        "cryptography",
        "paramiko",
        "fabric",
        "invoke",
        "tox",
        "twine",
        "pip",
        "pip-tools",
        "pip-compile",
        "poetry",
        "virtualenv",
        "celery",
        "redis-py",
        "kafka-python",
        "pymongo",
        "pymysql",
        "sqlalchemy",
        "alembic",
        "python-dotenv",
        "python-dateutil",
        "pytz",
        "tzdata",
        "cffi",
        "pycparser",
        "pyasn1",
        "rsa",
        "cachetools",
        "google-auth",
        "pyjwt",
        "cryptography",
        "ecdsa",
        "asn1crypto",
        "pillow",
        "image",
        "opencv-python",
        "scipy",
        "numpy",
        "networkx",
        "sympy",
        "statsmodels",
        "pandas",
        "matplotlib",
        "seaborn",
        "plotly",
        "dash",
        "fastapi",
        "uvicorn",
        "starlette",
        "pydantic",
        "email-validator",
        "httpx",
        "aiohttp",
        "requests-toolbelt",
        "beautifulsoup4",
        "lxml",
        "html5lib",
        "cssselect",
        "selenium",
        "playwright",
        "scrapy",
        "pyquery",
        "tqdm",
        "colorama",
        "click",
        "rich",
        "typer",
        "inquirer",
        "questionary",
        "prompt-toolkit",
        "pygments",
        "highlight.js",
        "markdown",
        "mistune",
        "commonmark",
        "recommonmark",
        "docutils",
        "sphinx",
        "sphinx-rtd-theme",
        "myst-parser",
    ];

    /// crates.io (Rust) popular packages.
    pub const CRATES: &[&str] = &[
        "serde",
        "tokio",
        "log",
        "rand",
        "clap",
        "chrono",
        "regex",
        "lazy_static",
        "anyhow",
        "thiserror",
        "reqwest",
        "hyper",
        "actix-web",
        "axum",
        "tracing",
        "dashmap",
        "crossbeam",
        "rayon",
        "serde_json",
        "serde_yaml",
        "serde_xml",
        "toml",
        "ron",
        "rucp",
        "bimap",
        "once_cell",
        "parking_lot",
        "smallvec",
        "growable_vec",
        "ahash",
        "hashbrown",
        "indexmap",
        "slotmap",
        "frobenius",
        "num_cpus",
        "memchr",
        "memoffset",
        "find_crate",
        "libloading",
        "raw-window-handle",
        "fontdue",
        "image",
        "png",
        "jpeg",
        "gif",
        "bmp",
        "tiff",
        "webp",
        "gifski",
        "imageproc",
        "imageinfo",
        "resvg",
        "qrcode",
        "barcode",
        "uuid",
        "rustyline",
        "console",
        "clap",
        "argh",
        "gumdrop",
        "pico_args",
        "structopt",
        "derive_more",
        "num_derive",
        "enum_dispatch",
        "strum",
        "strum_macros",
        "thiserror",
        "anyhow",
        "color-eyre",
        "eyre",
        "tracing",
        "tracing-subscriber",
        "tracing-appender",
        "tracing-attributes",
        "tracing-futures",
        "tracing-serde",
        "tracing-macros",
        "metrics",
        "metrics-exporter",
        "opentelemetry",
        "opentelemetry-api",
        "opentelemetry-sdk",
        "opentelemetry-otlp",
        "prost",
        "tonic",
        "grpcio",
        "sqlx",
        "diesel",
        "rustorm",
        "sea-orm",
        "tokio-postgres",
        "tokio-sqlite",
        "rusqlite",
        "mongodb",
        "redis",
        "kafka",
        "lapin",
        "mqtt",
        "nats",
        "reqwest",
        "hyper",
        "actix-web",
        "axum",
        "warp",
        "rocket",
        "poem",
        "salvo",
        "tower",
        "tower-http",
        "http",
        "http-body",
        "httparse",
        "mime",
        "mime-guess",
        "content-type",
        "cookie",
        "cookie-store",
        "form_urlencoded",
        "url",
        "urlencoding",
        "percent-encoding",
    ];

    /// Get packages for an ecosystem.
    pub fn for_ecosystem(ecosystem: &str) -> &'static [&'static str] {
        match ecosystem.to_lowercase().as_str() {
            "npm" | "node" | "nodejs" | "yarn" | "pnpm" => NPM,
            "pypi" | "pip" | "python" | "poetry" | "pipenv" => PYPI,
            "crates" | "cargo" | "rust" => CRATES,
            _ => &[],
        }
    }
}

/// Character substitutions for similar-looking characters.
const SIMILAR_CHARS: &[(char, char)] = &[
    ('0', 'o'),
    ('0', 'O'),
    ('1', 'l'),
    ('1', 'i'),
    ('1', 'I'),
    ('l', '1'),
    ('i', '1'),
    ('i', 'l'),
    ('o', '0'),
    ('O', '0'),
    ('5', 's'),
    ('5', 'S'),
    ('s', '5'),
    ('s', 'S'),
    ('a', 'e'),
    ('e', 'a'),
    ('g', 'q'),
    ('q', 'g'),
    ('c', 'k'),
    ('k', 'c'),
];

/// Compute Levenshtein distance between two strings.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let mut matrix = vec![vec![0usize; b.len() + 1]; a.len() + 1];

    for i in 0..=a.len() {
        matrix[i][0] = i;
    }
    for j in 0..=b.len() {
        matrix[0][j] = j;
    }

    for (i, ca) in a.chars().enumerate() {
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            matrix[i + 1][j + 1] = (matrix[i][j + 1] + 1)
                .min(matrix[i + 1][j] + 1)
                .min(matrix[i][j] + cost);
        }
    }

    matrix[a.len()][b.len()]
}

/// Generate common typosquatting mutations for a package name.
pub fn generate_mutations(name: &str) -> Vec<String> {
    let mut mutations = HashSet::new();
    let chars: Vec<char> = name.chars().collect();
    let len = chars.len();

    // Omitted characters (drop each character)
    for i in 0..len {
        let mut m = chars.clone();
        m.remove(i);
        if !m.is_empty() {
            mutations.insert(m.iter().collect());
        }
    }

    // Doubled characters (duplicate each character)
    for i in 0..len {
        let mut m = chars.clone();
        m.insert(i, chars[i]);
        mutations.insert(m.iter().collect());
    }

    // Swapped adjacent characters
    for i in 0..len.saturating_sub(1) {
        let mut m = chars.clone();
        m.swap(i, i + 1);
        mutations.insert(m.iter().collect());
    }

    for (i, c) in chars.iter().enumerate() {
        for (from, to) in SIMILAR_CHARS.iter() {
            if *c == *from {
                let mut m = chars.clone();
                m[i] = *to;
                mutations.insert(m.iter().collect());
            }
        }
    }

    for i in 0..len.saturating_sub(1) {
        let pair: String = chars[i..i + 2].iter().collect();
        if pair == "rn" {
            let mut m = chars.clone();
            m.splice(i..i + 2, ['m']);
            mutations.insert(m.iter().collect());
        } else if pair == "m" {
            let mut m = chars.clone();
            m.splice(i..i + 2, ['r', 'n']);
            mutations.insert(m.iter().collect());
        }
    }

    if !name.contains('-') {
        for i in 1..len {
            let mut m = String::new();
            m.push_str(&name[..i]);
            m.push('-');
            m.push_str(&name[i..]);
            mutations.insert(m);
        }
    }
    if !name.contains('_') {
        for i in 1..len {
            let mut m = String::new();
            m.push_str(&name[..i]);
            m.push('_');
            m.push_str(&name[i..]);
            mutations.insert(m);
        }
    }

    if !name.starts_with('@') {
        mutations.insert(name.to_lowercase());
        mutations.insert(name.to_uppercase());
    }

    mutations.into_iter().collect()
}

/// Typosquatting detection checker.
pub struct TyposquatChecker {
    popular_packages: HashSet<String>,
}

impl TyposquatChecker {
    /// Create a new checker with built-in popular packages for the given ecosystem.
    pub fn new(ecosystem: &str) -> Self {
        let packages = popular_packages::for_ecosystem(ecosystem);
        let popular_packages = packages.iter().map(|s| s.to_lowercase()).collect();
        Self { popular_packages }
    }

    /// Create a checker that covers all supported ecosystems.
    pub fn all() -> Self {
        let mut popular_packages = HashSet::new();

        for packages in [
            popular_packages::NPM,
            popular_packages::PYPI,
            popular_packages::CRATES,
        ] {
            for pkg in packages {
                popular_packages.insert(pkg.to_lowercase());
            }
        }

        Self { popular_packages }
    }

    /// Check a package name for potential typosquatting.
    ///
    /// Returns a vector of warning strings for each matching mutation.
    pub fn check_package(&self, name: &str, ecosystem: &str) -> Vec<String> {
        let name_lower = name.to_lowercase();
        let popular = popular_packages::for_ecosystem(ecosystem);

        let mut warnings = Vec::new();

        for pkg in popular {
            if name_lower == pkg.to_lowercase() {
                return warnings;
            }
        }

        // First: exact match on mutations against popular packages
        let mutations = generate_mutations(&name_lower);
        for m in &mutations {
            for pkg in popular {
                if m.to_lowercase() == pkg.to_lowercase() {
                    warnings.push(format!("Possible typosquat of '{}': '{}'", pkg, m));
                }
            }
        }

        // Fallback: Levenshtein distance <= 2 against all popular packages
        if warnings.is_empty() {
            for pkg in popular {
                let distance = levenshtein(&name_lower, &pkg.to_lowercase());
                if distance > 0 && distance <= 2 {
                    warnings.push(format!(
                        "Possible typosquat of '{}' (Levenshtein distance {}): '{}'",
                        pkg, distance, name
                    ));
                }
            }
        }

        warnings
    }

    /// Check a package name using the all-ecosystems database.
    pub fn check_package_all(&self, name: &str) -> Vec<String> {
        let name_lower = name.to_lowercase();
        let mut warnings = Vec::new();

        let mutations = generate_mutations(&name_lower);
        for m in &mutations {
            if self.popular_packages.contains(&m.to_lowercase()) {
                warnings.push(format!(
                    "Possible typosquat: '{}' matches known package '{}'",
                    name, m
                ));
            }
        }

        if warnings.is_empty() {
            for pkg in &self.popular_packages {
                let distance = levenshtein(&name_lower, pkg);
                if distance > 0 && distance <= 2 {
                    warnings.push(format!(
                        "Possible typosquat (Levenshtein distance {}): '{}' ~ '{}'",
                        distance, name, pkg
                    ));
                }
            }
        }

        warnings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein_exact_match() {
        assert_eq!(levenshtein("hello", "hello"), 0);
    }

    #[test]
    fn test_levenshtein_single_char_diff() {
        assert_eq!(levenshtein("hello", "hallo"), 1);
    }

    #[test]
    fn test_levenshtein_insertion() {
        assert_eq!(levenshtein("hello", "helloo"), 1);
    }

    #[test]
    fn test_levenshtein_deletion() {
        assert_eq!(levenshtein("hello", "hell"), 1);
    }

    #[test]
    fn test_levenshtein_swap() {
        assert_eq!(levenshtein("hello", "helol"), 2);
    }

    #[test]
    fn test_levenshtein_empty() {
        assert_eq!(levenshtein("", "hello"), 5);
        assert_eq!(levenshtein("hello", ""), 5);
        assert_eq!(levenshtein("", ""), 0);
    }

    #[test]
    fn test_levenshtein_complete_mutation() {
        assert_eq!(levenshtein("lodsh", "lodash"), 1);
    }

    #[test]
    fn test_generate_mutations_omitted() {
        let muts = generate_mutations("abc");
        assert!(muts.contains(&"bc".to_string()));
        assert!(muts.contains(&"ac".to_string()));
        assert!(muts.contains(&"ab".to_string()));
    }

    #[test]
    fn test_generate_mutations_doubled() {
        let muts = generate_mutations("abc");
        assert!(muts.contains(&"aabc".to_string()));
        assert!(muts.contains(&"abbc".to_string()));
        assert!(muts.contains(&"abcc".to_string()));
    }

    #[test]
    fn test_generate_mutations_swapped() {
        let muts = generate_mutations("abc");
        assert!(muts.contains(&"bac".to_string()));
        assert!(muts.contains(&"acb".to_string()));
    }

    #[test]
    fn test_generate_mutations_similar_chars() {
        let muts = generate_mutations("l0dh");
        assert!(muts.contains(&"lodh".to_string()));
    }

    #[test]
    fn test_generate_mutations_rn_m() {
        let muts = generate_mutations("form");
        assert!(muts.contains(&"from".to_string()));
    }

    #[test]
    fn test_generate_mutations_not_empty() {
        let muts = generate_mutations("abc");
        assert!(!muts.is_empty());
    }

    #[test]
    fn test_generate_mutations_uniqueness() {
        let muts = generate_mutations("aaa");
        let unique: HashSet<_> = muts.iter().collect();
        assert_eq!(muts.len(), unique.len());
    }

    #[test]
    fn test_typosquat_checker_npm_exact() {
        let checker = TyposquatChecker::new("npm");
        let warnings = checker.check_package("lodsh", "npm");
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("lodash")));
    }

    #[test]
    fn test_typosquat_checker_pypi_exact() {
        let checker = TyposquatChecker::new("pypi");
        let warnings = checker.check_package("reqests", "pypi");
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("requests")));
    }

    #[test]
    fn test_typosquat_checker_crates_exact() {
        let checker = TyposquatChecker::new("crates");
        let warnings = checker.check_package("toklo", "crates");
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("tokio")));
    }

    #[test]
    fn test_typosquat_checker_levenshtein_fallback() {
        let checker = TyposquatChecker::new("npm");
        let warnings = checker.check_package("loddash", "npm");
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_typosquat_checker_unknown_package() {
        let checker = TyposquatChecker::new("npm");
        let warnings = checker.check_package("xyzabc123nonexistent", "npm");
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_typosquat_checker_all() {
        let checker = TyposquatChecker::all();
        let warnings = checker.check_package_all("lodsh");
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_typosquat_checker_scoped_package() {
        let checker = TyposquatChecker::new("npm");
        let warnings = checker.check_package("@types/nde", "npm");
        assert!(!warnings.is_empty());
    }

    #[test]
    fn test_typosquat_checker_clean_package() {
        let checker = TyposquatChecker::new("npm");
        let warnings = checker.check_package("express", "npm");
        assert!(warnings.is_empty());
    }
}
