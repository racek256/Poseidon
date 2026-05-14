use std::env;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use duckdb::{Connection, OptionalExt, params};
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DEFAULT_MESSAGE_DB_PATH: &str = "poseidon_messages.duckdb";
const SIMILARITY_DISTANCE_THRESHOLD: u32 = 12;
const SIMILARITY_CANDIDATE_LIMIT: usize = 5_000;

pub struct MessageMemory {
    conn: Connection,
    store_raw_unsafe: bool,
}

#[derive(Debug)]
pub struct MemoryLookup {
    pub message_hash: String,
    pub simhash: u64,
    pub normalized_message: String,
    pub redacted_message: String,
    pub exact_match: Option<UnsafeMessageMatch>,
    pub similar_matches: Vec<UnsafeMessageMatch>,
    pub risk_adjustment: u8,
}

#[derive(Debug, Clone)]
pub struct UnsafeMessageMatch {
    pub message_hash: String,
    pub distance: u32,
    pub risk_score: u8,
    pub decision: String,
    pub summary: Option<String>,
}

#[derive(Debug)]
pub struct UnsafeMessageRecord<'a> {
    pub message: &'a str,
    pub decision: &'a str,
    pub risk_score: u8,
    pub confidence: u8,
    pub summary: Option<&'a str>,
    pub tags: Vec<String>,
    pub url_hashes: Vec<String>,
}

impl MemoryLookup {
    pub fn to_json(&self, stored: bool) -> Value {
        json!({
            "stored": stored,
            "message_hash": self.message_hash,
            "simhash": format!("{:016x}", self.simhash),
            "exact_match": self.exact_match.as_ref().map(match_json),
            "similar_matches": self.similar_matches.iter().map(match_json).collect::<Vec<_>>(),
            "nearest_distance": self.similar_matches.first().map(|item| item.distance),
            "risk_adjustment": self.risk_adjustment
        })
    }
}

impl MessageMemory {
    pub fn from_env() -> duckdb::Result<Self> {
        let path = env::var("POSEIDON_MESSAGE_DB_PATH")
            .unwrap_or_else(|_| DEFAULT_MESSAGE_DB_PATH.to_string());
        let store_raw_unsafe = env::var("POSEIDON_STORE_RAW_UNSAFE")
            .map(|value| !matches!(value.as_str(), "0" | "false" | "FALSE" | "no" | "NO"))
            .unwrap_or(true);
        eprintln!("message memory db: using DuckDB at {path}");
        let memory = Self {
            conn: Connection::open(Path::new(&path))?,
            store_raw_unsafe,
        };
        memory.init()?;
        Ok(memory)
    }

    pub fn init(&self) -> duckdb::Result<()> {
        self.conn.execute_batch(
            "SET preserve_insertion_order=false;
            CREATE TABLE IF NOT EXISTS unsafe_messages (
                message_hash TEXT PRIMARY KEY,
                simhash TEXT NOT NULL,
                raw_message TEXT,
                redacted_message TEXT NOT NULL,
                normalized_message TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score UTINYINT NOT NULL,
                confidence UTINYINT NOT NULL,
                summary TEXT,
                first_seen BIGINT NOT NULL,
                last_seen BIGINT NOT NULL,
                seen_count UBIGINT NOT NULL,
                source TEXT NOT NULL,
                updated_at BIGINT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_unsafe_messages_updated_at ON unsafe_messages(updated_at);

            CREATE TABLE IF NOT EXISTS unsafe_message_tags (
                message_hash TEXT NOT NULL,
                tag TEXT NOT NULL,
                confidence UTINYINT,
                source TEXT NOT NULL,
                updated_at BIGINT NOT NULL,
                UNIQUE(message_hash, tag, source)
            );
            CREATE INDEX IF NOT EXISTS idx_unsafe_message_tags_hash ON unsafe_message_tags(message_hash);

            CREATE TABLE IF NOT EXISTS unsafe_message_urls (
                message_hash TEXT NOT NULL,
                url_hash TEXT NOT NULL,
                updated_at BIGINT NOT NULL,
                UNIQUE(message_hash, url_hash)
            );

            CREATE TABLE IF NOT EXISTS unsafe_message_similarity (
                message_hash TEXT NOT NULL,
                similar_message_hash TEXT NOT NULL,
                hamming_distance UTINYINT NOT NULL,
                similar_risk_score UTINYINT NOT NULL,
                updated_at BIGINT NOT NULL,
                UNIQUE(message_hash, similar_message_hash)
            );",
        )
    }

    pub fn lookup(&self, message: &str) -> duckdb::Result<MemoryLookup> {
        let normalized_message = normalize_message(message);
        let redacted_message = redact_message(&normalized_message);
        let message_hash = sha256_hex(&normalized_message);
        let simhash = simhash64(&normalized_message);
        let exact_match = self.exact_match(&message_hash)?;
        let mut similar_matches = self.similar_matches(&message_hash, simhash)?;
        similar_matches.sort_by(|a, b| {
            a.distance
                .cmp(&b.distance)
                .then_with(|| b.risk_score.cmp(&a.risk_score))
        });
        similar_matches.truncate(10);

        let mut risk_adjustment = similar_matches
            .iter()
            .map(|item| adjustment_for_distance(item.distance))
            .max()
            .unwrap_or_default();
        if exact_match.is_some() {
            risk_adjustment = risk_adjustment.max(35);
        }

        Ok(MemoryLookup {
            message_hash,
            simhash,
            normalized_message,
            redacted_message,
            exact_match,
            similar_matches,
            risk_adjustment,
        })
    }

    pub fn store_unsafe(
        &self,
        lookup: &MemoryLookup,
        record: UnsafeMessageRecord<'_>,
    ) -> duckdb::Result<()> {
        let now = unix_now();
        let raw_message = self.store_raw_unsafe.then_some(record.message);
        self.conn.execute(
            "INSERT INTO unsafe_messages (
                message_hash, simhash, raw_message, redacted_message, normalized_message,
                decision, risk_score, confidence, summary, first_seen, last_seen,
                seen_count, source, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, 1, 'scoring', ?10)
            ON CONFLICT(message_hash) DO UPDATE SET
                raw_message = COALESCE(excluded.raw_message, unsafe_messages.raw_message),
                redacted_message = excluded.redacted_message,
                normalized_message = excluded.normalized_message,
                decision = excluded.decision,
                risk_score = excluded.risk_score,
                confidence = excluded.confidence,
                summary = excluded.summary,
                last_seen = excluded.last_seen,
                seen_count = unsafe_messages.seen_count + 1,
                source = excluded.source,
                updated_at = excluded.updated_at",
            params![
                lookup.message_hash,
                format!("{:016x}", lookup.simhash),
                raw_message,
                lookup.redacted_message,
                lookup.normalized_message,
                record.decision,
                record.risk_score,
                record.confidence,
                record.summary,
                now,
            ],
        )?;

        for tag in record.tags {
            self.conn.execute(
                "INSERT INTO unsafe_message_tags (message_hash, tag, confidence, source, updated_at)
                VALUES (?1, ?2, ?3, 'scoring', ?4)
                ON CONFLICT(message_hash, tag, source) DO UPDATE SET
                    confidence = excluded.confidence,
                    updated_at = excluded.updated_at",
                params![lookup.message_hash, tag, record.confidence, now],
            )?;
        }

        for url_hash in record.url_hashes {
            self.conn.execute(
                "INSERT INTO unsafe_message_urls (message_hash, url_hash, updated_at)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(message_hash, url_hash) DO UPDATE SET updated_at = excluded.updated_at",
                params![lookup.message_hash, url_hash, now],
            )?;
        }

        for item in &lookup.similar_matches {
            self.conn.execute(
                "INSERT INTO unsafe_message_similarity (
                    message_hash, similar_message_hash, hamming_distance, similar_risk_score, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                ON CONFLICT(message_hash, similar_message_hash) DO UPDATE SET
                    hamming_distance = excluded.hamming_distance,
                    similar_risk_score = excluded.similar_risk_score,
                    updated_at = excluded.updated_at",
                params![
                    lookup.message_hash,
                    item.message_hash,
                    item.distance as u8,
                    item.risk_score,
                    now
                ],
            )?;
        }

        Ok(())
    }

    fn exact_match(&self, message_hash: &str) -> duckdb::Result<Option<UnsafeMessageMatch>> {
        self.conn
            .query_row(
                "SELECT message_hash, risk_score, decision, summary FROM unsafe_messages WHERE message_hash = ?1",
                params![message_hash],
                |row| {
                    Ok(UnsafeMessageMatch {
                        message_hash: row.get(0)?,
                        distance: 0,
                        risk_score: row.get(1)?,
                        decision: row.get(2)?,
                        summary: row.get(3)?,
                    })
                },
            )
            .optional()
    }

    fn similar_matches(
        &self,
        message_hash: &str,
        simhash: u64,
    ) -> duckdb::Result<Vec<UnsafeMessageMatch>> {
        let mut stmt = self.conn.prepare(
            "SELECT message_hash, simhash, risk_score, decision, summary
             FROM unsafe_messages
             WHERE message_hash <> ?1
             ORDER BY updated_at DESC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(
            params![message_hash, SIMILARITY_CANDIDATE_LIMIT as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, u8>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )?;

        let mut matches = Vec::new();
        for row in rows {
            let (candidate_hash, candidate_simhash, risk_score, decision, summary) = row?;
            let Some(candidate_simhash) = parse_simhash(&candidate_simhash) else {
                continue;
            };
            let distance = (simhash ^ candidate_simhash).count_ones();
            if distance <= SIMILARITY_DISTANCE_THRESHOLD {
                matches.push(UnsafeMessageMatch {
                    message_hash: candidate_hash,
                    distance,
                    risk_score,
                    decision,
                    summary,
                });
            }
        }
        Ok(matches)
    }
}

pub fn run_benchmark() -> duckdb::Result<()> {
    let memory = MessageMemory::from_env()?;
    let seed = "Urgent: verify your PayPal account now at https://paypal-login.example.net";
    let seed_lookup = memory.lookup(seed)?;
    memory.store_unsafe(
        &seed_lookup,
        UnsafeMessageRecord {
            message: seed,
            decision: "warn_both",
            risk_score: 85,
            confidence: 90,
            summary: Some("PayPal verification phishing lure"),
            tags: vec!["phishing".to_string(), "impersonation".to_string()],
            url_hashes: Vec::new(),
        },
    )?;

    let similar = "Please verify your paypal account immediately here https://bad.example.org";
    let lookup = memory.lookup(similar)?;
    println!("exact_match: {}", lookup.exact_match.is_some());
    println!("similar_matches: {}", lookup.similar_matches.len());
    println!("risk_adjustment: {}", lookup.risk_adjustment);
    if let Some(nearest) = lookup.similar_matches.first() {
        println!(
            "nearest: distance={} risk={} decision={}",
            nearest.distance, nearest.risk_score, nearest.decision
        );
    }
    Ok(())
}

fn match_json(item: &UnsafeMessageMatch) -> Value {
    json!({
        "message_hash": item.message_hash,
        "distance": item.distance,
        "risk_score": item.risk_score,
        "decision": item.decision,
        "summary": item.summary
    })
}

fn normalize_message(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    let urls =
        Regex::new(r#"https?://[^\s<>"]+|[a-zA-Z0-9][a-zA-Z0-9\-]*\.[a-zA-Z]{2,}(?:/[^\s<>"]*)?"#)
            .unwrap();
    let emails = Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap();
    let numbers = Regex::new(r"\b\d{4,}\b").unwrap();
    let whitespace = Regex::new(r"\s+").unwrap();

    let text = urls.replace_all(&lower, " <url> ");
    let text = emails.replace_all(&text, " <email> ");
    let text = numbers.replace_all(&text, " <num> ");
    whitespace.replace_all(&text, " ").trim().to_string()
}

fn redact_message(message: &str) -> String {
    let secrets =
        Regex::new(r"(?i)(api[_-]?key|token|secret|password)[^a-zA-Z0-9]{0,10}[A-Za-z0-9_\-]{16,}")
            .unwrap();
    let cards = Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap();
    let phones = Regex::new(r"(?x)\b\+?\d[\d\s().-]{7,}\d\b").unwrap();
    let text = secrets.replace_all(message, "<secret>");
    let text = cards.replace_all(&text, "<card>");
    phones.replace_all(&text, "<phone>").to_string()
}

fn simhash64(message: &str) -> u64 {
    let mut weights = [0_i32; 64];
    for token in message.split_whitespace() {
        let token =
            token.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '<' && ch != '>');
        if token.is_empty() {
            continue;
        }
        let weight = token_weight(token);
        let hash = stable_hash(token);
        for (bit, weight_slot) in weights.iter_mut().enumerate() {
            if (hash >> bit) & 1 == 1 {
                *weight_slot += weight;
            } else {
                *weight_slot -= weight;
            }
        }
    }

    let mut result = 0_u64;
    for (bit, weight) in weights.iter().enumerate() {
        if *weight >= 0 {
            result |= 1_u64 << bit;
        }
    }
    result
}

fn token_weight(token: &str) -> i32 {
    match token {
        "<url>" | "login" | "verify" | "account" | "password" | "wallet" | "payment" => 4,
        "urgent" | "suspended" | "immediately" | "secure" | "update" => 3,
        _ => 1,
    }
}

fn stable_hash(value: &str) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes)
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn parse_simhash(value: &str) -> Option<u64> {
    u64::from_str_radix(value, 16).ok()
}

fn adjustment_for_distance(distance: u32) -> u8 {
    if distance <= 3 {
        35
    } else if distance <= 8 {
        20
    } else if distance <= 12 {
        10
    } else {
        0
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
