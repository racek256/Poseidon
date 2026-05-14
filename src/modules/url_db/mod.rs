use std::env;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use duckdb::{Connection, OptionalExt, params};
use sha2::{Digest, Sha256};

use crate::modules::threat_intel::normalize_domain;
use crate::modules::url_analysis::brand::BrandImpersonation;
use crate::modules::url_analysis::brand_detector::{BrandCandidate, DomainRelationship};
use crate::modules::url_analysis::domain::parse_url_parts;

const DEFAULT_URL_DB_PATH: &str = "poseidon_urls.duckdb";

pub struct UrlDb {
    conn: Connection,
}

#[derive(Debug)]
pub struct UrlIdentity {
    pub normalized_url: String,
    pub domain: String,
    pub url_hash: String,
    pub domain_hash: String,
    pub host_hash: String,
}

#[derive(Debug)]
pub struct UrlLookup {
    pub verdict: String,
    pub confidence: u8,
    pub risk_score: u8,
    pub tags: Vec<String>,
    pub brand_impersonation: Option<StoredBrandImpersonation>,
}

#[derive(Debug)]
pub struct StoredBrandImpersonation {
    pub matched_brand: Option<String>,
    pub official: bool,
    pub hosting_provider: Option<String>,
    pub score: u8,
    pub confidence: u8,
    pub risk_level: String,
    pub reasons_json: String,
    pub safe_evidence_json: String,
}

#[derive(Debug)]
pub struct QueuedUrl {
    pub id: i64,
    pub raw_url: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DomainReputation {
    pub safe_observations: u64,
    pub bad_observations: u64,
    pub boost: u8,
}

impl UrlDb {
    pub fn from_env() -> duckdb::Result<Self> {
        let path =
            env::var("POSEIDON_URL_DB_PATH").unwrap_or_else(|_| DEFAULT_URL_DB_PATH.to_string());
        eprintln!("url db: using DuckDB at {path}");
        let db = Self {
            conn: Connection::open(Path::new(&path))?,
        };
        db.init()?;
        Ok(db)
    }

    pub fn init(&self) -> duckdb::Result<()> {
        self.conn.execute_batch(
            "SET preserve_insertion_order=false;
            CREATE SEQUENCE IF NOT EXISTS url_queue_id_seq START 1;
            CREATE TABLE IF NOT EXISTS url_observations (
                url_hash TEXT PRIMARY KEY,
                domain_hash TEXT NOT NULL,
                host_hash TEXT NOT NULL,
                first_seen BIGINT NOT NULL,
                last_seen BIGINT NOT NULL,
                seen_count UBIGINT NOT NULL,
                verdict TEXT NOT NULL,
                confidence UTINYINT NOT NULL,
                risk_score UTINYINT NOT NULL,
                source TEXT NOT NULL,
                updated_at BIGINT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_url_observations_domain_hash ON url_observations(domain_hash);

            CREATE TABLE IF NOT EXISTS url_tags (
                url_hash TEXT NOT NULL,
                tag TEXT NOT NULL,
                confidence UTINYINT,
                source TEXT NOT NULL,
                updated_at BIGINT NOT NULL,
                UNIQUE(url_hash, tag, source)
            );
            CREATE INDEX IF NOT EXISTS idx_url_tags_url_hash ON url_tags(url_hash);

            CREATE TABLE IF NOT EXISTS url_analysis_queue (
                id BIGINT PRIMARY KEY DEFAULT nextval('url_queue_id_seq'),
                url_hash TEXT NOT NULL,
                domain_hash TEXT NOT NULL,
                raw_url TEXT,
                status TEXT NOT NULL,
                attempts UTINYINT NOT NULL,
                priority UTINYINT NOT NULL,
                reason TEXT NOT NULL,
                created_at BIGINT NOT NULL,
                updated_at BIGINT NOT NULL,
                last_error TEXT,
                UNIQUE(url_hash, status)
            );
            CREATE INDEX IF NOT EXISTS idx_url_queue_status_priority ON url_analysis_queue(status, priority);

            CREATE TABLE IF NOT EXISTS url_evidence (
                url_hash TEXT NOT NULL,
                kind TEXT NOT NULL,
                key TEXT NOT NULL,
                value_hash TEXT,
                value_text TEXT,
                score UTINYINT,
                source TEXT NOT NULL,
                created_at BIGINT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_url_evidence_url_hash ON url_evidence(url_hash);

            CREATE TABLE IF NOT EXISTS brand_impersonation_results (
                url_hash TEXT PRIMARY KEY,
                domain_hash TEXT NOT NULL,
                matched_brand TEXT,
                official BOOLEAN NOT NULL,
                hosting_provider TEXT,
                score UTINYINT NOT NULL,
                confidence UTINYINT NOT NULL,
                risk_level TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                safe_evidence_json TEXT NOT NULL,
                updated_at BIGINT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tranco_domains (
                domain TEXT PRIMARY KEY,
                rank INTEGER NOT NULL,
                updated_at BIGINT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tranco_domains_rank ON tranco_domains(rank);

            CREATE TABLE IF NOT EXISTS brand_candidates (
                brand_key TEXT NOT NULL,
                display_name TEXT NOT NULL,
                primary_domain TEXT NOT NULL,
                domain_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                confidence UTINYINT NOT NULL,
                tranco_rank INTEGER,
                evidence_json TEXT NOT NULL,
                first_seen BIGINT NOT NULL,
                updated_at BIGINT NOT NULL,
                UNIQUE(brand_key, domain_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_brand_candidates_domain_hash ON brand_candidates(domain_hash);

            CREATE TABLE IF NOT EXISTS brand_domains (
                brand_key TEXT NOT NULL,
                domain TEXT NOT NULL,
                domain_hash TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                confidence UTINYINT NOT NULL,
                source TEXT NOT NULL,
                evidence_json TEXT,
                updated_at BIGINT NOT NULL,
                UNIQUE(brand_key, domain_hash, relation_type)
            );

            CREATE TABLE IF NOT EXISTS domain_relationships (
                source_domain TEXT NOT NULL,
                source_domain_hash TEXT NOT NULL,
                related_domain TEXT NOT NULL,
                related_domain_hash TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                confidence UTINYINT NOT NULL,
                evidence_json TEXT,
                updated_at BIGINT NOT NULL,
                UNIQUE(source_domain_hash, related_domain_hash, relation_type)
            );

            CREATE TABLE IF NOT EXISTS domain_reputation (
                domain_hash TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                safe_observations UBIGINT NOT NULL,
                bad_observations UBIGINT NOT NULL,
                first_seen BIGINT NOT NULL,
                last_seen BIGINT NOT NULL,
                updated_at BIGINT NOT NULL
            );",
        )
    }

    pub fn identity(&self, url: &str) -> UrlIdentity {
        let normalized_url = normalize_url(url);
        let domain = normalize_domain(&normalized_url);
        UrlIdentity {
            url_hash: hash_value(&normalized_url),
            domain_hash: hash_value(&domain),
            host_hash: hash_value(&domain),
            normalized_url,
            domain,
        }
    }

    pub fn lookup(&self, identity: &UrlIdentity) -> duckdb::Result<Option<UrlLookup>> {
        let row = self
            .conn
            .query_row(
                "SELECT verdict, confidence, risk_score FROM url_observations WHERE url_hash = ?1",
                params![identity.url_hash],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u8>(1)?,
                        row.get::<_, u8>(2)?,
                    ))
                },
            )
            .optional()?;

        let Some((verdict, confidence, risk_score)) = row else {
            return Ok(None);
        };

        Ok(Some(UrlLookup {
            verdict,
            confidence,
            risk_score,
            tags: self.tags(&identity.url_hash)?,
            brand_impersonation: self.brand_impersonation(&identity.url_hash)?,
        }))
    }

    pub fn enqueue_unknown(
        &self,
        identity: &UrlIdentity,
        raw_url: &str,
        priority: u8,
        reason: &str,
    ) -> duckdb::Result<bool> {
        let now = unix_now();
        let changed = self.conn.execute(
            "INSERT INTO url_analysis_queue (
                url_hash, domain_hash, raw_url, status, attempts, priority, reason, created_at, updated_at
            ) VALUES (?1, ?2, ?3, 'pending', 0, ?4, ?5, ?6, ?6)
            ON CONFLICT(url_hash, status) DO NOTHING",
            params![
                identity.url_hash,
                identity.domain_hash,
                raw_url,
                priority,
                reason,
                now
            ],
        )?;
        Ok(changed > 0)
    }

    pub fn enqueue_analysis(
        &self,
        identity: &UrlIdentity,
        raw_url: &str,
        priority: u8,
        reason: &str,
    ) -> duckdb::Result<bool> {
        self.enqueue_unknown(identity, raw_url, priority, reason)
    }

    pub fn store_brand_impersonation(
        &self,
        identity: &UrlIdentity,
        result: &BrandImpersonation,
    ) -> duckdb::Result<()> {
        let now = unix_now();
        let reasons = serde_json::to_string(&result.reasons).unwrap_or_else(|_| "[]".to_string());
        let safe_evidence =
            serde_json::to_string(&result.safe_evidence).unwrap_or_else(|_| "[]".to_string());

        self.conn.execute(
            "INSERT INTO brand_impersonation_results (
                url_hash, domain_hash, matched_brand, official, hosting_provider, score,
                confidence, risk_level, reasons_json, safe_evidence_json, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            ON CONFLICT(url_hash) DO UPDATE SET
                domain_hash = excluded.domain_hash,
                matched_brand = excluded.matched_brand,
                official = excluded.official,
                hosting_provider = excluded.hosting_provider,
                score = excluded.score,
                confidence = excluded.confidence,
                risk_level = excluded.risk_level,
                reasons_json = excluded.reasons_json,
                safe_evidence_json = excluded.safe_evidence_json,
                updated_at = excluded.updated_at",
            params![
                identity.url_hash,
                identity.domain_hash,
                result.matched_brand,
                result.official,
                result.hosting_provider,
                result.score,
                result.confidence,
                result.risk_level,
                reasons,
                safe_evidence,
                now
            ],
        )?;

        Ok(())
    }

    pub fn store_observation(
        &self,
        identity: &UrlIdentity,
        verdict: &str,
        confidence: u8,
        risk_score: u8,
        source: &str,
    ) -> duckdb::Result<()> {
        let now = unix_now();
        self.conn.execute(
            "INSERT INTO url_observations (
                url_hash, domain_hash, host_hash, first_seen, last_seen, seen_count,
                verdict, confidence, risk_score, source, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?4, 1, ?5, ?6, ?7, ?8, ?4)
            ON CONFLICT(url_hash) DO UPDATE SET
                last_seen = excluded.last_seen,
                seen_count = url_observations.seen_count + 1,
                verdict = excluded.verdict,
                confidence = excluded.confidence,
                risk_score = excluded.risk_score,
                source = excluded.source,
                updated_at = excluded.updated_at",
            params![
                identity.url_hash,
                identity.domain_hash,
                identity.host_hash,
                now,
                verdict,
                confidence,
                risk_score,
                source
            ],
        )?;
        Ok(())
    }

    pub fn add_tag(
        &self,
        identity: &UrlIdentity,
        tag: &str,
        confidence: Option<u8>,
        source: &str,
    ) -> duckdb::Result<()> {
        self.conn.execute(
            "INSERT INTO url_tags (url_hash, tag, confidence, source, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(url_hash, tag, source) DO UPDATE SET
                confidence = excluded.confidence,
                updated_at = excluded.updated_at",
            params![identity.url_hash, tag, confidence, source, unix_now()],
        )?;
        Ok(())
    }

    pub fn add_evidence(
        &self,
        identity: &UrlIdentity,
        kind: &str,
        key: &str,
        value_text: Option<&str>,
        score: Option<u8>,
        source: &str,
    ) -> duckdb::Result<()> {
        let value_hash = value_text.map(hash_value);
        self.conn.execute(
            "INSERT INTO url_evidence (
                url_hash, kind, key, value_hash, value_text, score, source, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                identity.url_hash,
                kind,
                key,
                value_hash,
                value_text,
                score,
                source,
                unix_now()
            ],
        )?;
        Ok(())
    }

    pub fn observe_domain_reputation(
        &self,
        identity: &UrlIdentity,
        safe: bool,
    ) -> duckdb::Result<DomainReputation> {
        let now = unix_now();
        let domain = reputation_domain(&identity.domain);
        let domain_hash = hash_value(&domain);
        let safe_increment = u64::from(safe);
        let bad_increment = u64::from(!safe);
        self.conn.execute(
            "INSERT INTO domain_reputation (
                domain_hash, domain, safe_observations, bad_observations, first_seen, last_seen, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5)
             ON CONFLICT(domain_hash) DO UPDATE SET
                domain = excluded.domain,
                safe_observations = domain_reputation.safe_observations + excluded.safe_observations,
                bad_observations = domain_reputation.bad_observations + excluded.bad_observations,
                last_seen = excluded.last_seen,
                updated_at = excluded.updated_at",
            params![
                domain_hash,
                domain,
                safe_increment,
                bad_increment,
                now
            ],
        )?;
        self.domain_reputation(&domain)
    }

    pub fn domain_reputation(&self, domain: &str) -> duckdb::Result<DomainReputation> {
        let domain = reputation_domain(domain);
        let domain_hash = hash_value(&domain);
        let row = self
            .conn
            .query_row(
                "SELECT safe_observations, bad_observations
                 FROM domain_reputation
                 WHERE domain_hash = ?1",
                params![domain_hash],
                |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
            )
            .optional()?;

        let Some((safe_observations, bad_observations)) = row else {
            return Ok(DomainReputation::default());
        };

        Ok(DomainReputation {
            safe_observations,
            bad_observations,
            boost: local_reputation_boost(safe_observations, bad_observations),
        })
    }

    pub fn claim_pending(&self, limit: usize) -> duckdb::Result<Vec<QueuedUrl>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, raw_url
             FROM url_analysis_queue
             WHERE status = 'pending' AND raw_url IS NOT NULL
             ORDER BY priority DESC, created_at ASC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(QueuedUrl {
                id: row.get(0)?,
                raw_url: row.get(1)?,
            })
        })?;

        let mut queued = Vec::new();
        for row in rows {
            queued.push(row?);
        }

        for item in &queued {
            self.conn.execute(
                "UPDATE url_analysis_queue SET status = 'processing', attempts = attempts + 1, updated_at = ?1 WHERE id = ?2",
                params![unix_now(), item.id],
            )?;
        }

        Ok(queued)
    }

    pub fn mark_done(&self, queue_id: i64) -> duckdb::Result<()> {
        self.conn.execute(
            "DELETE FROM url_analysis_queue
             WHERE status = 'done'
               AND id <> ?1
               AND url_hash = (SELECT url_hash FROM url_analysis_queue WHERE id = ?1)",
            params![queue_id],
        )?;
        self.conn.execute(
            "UPDATE url_analysis_queue SET status = 'done', raw_url = NULL, updated_at = ?1 WHERE id = ?2",
            params![unix_now(), queue_id],
        )?;
        Ok(())
    }

    pub fn mark_failed(&self, queue_id: i64, err: &str) -> duckdb::Result<()> {
        self.conn.execute(
            "UPDATE url_analysis_queue SET status = 'failed', last_error = ?1, updated_at = ?2 WHERE id = ?3",
            params![err, unix_now(), queue_id],
        )?;
        Ok(())
    }

    pub fn tranco_rank(&self, domain: &str) -> duckdb::Result<Option<u32>> {
        self.conn
            .query_row(
                "SELECT rank FROM tranco_domains WHERE domain = ?1",
                params![domain],
                |row| row.get::<_, u32>(0),
            )
            .optional()
    }

    pub fn store_brand_candidate(&self, candidate: &BrandCandidate) -> duckdb::Result<()> {
        let now = unix_now();
        self.conn.execute(
            "INSERT INTO brand_candidates (
                brand_key, display_name, primary_domain, domain_hash, status, confidence,
                tranco_rank, evidence_json, first_seen, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)
            ON CONFLICT(brand_key, domain_hash) DO UPDATE SET
                display_name = excluded.display_name,
                primary_domain = excluded.primary_domain,
                status = excluded.status,
                confidence = excluded.confidence,
                tranco_rank = excluded.tranco_rank,
                evidence_json = excluded.evidence_json,
                updated_at = excluded.updated_at",
            params![
                candidate.brand_key,
                candidate.display_name,
                candidate.primary_domain,
                hash_value(&candidate.primary_domain),
                candidate.status,
                candidate.confidence,
                candidate.tranco_rank,
                candidate.evidence_json,
                now
            ],
        )?;

        self.conn.execute(
            "INSERT INTO brand_domains (
                brand_key, domain, domain_hash, relation_type, confidence, source, evidence_json, updated_at
            ) VALUES (?1, ?2, ?3, 'primary_domain', ?4, 'brand_detector', ?5, ?6)
            ON CONFLICT(brand_key, domain_hash, relation_type) DO UPDATE SET
                confidence = excluded.confidence,
                evidence_json = excluded.evidence_json,
                updated_at = excluded.updated_at",
            params![
                candidate.brand_key,
                candidate.primary_domain,
                hash_value(&candidate.primary_domain),
                candidate.confidence,
                candidate.evidence_json,
                now
            ],
        )?;

        Ok(())
    }

    pub fn store_domain_relationship(&self, relation: &DomainRelationship) -> duckdb::Result<()> {
        let now = unix_now();
        self.conn.execute(
            "INSERT INTO domain_relationships (
                source_domain, source_domain_hash, related_domain, related_domain_hash,
                relation_type, confidence, evidence_json, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(source_domain_hash, related_domain_hash, relation_type) DO UPDATE SET
                confidence = excluded.confidence,
                evidence_json = excluded.evidence_json,
                updated_at = excluded.updated_at",
            params![
                relation.source_domain,
                hash_value(&relation.source_domain),
                relation.related_domain,
                hash_value(&relation.related_domain),
                relation.relation_type,
                relation.confidence,
                relation.evidence_json,
                now
            ],
        )?;
        Ok(())
    }

    pub fn print_brand_learning_summary(&self) -> duckdb::Result<()> {
        println!("brand learning tables");
        println!("tranco_domains: {}", self.count_table("tranco_domains")?);
        println!(
            "brand_candidates: {}",
            self.count_table("brand_candidates")?
        );
        println!("brand_domains: {}", self.count_table("brand_domains")?);
        println!(
            "domain_relationships: {}",
            self.count_table("domain_relationships")?
        );
        println!(
            "domain_reputation: {}",
            self.count_table("domain_reputation")?
        );
        println!();

        println!("recent brand_candidates");
        let mut stmt = self.conn.prepare(
            "SELECT display_name, primary_domain, status, confidence, tranco_rank
             FROM brand_candidates
             ORDER BY updated_at DESC
             LIMIT 20",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u8>(3)?,
                row.get::<_, Option<u32>>(4)?,
            ))
        })?;
        for row in rows {
            let (name, domain, status, confidence, tranco_rank) = row?;
            println!(
                "{name} | {domain} | {status} | confidence={confidence} | tranco_rank={tranco_rank:?}"
            );
        }
        println!();

        println!("recent brand_domains");
        let mut stmt = self.conn.prepare(
            "SELECT brand_key, domain, relation_type, confidence, source
             FROM brand_domains
             ORDER BY updated_at DESC
             LIMIT 20",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u8>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (brand_key, domain, relation_type, confidence, source) = row?;
            println!(
                "{brand_key} | {domain} | {relation_type} | confidence={confidence} | source={source}"
            );
        }
        println!();

        println!("recent domain_relationships");
        let mut stmt = self.conn.prepare(
            "SELECT source_domain, related_domain, relation_type, confidence
             FROM domain_relationships
             ORDER BY updated_at DESC
             LIMIT 20",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u8>(3)?,
            ))
        })?;
        for row in rows {
            let (source, related, relation_type, confidence) = row?;
            println!("{source} -> {related} | {relation_type} | confidence={confidence}");
        }

        Ok(())
    }

    pub fn print_domain_reputation(&self, domain: &str) -> duckdb::Result<()> {
        let reputation = self.domain_reputation(domain)?;
        println!(
            "domain={domain} safe_observations={} bad_observations={} boost={}",
            reputation.safe_observations, reputation.bad_observations, reputation.boost
        );
        Ok(())
    }

    fn count_table(&self, table: &str) -> duckdb::Result<u64> {
        let sql = format!("SELECT COUNT(*) FROM {table}");
        self.conn.query_row(&sql, [], |row| row.get(0))
    }

    fn tags(&self, url_hash: &str) -> duckdb::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT tag FROM url_tags WHERE url_hash = ?1 ORDER BY tag")?;
        let rows = stmt.query_map(params![url_hash], |row| row.get(0))?;
        let mut tags = Vec::new();
        for row in rows {
            tags.push(row?);
        }
        Ok(tags)
    }

    fn brand_impersonation(
        &self,
        url_hash: &str,
    ) -> duckdb::Result<Option<StoredBrandImpersonation>> {
        self.conn
            .query_row(
                "SELECT matched_brand, official, hosting_provider, score, confidence, risk_level,
                    reasons_json, safe_evidence_json
                 FROM brand_impersonation_results
                 WHERE url_hash = ?1",
                params![url_hash],
                |row| {
                    Ok(StoredBrandImpersonation {
                        matched_brand: row.get(0)?,
                        official: row.get(1)?,
                        hosting_provider: row.get(2)?,
                        score: row.get(3)?,
                        confidence: row.get(4)?,
                        risk_level: row.get(5)?,
                        reasons_json: row.get(6)?,
                        safe_evidence_json: row.get(7)?,
                    })
                },
            )
            .optional()
    }
}

fn normalize_url(url: &str) -> String {
    url.trim()
        .trim_end_matches(&['.', ',', ';', ')', ']'][..])
        .to_ascii_lowercase()
}

fn hash_value(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn reputation_domain(value: &str) -> String {
    parse_url_parts(value).registrable_domain
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn local_reputation_boost(safe_observations: u64, bad_observations: u64) -> u8 {
    if bad_observations > 0 {
        return 0;
    }
    if safe_observations >= 250 {
        15
    } else if safe_observations >= 75 {
        10
    } else if safe_observations >= 25 {
        5
    } else {
        0
    }
}
