use std::time::{Duration, SystemTime, UNIX_EPOCH};

use duckdb::{Connection, OptionalExt, params};

use super::feeds::ThreatRecord;

#[derive(Debug)]
pub struct ThreatMatch {
    pub indicator: String,
    pub indicator_type: String,
    pub threat_type: String,
    pub source: String,
    pub confidence: Option<u8>,
}

pub fn init_schema(conn: &Connection) -> duckdb::Result<()> {
    conn.execute_batch(
        "SET preserve_insertion_order=false;
        CREATE SEQUENCE IF NOT EXISTS threats_id_seq START 1;
        CREATE TABLE IF NOT EXISTS threats (
            id BIGINT PRIMARY KEY DEFAULT nextval('threats_id_seq'),
            indicator TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            source TEXT NOT NULL,
            source_ref TEXT,
            first_seen TEXT,
            last_seen TEXT,
            confidence UTINYINT,
            updated_at BIGINT NOT NULL,
            UNIQUE(indicator, indicator_type, threat_type, source)
        );
        CREATE TABLE IF NOT EXISTS threat_tags (
            indicator TEXT NOT NULL,
            source TEXT NOT NULL,
            tag TEXT NOT NULL,
            UNIQUE(indicator, source, tag)
        );
        CREATE TABLE IF NOT EXISTS threat_feed_state (
            source TEXT PRIMARY KEY,
            updated_at BIGINT NOT NULL,
            record_count UBIGINT NOT NULL
        );",
    )
}

pub fn lookup(conn: &Connection, url: &str) -> duckdb::Result<Option<ThreatMatch>> {
    let normalized_url = normalize_url(url);
    let normalized_domain = normalize_domain(url);
    let mut stmt = conn.prepare(
        "SELECT indicator, indicator_type, threat_type, source, confidence
         FROM threats
         WHERE (indicator_type = 'url' AND indicator = ?1)
            OR (indicator_type = 'domain' AND indicator = ?2)
            OR (indicator_type = 'ip' AND indicator = ?2)
         ORDER BY confidence DESC NULLS LAST, updated_at DESC
         LIMIT 1",
    )?;

    stmt.query_row(params![normalized_url, normalized_domain], |row| {
        Ok(ThreatMatch {
            indicator: row.get(0)?,
            indicator_type: row.get(1)?,
            threat_type: row.get(2)?,
            source: row.get(3)?,
            confidence: row.get(4)?,
        })
    })
    .optional()
}

pub fn upsert_records(
    conn: &Connection,
    source: &str,
    records: &[ThreatRecord],
    mut on_record: impl FnMut(usize),
) -> duckdb::Result<()> {
    let now = unix_now();

    conn.execute_batch("BEGIN TRANSACTION")?;

    let result = (|| -> duckdb::Result<()> {
        conn.execute_batch(
            "DROP TABLE IF EXISTS threat_stage;
            DROP TABLE IF EXISTS threat_tag_stage;
            CREATE TEMPORARY TABLE threat_stage (
                indicator TEXT,
                indicator_type TEXT,
                threat_type TEXT,
                source TEXT,
                source_ref TEXT,
                first_seen TEXT,
                last_seen TEXT,
                confidence UTINYINT,
                updated_at BIGINT
            );
            CREATE TEMPORARY TABLE threat_tag_stage (
                indicator TEXT,
                source TEXT,
                tag TEXT
            );",
        )?;

        {
            let mut threat_app = conn.appender("threat_stage")?;
            let mut tag_app = conn.appender("threat_tag_stage")?;

            for (index, record) in records.iter().enumerate() {
                threat_app.append_row(params![
                    record.indicator,
                    record.indicator_type,
                    record.threat_type,
                    record.source,
                    record.source_ref,
                    record.first_seen,
                    record.last_seen,
                    record.confidence,
                    now,
                ])?;
                for tag in &record.tags {
                    tag_app.append_row(params![record.indicator, record.source, tag])?;
                }
                on_record(index + 1);
            }
        }

        conn.execute("DELETE FROM threat_tags WHERE source = ?1", params![source])?;
        conn.execute("DELETE FROM threats WHERE source = ?1", params![source])?;
        conn.execute_batch(
            "INSERT INTO threats (
                indicator, indicator_type, threat_type, source, source_ref,
                first_seen, last_seen, confidence, updated_at
            )
            SELECT
                indicator,
                indicator_type,
                threat_type,
                source,
                min(source_ref),
                min(first_seen),
                max(last_seen),
                max(confidence),
                max(updated_at)
            FROM threat_stage
            GROUP BY indicator, indicator_type, threat_type, source;

            INSERT INTO threat_tags (indicator, source, tag)
            SELECT DISTINCT indicator, source, tag
            FROM threat_tag_stage
            WHERE tag IS NOT NULL AND tag <> '';",
        )?;
        Ok(())
    })();

    match result {
        Ok(()) => conn.execute_batch("COMMIT"),
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

pub fn source_age(conn: &Connection, source: &str) -> duckdb::Result<Option<Duration>> {
    let updated_at: Option<i64> = conn
        .query_row(
            "SELECT updated_at FROM threat_feed_state WHERE source = ?1",
            params![source],
            |row| row.get(0),
        )
        .optional()?;

    Ok(updated_at
        .map(|updated_at| Duration::from_secs(unix_now().saturating_sub(updated_at) as u64)))
}

pub fn mark_source_updated(conn: &Connection, source: &str, count: usize) -> duckdb::Result<()> {
    conn.execute(
        "INSERT INTO threat_feed_state (source, updated_at, record_count) VALUES (?1, ?2, ?3)
         ON CONFLICT(source) DO UPDATE SET
            updated_at = excluded.updated_at,
            record_count = excluded.record_count",
        params![source, unix_now(), count as u64],
    )?;
    Ok(())
}

pub fn normalize_url(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(&['.', ',', ';', ')', ']'][..])
        .to_ascii_lowercase()
}

pub fn normalize_domain(value: &str) -> String {
    let without_scheme = value
        .trim()
        .trim_end_matches(&['.', ',', ';', ')', ']'][..])
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
        .to_ascii_lowercase()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
