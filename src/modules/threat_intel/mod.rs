mod db;
mod feeds;
mod sources;

use std::env;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use duckdb::Connection;

pub use db::{ThreatMatch, normalize_domain};
use feeds::fetch_source;
use sources::feed_sources;

const DEFAULT_UPDATE_MINUTES: u64 = 30;

pub struct ThreatIntel {
    conn: Connection,
    update_interval: Duration,
}

impl ThreatIntel {
    pub fn from_env() -> duckdb::Result<Self> {
        let update_minutes = env::var("POSEIDON_THREAT_UPDATE_MINUTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_UPDATE_MINUTES)
            .max(30);

        let conn = match env::var("POSEIDON_THREAT_DB_PATH") {
            Ok(path) if !path.trim().is_empty() => {
                eprintln!("threat intel db: using persistent DuckDB at {path}");
                Connection::open(Path::new(&path))?
            }
            _ => {
                eprintln!(
                    "threat intel db: using in-memory DuckDB; feeds are downloaded and ingested every startup"
                );
                Connection::open_in_memory()?
            }
        };

        let intel = Self {
            conn,
            update_interval: Duration::from_secs(update_minutes * 60),
        };
        intel.init()?;
        Ok(intel)
    }

    pub fn init(&self) -> duckdb::Result<()> {
        db::init_schema(&self.conn)
    }

    pub fn lookup(&self, url: &str) -> duckdb::Result<Option<ThreatMatch>> {
        db::lookup(&self.conn, url)
    }

    pub fn update_if_due(&self) {
        let sources = feed_sources();
        let total_sources = sources.len();
        let progress = ProgressLine::new();

        let mut completed_sources = 0_usize;

        for source in sources {
            progress.render(
                completed_sources,
                total_sources,
                &format!("checking {}", source.name),
            );
            match db::source_age(&self.conn, source.name) {
                Ok(Some(age)) if age < self.update_interval => {
                    completed_sources += 1;
                    progress.render(
                        completed_sources,
                        total_sources,
                        &format!("cached {}", source.name),
                    );
                    continue;
                }
                Ok(_) => {}
                Err(err) => {
                    eprintln!(
                        "threat intel metadata check failed for {}: {err}",
                        source.name
                    );
                    completed_sources += 1;
                    progress.render(
                        completed_sources,
                        total_sources,
                        &format!("skipped {}", source.name),
                    );
                    continue;
                }
            }

            progress.render(
                completed_sources,
                total_sources,
                &format!("downloading {}", source.name),
            );
            match fetch_source(&source) {
                Ok(records) => {
                    let count = records.len();
                    let progress_step = (count / 100).max(1);
                    progress.render(
                        0,
                        count.max(1),
                        &format!("preparing {} ({count} records)", source.name),
                    );
                    if let Err(err) =
                        db::upsert_records(&self.conn, source.name, &records, |appended| {
                            if appended % progress_step == 0 || appended == count {
                                progress.render(
                                    appended,
                                    count.max(1),
                                    &format!("preparing {} ({count} records)", source.name),
                                );
                            }
                        })
                    {
                        eprintln!("threat intel ingest failed for {}: {err}", source.name);
                        completed_sources += 1;
                        progress.render(
                            completed_sources,
                            total_sources,
                            &format!("failed {}", source.name),
                        );
                        continue;
                    }
                    if let Err(err) = db::mark_source_updated(&self.conn, source.name, count) {
                        eprintln!(
                            "threat intel state update failed for {}: {err}",
                            source.name
                        );
                    }
                }
                Err(err) => eprintln!("threat intel fetch failed for {}: {err}", source.name),
            }
            completed_sources += 1;
            progress.render(
                completed_sources,
                total_sources,
                &format!("done {}", source.name),
            );
        }
        progress.finish(total_sources, "threat db ready");
    }
}

struct ProgressLine;

impl ProgressLine {
    fn new() -> Self {
        Self
    }

    fn render(&self, pos: usize, len: usize, message: &str) {
        let len = len.max(1);
        let width = 40;
        let filled = ((pos.min(len) * width) / len).min(width);
        let bar = format!("{}{}", "=".repeat(filled), " ".repeat(width - filled));
        print!("\r\x1b[2Kthreat db [{bar}] {pos}/{len} {message}");
        let _ = io::stdout().flush();
    }

    fn finish(&self, len: usize, message: &str) {
        self.render(len, len, message);
        println!();
    }
}
