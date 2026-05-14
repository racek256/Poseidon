use std::env;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use duckdb::{Connection, params};
use reqwest::blocking::ClientBuilder;
use zip::ZipArchive;

const DEFAULT_TRANCO_URL: &str = "https://tranco-list.eu/top-1m.csv.zip";
const DEFAULT_URL_DB_PATH: &str = "poseidon_urls.duckdb";

fn main() {
    if let Err(err) = run() {
        eprintln!("tranco import failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let db_path =
        env::var("POSEIDON_URL_DB_PATH").unwrap_or_else(|_| DEFAULT_URL_DB_PATH.to_string());
    let limit = env::var("POSEIDON_TRANCO_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    let csv = if let Ok(path) = env::var("POSEIDON_TRANCO_CSV_PATH") {
        read_local(&path)?
    } else {
        let url =
            env::var("POSEIDON_TRANCO_URL").unwrap_or_else(|_| DEFAULT_TRANCO_URL.to_string());
        download_tranco(&url)?
    };

    let conn = Connection::open(Path::new(&db_path)).map_err(|err| err.to_string())?;
    init(&conn).map_err(|err| err.to_string())?;
    conn.execute_batch("BEGIN TRANSACTION; DELETE FROM tranco_domains;")
        .map_err(|err| err.to_string())?;

    let now = unix_now();
    let mut imported = 0_usize;
    for line in csv.lines() {
        if let Some(limit) = limit {
            if imported >= limit {
                break;
            }
        }
        let Some((rank, domain)) = line.split_once(',') else {
            continue;
        };
        let Ok(rank) = rank.trim().parse::<u32>() else {
            continue;
        };
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }
        conn.execute(
            "INSERT INTO tranco_domains (domain, rank, updated_at) VALUES (?1, ?2, ?3)",
            params![domain, rank, now],
        )
        .map_err(|err| err.to_string())?;
        imported += 1;
        if imported % 100_000 == 0 {
            eprintln!("imported {imported} Tranco domains");
        }
    }
    conn.execute_batch("COMMIT;")
        .map_err(|err| err.to_string())?;
    println!("imported {imported} Tranco domains into {db_path}");
    Ok(())
}

fn init(conn: &Connection) -> duckdb::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS tranco_domains (
            domain TEXT PRIMARY KEY,
            rank INTEGER NOT NULL,
            updated_at BIGINT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_tranco_domains_rank ON tranco_domains(rank);",
    )
}

fn read_local(path: &str) -> Result<String, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|err| err.to_string())?
        .read_to_end(&mut bytes)
        .map_err(|err| err.to_string())?;
    if path.ends_with(".zip") {
        unzip_csv(bytes)
    } else {
        String::from_utf8(bytes).map_err(|err| err.to_string())
    }
}

fn download_tranco(url: &str) -> Result<String, String> {
    eprintln!("downloading Tranco list: {url}");
    let bytes = ClientBuilder::new()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent("Poseidon-tranco-importer/0.1")
        .build()
        .map_err(|err| err.to_string())?
        .get(url)
        .send()
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?
        .bytes()
        .map_err(|err| err.to_string())?
        .to_vec();
    unzip_csv(bytes)
}

fn unzip_csv(bytes: Vec<u8>) -> Result<String, String> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).map_err(|err| err.to_string())?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).map_err(|err| err.to_string())?;
        if !file.name().ends_with(".csv") {
            continue;
        }
        let mut csv = String::new();
        file.read_to_string(&mut csv)
            .map_err(|err| err.to_string())?;
        return Ok(csv);
    }
    Err("zip did not contain a csv file".to_string())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
