# Poseidon
Project repository for AT&amp;T hackathon.

## Threat Intel

Poseidon loads a local DuckDB threat-intelligence store before URL WHOIS checks. It defaults to an in-memory database and refreshes feeds no more often than every 30 minutes.

- `POSEIDON_THREAT_DB_PATH=/path/to/poseidon.duckdb` enables file-backed persistence.
- `POSEIDON_THREAT_UPDATE_MINUTES=30` controls the refresh interval. Values below 30 are clamped to 30 minutes.
