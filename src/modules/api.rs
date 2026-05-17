use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use serde_json::{Value, json};

use crate::modules::message_memory::MessageMemory;
use crate::modules::scoring::analyse;
use crate::modules::supply_chain;
use crate::modules::threat_intel::ThreatIntel;
use crate::modules::tui::bridge;
use crate::modules::url_db::UrlDb;

const MAX_BODY_BYTES: usize = 1024 * 1024;
const WEB_HTML: &str = include_str!("../web/index.html");
const WEB_CSS: &str = include_str!("../web/styles.css");
const WEB_JS: &str = include_str!("../web/app.js");

pub fn serve(
    addr: &str,
    threat_intel: &ThreatIntel,
    url_db: &UrlDb,
    message_memory: &MessageMemory,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    bridge::log(&format!("API server listening on http://{addr}"));

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if let Err(err) =
                    handle_connection(&mut stream, threat_intel, url_db, message_memory)
                {
                    let body = json!({ "error": err.to_string() });
                    let _ = write_json(&mut stream, 500, &body);
                }
            }
            Err(err) => bridge::elog(&format!("connection failed: {err}")),
        }
    }

    Ok(())
}

fn handle_connection(
    stream: &mut TcpStream,
    threat_intel: &ThreatIntel,
    url_db: &UrlDb,
    message_memory: &MessageMemory,
) -> std::io::Result<()> {
    let request = read_request(stream)?;
    let Some((head, body)) = request.split_once("\r\n\r\n") else {
        return write_json(stream, 400, &json!({ "error": "invalid http request" }));
    };

    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return write_json(stream, 400, &json!({ "error": "invalid request line" }));
    }

    match (parts[0], parts[1]) {
        ("GET", "/") | ("GET", "/web") | ("GET", "/web/") => {
            write_response(stream, 200, "text/html; charset=utf-8", WEB_HTML)
        }
        ("GET", "/web/styles.css") => {
            write_response(stream, 200, "text/css; charset=utf-8", WEB_CSS)
        }
        ("GET", "/web/app.js") => {
            write_response(stream, 200, "application/javascript; charset=utf-8", WEB_JS)
        }
        ("GET", "/health") => write_json(stream, 200, &json!({ "ok": true })),
        ("POST", "/analyse") | ("POST", "/analyze") => {
            bridge::post_log(&format!("Handling request: {}", parts[1]));
            analyse_request(stream, body, threat_intel, url_db, message_memory)
        }
        _ if parts[1].starts_with("/supplychain") => {
            supply_chain_request(stream, parts[0], parts[1], body)
        }
        _ => write_json(stream, 404, &json!({ "error": "not found" })),
    }
}

fn analyse_request(
    stream: &mut TcpStream,
    body: &str,
    threat_intel: &ThreatIntel,
    url_db: &UrlDb,
    message_memory: &MessageMemory,
) -> std::io::Result<()> {
    let value: Value = match serde_json::from_str(body) {
        Ok(value) => value,
        Err(err) => {
            return write_json(
                stream,
                400,
                &json!({ "error": format!("invalid json: {err}") }),
            );
        }
    };
    let Some(message) = value.get("message").and_then(Value::as_str) else {
        return write_json(
            stream,
            400,
            &json!({ "error": "missing string field: message" }),
        );
    };
    let user_id = value.get("user_id").and_then(Value::as_str);
    let compare_ai_only = value
        .get("compare_ai_only")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Track request start
    let track_start = bridge::track_request_start();
    bridge::post_log("Received analyse request");

    let scoring = analyse(message, user_id, threat_intel, url_db, message_memory);

    // Track request end
    bridge::track_request_end(track_start);

    // Post output to TUI
    let result_json = if compare_ai_only {
        json!({
            "compare_ai_only": true,
            "ai_only": ai_only_json(&scoring),
            "full": scoring.to_json()
        })
    } else {
        scoring.to_json()
    };
    bridge::post_output(&format!(
        "Decision: {} | Risk: {}",
        scoring.decision.as_str(),
        scoring.overall_risk
    ));
    bridge::post_log(&format!(
        "Analysis complete: decision={}, risk={}",
        scoring.decision.as_str(),
        scoring.overall_risk
    ));

    write_json(stream, 200, &result_json)
}

fn ai_only_json(scoring: &crate::modules::scoring::Scoring) -> Value {
    let raw = scoring.ai_raw_response.as_deref().unwrap_or_default();
    let parsed = serde_json::from_str::<Value>(raw).unwrap_or_else(|_| json!({}));
    let phishing = json_score(&parsed, "phishing");
    let impersonation = json_score(&parsed, "impersonation");
    let risk = json_score(&parsed, "risk");
    let confidence = json_score(&parsed, "confidence");
    let flags = parsed
        .get("flags")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let overall_risk = phishing.max(impersonation).max(risk);
    let decision = if overall_risk >= 85 {
        "block"
    } else if overall_risk >= 65 {
        "warn_both"
    } else if overall_risk >= 45 {
        "warn_sender"
    } else {
        "allow"
    };
    json!({
        "decision": decision,
        "overall_risk": overall_risk,
        "scores": {
            "phishing": phishing,
            "impersonation": impersonation,
            "risk": risk,
            "confidence": confidence
        },
        "flags": flags,
        "ai_raw_response": scoring.ai_raw_response
    })
}

fn json_score(value: &Value, key: &str) -> u8 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_default()
        .min(100) as u8
}

fn supply_chain_request(
    stream: &mut TcpStream,
    method: &str,
    path: &str,
    body: &str,
) -> std::io::Result<()> {
    match (method, path) {
        ("POST", "/supplychain/quick-analyze") => {
            let result = supply_chain::handle_quick_analyze(body);
            write_json(stream, 200, &result)
        }
        ("POST", "/supplychain/deep-analyze") => {
            let result = supply_chain::handle_deep_analyze(body);
            write_json(stream, 200, &result)
        }
        ("GET", "/supplychain/status") => {
            let result = supply_chain::handle_status();
            write_json(stream, 200, &result)
        }
        _ => write_json(
            stream,
            404,
            &json!({ "error": "supply chain endpoint not found" }),
        ),
    }
}

fn read_request(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut buffer = Vec::new();
    let mut temp = [0_u8; 4096];

    loop {
        let read = stream.read(&mut temp)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&temp[..read]);

        if buffer.len() > MAX_BODY_BYTES {
            break;
        }

        if let Some(header_end) = find_header_end(&buffer) {
            let headers = String::from_utf8_lossy(&buffer[..header_end]);
            let content_length = content_length(&headers).unwrap_or(0);
            let request_len = header_end + 4 + content_length;
            while buffer.len() < request_len && buffer.len() <= MAX_BODY_BYTES {
                let read = stream.read(&mut temp)?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&temp[..read]);
            }
            break;
        }
    }

    Ok(String::from_utf8_lossy(&buffer).to_string())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> Option<usize> {
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    })
}

fn write_json(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    write_response(stream, status, "application/json", &body.to_string())
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {status_text}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}
