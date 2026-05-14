use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use serde_json::{Value, json};

use crate::modules::message_memory::MessageMemory;
use crate::modules::scoring::analyse;
use crate::modules::threat_intel::ThreatIntel;
use crate::modules::url_db::UrlDb;

const MAX_BODY_BYTES: usize = 1024 * 1024;

pub fn serve(
    addr: &str,
    threat_intel: &ThreatIntel,
    url_db: &UrlDb,
    message_memory: &MessageMemory,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    println!("poseidon api listening on http://{addr}");

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
            Err(err) => eprintln!("connection failed: {err}"),
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
        ("GET", "/health") => write_json(stream, 200, &json!({ "ok": true })),
        ("POST", "/analyse") | ("POST", "/analyze") => {
            analyse_request(stream, body, threat_intel, url_db, message_memory)
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

    let scoring = analyse(message, user_id, threat_intel, url_db, message_memory);
    write_json(stream, 200, &scoring.to_json())
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
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let body = body.to_string();
    write!(
        stream,
        "HTTP/1.1 {status} {status_text}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}
