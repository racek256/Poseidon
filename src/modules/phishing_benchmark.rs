use std::time::Instant;

use serde_json::Value;

use crate::modules::message_memory::MessageMemory;
use crate::modules::scoring::{self, Decision};
use crate::modules::threat_intel::ThreatIntel;
use crate::modules::url_db::UrlDb;

const DATASET: &str = include_str!("../../data/benchmarks/phishing_messages.jsonl");

struct Case {
    id: String,
    expected_unsafe: bool,
    message: String,
}

pub fn run() -> Result<(), String> {
    let cases = load_cases()?;
    let threat_intel = ThreatIntel::from_env().map_err(|err| err.to_string())?;
    let url_db = UrlDb::from_env().map_err(|err| err.to_string())?;
    let message_memory = MessageMemory::from_env().map_err(|err| err.to_string())?;
    let ai_enabled = std::env::var("POSEIDON_BENCHMARK_AI")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    let mut true_positive = 0_u32;
    let mut false_positive = 0_u32;
    let mut true_negative = 0_u32;
    let mut false_negative = 0_u32;
    let mut risk_sum = 0_u64;
    let started = Instant::now();

    for case in &cases {
        let user_id = format!("benchmark-{}", case.id);
        let scoring = if ai_enabled {
            scoring::analyse(
                &case.message,
                Some(&user_id),
                &threat_intel,
                &url_db,
                &message_memory,
            )
        } else {
            scoring::analyse_without_ai(
                &case.message,
                Some(&user_id),
                &threat_intel,
                &url_db,
                &message_memory,
            )
        };
        let predicted_unsafe = matches!(
            scoring.decision,
            Decision::WarnR | Decision::WarnB | Decision::Block
        ) || scoring.overall_risk >= 60;
        risk_sum += scoring.overall_risk as u64;

        match (case.expected_unsafe, predicted_unsafe) {
            (true, true) => true_positive += 1,
            (false, true) => {
                false_positive += 1;
                print_failure("false_positive", case, &scoring);
            }
            (false, false) => true_negative += 1,
            (true, false) => {
                false_negative += 1;
                print_failure("false_negative", case, &scoring);
            }
        }
    }

    let total = cases.len() as f64;
    let accuracy = (true_positive + true_negative) as f64 / total;
    let precision = safe_div(true_positive, true_positive + false_positive);
    let recall = safe_div(true_positive, true_positive + false_negative);
    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };
    let elapsed = started.elapsed();

    println!("cases: {}", cases.len());
    println!("true_positive: {true_positive}");
    println!("false_positive: {false_positive}");
    println!("true_negative: {true_negative}");
    println!("false_negative: {false_negative}");
    println!("accuracy: {:.3}", accuracy);
    println!("precision: {:.3}", precision);
    println!("recall: {:.3}", recall);
    println!("f1: {:.3}", f1);
    println!("avg_risk: {:.1}", risk_sum as f64 / total);
    println!("total_ms: {:.1}", elapsed.as_secs_f64() * 1000.0);
    println!(
        "avg_ms_per_case: {:.3}",
        elapsed.as_secs_f64() * 1000.0 / total
    );
    println!("ai_enabled: {ai_enabled}");

    Ok(())
}

fn load_cases() -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();
    for (line_number, line) in DATASET.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|err| format!("invalid benchmark json line {}: {err}", line_number + 1))?;
        cases.push(Case {
            id: value
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("missing id on line {}", line_number + 1))?
                .to_string(),
            expected_unsafe: value
                .get("expected_unsafe")
                .and_then(Value::as_bool)
                .ok_or_else(|| format!("missing expected_unsafe on line {}", line_number + 1))?,
            message: value
                .get("message")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("missing message on line {}", line_number + 1))?
                .to_string(),
        });
    }
    if cases.len() < 100 {
        return Err(format!(
            "benchmark needs at least 100 cases, got {}",
            cases.len()
        ));
    }
    Ok(cases)
}

fn safe_div(numerator: u32, denominator: u32) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn print_failure(kind: &str, case: &Case, scoring: &scoring::Scoring) {
    println!("failure_kind: {kind}");
    println!("id: {}", case.id);
    println!("expected_unsafe: {}", case.expected_unsafe);
    println!("risk: {}", scoring.overall_risk);
    println!("decision: {}", scoring.decision.as_str());
    println!(
        "scores: phishing={} secret={} prompt_injection={} url_reputation={:?} impersonation={} slop_score={}",
        scoring.scores.phishing,
        scoring.scores.secret,
        scoring.scores.prompt_injection,
        scoring.scores.url_reputation,
        scoring.scores.impersonation,
        scoring.scores.slop_score
    );
    println!("flags: {}", scoring.flags.join(" | "));
    println!("message: {}", case.message);
    println!(
        "ai_response: {}",
        scoring.ai_raw_response.as_deref().unwrap_or("<none>")
    );
}
