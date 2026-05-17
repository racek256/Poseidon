use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::modules::tui::bridge;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: &str = "8081";

pub fn ensure() {
    if std::env::var("POSEIDON_LLM_ENDPOINT").is_ok_and(|value| !value.is_empty()) {
        return;
    }

    let host = std::env::var("POSEIDON_LLAMA_HOST").unwrap_or_else(|_| DEFAULT_HOST.to_string());
    let port = std::env::var("POSEIDON_LLAMA_PORT").unwrap_or_else(|_| DEFAULT_PORT.to_string());
    let endpoint = format!("http://{host}:{port}/v1");
    if endpoint_healthy(&endpoint, Duration::from_millis(500)) {
        set_llm_env(&endpoint, None);
        return;
    }

    if let Err(err) = ensure_local_server(&endpoint) {
        bridge::elog(&format!("llama.cpp server unavailable: {err}"));
    }
}

fn ensure_local_server(endpoint: &str) -> Result<(), String> {
    let project_dir = project_dir()?;
    let server = project_dir.join("external/llama.cpp/build/bin/llama-server");
    if !server.is_file() {
        run_setup_script(
            &project_dir.join("scripts/build-llama-server.sh"),
            "building llama.cpp server",
        )?;
        if !server.is_file() {
            return Err(format!(
                "missing {} after build; run scripts/build-llama-server.sh",
                server.display()
            ));
        }
    }

    let model = match find_model(&project_dir) {
        Some(model) => model,
        None => {
            run_setup_script(
                &project_dir.join("scripts/download-model.sh"),
                "downloading default Theseus-v2 GGUF model",
            )?;
            find_model(&project_dir).ok_or_else(|| {
                "no GGUF model found after download; set POSEIDON_LLAMA_MODEL or run scripts/download-model.sh theseus-v2"
                    .to_string()
            })?
        }
    };
    let run_script = project_dir.join("scripts/run-llama-server.sh");
    if !run_script.is_file() {
        return Err(format!("missing {}", run_script.display()));
    }

    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(project_dir.join("llama-server.log"))
        .map_err(|err| err.to_string())?;
    let err_log = log.try_clone().map_err(|err| err.to_string())?;

    Command::new("bash")
        .arg(&run_script)
        .env("POSEIDON_LLAMA_MODEL", &model)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err_log))
        .spawn()
        .map_err(|err| format!("failed to start llama-server: {err}"))?;

    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        if endpoint_healthy(endpoint, Duration::from_secs(1)) {
            set_llm_env(endpoint, Some(&model));
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    Err("llama-server did not become healthy within 30s".to_string())
}

fn run_setup_script(script: &Path, description: &str) -> Result<(), String> {
    if std::env::var("POSEIDON_LLAMA_AUTO_SETUP").is_ok_and(|value| value == "false") {
        return Err(format!(
            "{description} skipped because POSEIDON_LLAMA_AUTO_SETUP=false"
        ));
    }
    if !script.is_file() {
        return Err(format!("missing {}", script.display()));
    }

    bridge::elog(&format!("llama.cpp setup: {description}"));
    let status = Command::new("bash")
        .arg(script)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| format!("failed to run {}: {err}", script.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{} exited with {status}", script.display()))
    }
}

fn project_dir() -> Result<PathBuf, String> {
    std::env::current_dir().map_err(|err| err.to_string())
}

fn find_model(project_dir: &Path) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("POSEIDON_LLAMA_MODEL") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }

    let models_dir = std::env::var("POSEIDON_MODELS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| project_dir.join("models"));
    for name in [
        "Theseus-v2-1e.gguf",
        "Theseus-1e-q4_k_m.gguf",
        "gemma-3-1b-it-Q4_K_M.gguf",
        "gemma-3-1b-it-Q4_0.gguf",
    ] {
        let path = models_dir.join(name);
        if path.is_file() {
            return Some(path);
        }
    }
    let mut models = fs::read_dir(models_dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "gguf"))
        .collect::<Vec<_>>();
    models.sort();
    models.into_iter().next()
}

fn endpoint_healthy(endpoint: &str, timeout: Duration) -> bool {
    let url = endpoint.trim_end_matches("/v1").trim_end_matches('/');
    let Ok(client) = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
    else {
        return false;
    };
    client
        .get(format!("{url}/health"))
        .send()
        .is_ok_and(|response| response.status().is_success())
}

fn set_llm_env(endpoint: &str, model: Option<&Path>) {
    // Called during single-threaded startup before request handling begins.
    unsafe {
        std::env::set_var("POSEIDON_LLM_ENDPOINT", endpoint);
        if std::env::var("POSEIDON_OLLAMA_MODEL").is_err() {
            let model_name = model
                .and_then(Path::file_stem)
                .and_then(|name| name.to_str())
                .unwrap_or("local-gguf");
            std::env::set_var("POSEIDON_OLLAMA_MODEL", model_name);
        }
    }
}
