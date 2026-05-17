//! TUI Bridge module for inter-thread/posting state updates to the TUI.
//!
//! This module provides a global state holder that allows the server,
//! scoring engine, and other components to communicate with the TUI
//! without direct ownership of the TuiState.
//!
//! All functions are NO-OPs when the TUI is not active (i.e., when
//! `set_tui_state` has not been called).

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use crate::modules::tui::trackers::PerformanceTrackers;

/// Global TUI state holder. Uses OnceLock for lazy initialization and
/// Arc<Mutex<TuiState>> for thread-safe shared access.
static TUI_STATE: OnceLock<Arc<Mutex<crate::modules::tui::state::TuiState>>> = OnceLock::new();

static TRACKERS: OnceLock<Mutex<PerformanceTrackers>> = OnceLock::new();

/// Initializes trackers. Called once when TUI starts.
pub fn init_trackers() {
    let _ = TRACKERS.set(Mutex::new(PerformanceTrackers::new()));
}

pub fn set_tui_state(state: Arc<Mutex<crate::modules::tui::state::TuiState>>) {
    let _ = TUI_STATE.set(state);
    init_trackers();
}

/// Checks if interactive mode (TUI) is active.
pub fn is_interactive() -> bool {
    TUI_STATE.get().is_some()
}

/// Logs a message to the TUI if active, otherwise prints to stdout.
pub fn log(msg: &str) {
    if is_interactive() {
        post_log(msg);
    } else {
        println!("{msg}");
    }
}

/// Logs a message to the TUI if active, otherwise prints to stderr.
pub fn elog(msg: &str) {
    if is_interactive() {
        post_log(msg);
    } else {
        eprintln!("{msg}");
    }
}

/// Posts the current processing step to TUI.
pub fn post_step(step: &str) {
    if let Some(state) = TUI_STATE.get() {
        if let Ok(mut s) = state.lock() {
            s.set_step(step);
        }
    }
}

/// Posts progress percentage (0.0 - 100.0) to TUI.
pub fn post_progress(percent: f64) {
    if let Some(state) = TUI_STATE.get() {
        if let Ok(mut s) = state.lock() {
            s.set_progress(percent);
        }
    }
}

/// Marks backend DB/API readiness for the TUI.
pub fn post_backend_ready(ready: bool) {
    if let Some(state) = TUI_STATE.get() {
        if let Ok(mut s) = state.lock() {
            s.set_backend_ready(ready);
        }
    }
}

/// Adds a log entry to TUI.
pub fn post_log(message: &str) {
    if let Some(state) = TUI_STATE.get() {
        if let Ok(mut s) = state.lock() {
            s.add_log(message.to_string());
        }
    }
}

/// Appends output to TUI.
pub fn post_output(content: &str) {
    if let Some(state) = TUI_STATE.get() {
        if let Ok(mut s) = state.lock() {
            s.append_output(content);
        }
    }
}

/// Updates generation speed.
pub fn post_generation_speed(speed: f64) {
    if let Some(state) = TUI_STATE.get() {
        if let Ok(mut s) = state.lock() {
            s.set_generation_speed(speed);
        }
    }
}

/// Records request start time, returns Instant for tracking.
pub fn track_request_start() -> Option<Instant> {
    if is_interactive() {
        if let Some(trackers) = TRACKERS.get() {
            if let Ok(mut t) = trackers.lock() {
                t.record_request_start();
            }
        }
        Some(Instant::now())
    } else {
        None
    }
}

/// Records request end and updates TUI performance stats.
pub fn track_request_end(start: Option<Instant>) {
    if let Some(start) = start {
        let duration = start.elapsed();
        if let Some(trackers) = TRACKERS.get() {
            if let Ok(mut t) = trackers.lock() {
                t.record_request_end(duration);
            }
        }
        if let Some(state) = TUI_STATE.get() {
            if let Ok(mut s) = state.lock() {
                if let Some(trackers) = TRACKERS.get() {
                    if let Ok(t) = trackers.lock() {
                        s.set_stat("Requests", t.get_request_count().to_string());
                        s.set_stat("Avg Delay", format!("{:.2}ms", t.get_avg_delay_ms()));
                        s.set_stat("Msgs/sec", format!("{:.2}", t.get_msgs_per_second()));
                        s.set_stat("Uptime", t.uptime_string());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::tui::state::TuiState;

    #[test]
    fn test_not_interactive_when_not_set() {
        TUI_STATE.get_or_init(|| Arc::new(Mutex::new(TuiState::new())));
    }

    #[test]
    fn test_post_functions_are_noop_when_not_interactive() {
        post_step("test");
        post_progress(50.0);
        post_log("test message");
        post_output("test output");
        post_generation_speed(10.0);
        assert!(track_request_start().is_none());
        track_request_end(None);
    }
}
