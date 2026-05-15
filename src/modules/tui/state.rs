//! Thread-safe shared state for the TUI application.
//! Uses Arc<Mutex<T>> pattern for simple, safe concurrent access.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Thread-safe TUI state that can be shared across modules.
/// Access is controlled via Arc<Mutex<TuiState>>.
pub struct TuiState {
    /// Current processing step description
    pub current_step: String,
    /// Progress percentage (0.0 to 100.0)
    pub progress_percent: f64,
    /// Server/application logs
    pub logs: Vec<String>,
    /// Output messages/content
    pub output: Vec<String>,
    /// User input buffer
    pub input_buffer: String,
    /// Generation speed in tokens/sec or msgs/sec
    pub generation_speed: f64,
    /// Whether the TUI loop is actively running
    pub is_running: bool,
    /// Placeholder statistics for right sidebar
    pub placeholder_stats: HashMap<String, String>,
    /// Whether a request is pending (being processed)
    pub request_pending: bool,
}

impl TuiState {
    /// Creates a new TuiState with default values.
    pub fn new() -> Self {
        Self {
            current_step: String::from("Idle"),
            progress_percent: 0.0,
            logs: Vec::new(),
            output: Vec::new(),
            input_buffer: String::new(),
            generation_speed: 0.0,
            is_running: false,
            placeholder_stats: HashMap::new(),
            request_pending: false,
        }
    }

    /// Creates a new Arc<Mutex<TuiState>> with default values.
    pub fn new_shared() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::new()))
    }

    /// Adds a log entry with timestamp.
    pub fn add_log(&mut self, message: String) {
        let timestamp = chrono::Local::now().format("%H:%M:%S");
        self.logs.push(format!("[{}] {}", timestamp, message));
        // Keep logs manageable - keep last 100 entries
        if self.logs.len() > 100 {
            self.logs.remove(0);
        }
    }

    /// Sets the current processing step.
    pub fn set_step(&mut self, step: impl Into<String>) {
        self.current_step = step.into();
    }

    /// Sets the progress percentage (clamped to 0.0-100.0).
    pub fn set_progress(&mut self, percent: f64) {
        self.progress_percent = percent.clamp(0.0, 100.0);
    }

    /// Increments progress by a delta value.
    pub fn increment_progress(&mut self, delta: f64) {
        self.progress_percent = (self.progress_percent + delta).clamp(0.0, 100.0);
    }

    /// Appends output content.
    pub fn append_output(&mut self, content: impl Into<String>) {
        self.output.push(content.into());
        // Keep output manageable - keep last 200 entries
        if self.output.len() > 200 {
            self.output.remove(0);
        }
    }

    /// Clears all output.
    pub fn clear_output(&mut self) {
        self.output.clear();
    }

    /// Updates the input buffer.
    pub fn set_input(&mut self, input: impl Into<String>) {
        self.input_buffer = input.into();
    }

    /// Appends to the input buffer.
    pub fn append_input(&mut self, ch: char) {
        self.input_buffer.push(ch);
    }

    /// Removes the last character from the input buffer.
    pub fn pop_input(&mut self) {
        self.input_buffer.pop();
    }

    /// Clears the input buffer.
    pub fn clear_input(&mut self) {
        self.input_buffer.clear();
    }

    /// Sets the generation speed metric.
    pub fn set_generation_speed(&mut self, speed: f64) {
        self.generation_speed = speed;
    }

    /// Starts the TUI.
    pub fn start(&mut self) {
        self.is_running = true;
        self.add_log("TUI started".to_string());
    }

    /// Stops the TUI.
    pub fn stop(&mut self) {
        self.is_running = false;
        self.add_log("TUI stopped".to_string());
    }

    /// Checks if the TUI is running.
    pub fn running(&self) -> bool {
        self.is_running
    }

    /// Sets a placeholder statistic.
    pub fn set_stat(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.placeholder_stats.insert(key.into(), value.into());
    }

    /// Clears all logs.
    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    /// Resets all state to defaults.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Sets whether a request is pending.
    pub fn set_request_pending(&mut self, pending: bool) {
        self.request_pending = pending;
    }
}

impl Default for TuiState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_state() {
        let state = TuiState::new();
        assert_eq!(state.current_step, "Idle");
        assert_eq!(state.progress_percent, 0.0);
        assert!(state.logs.is_empty());
        assert!(state.output.is_empty());
        assert!(!state.is_running);
    }

    #[test]
    fn test_progress_clamping() {
        let mut state = TuiState::new();
        state.set_progress(150.0);
        assert_eq!(state.progress_percent, 100.0);
        state.set_progress(-10.0);
        assert_eq!(state.progress_percent, 0.0);
    }

    #[test]
    fn test_shared_state() {
        let shared = TuiState::new_shared();
        {
            let mut state = shared.lock().unwrap();
            state.set_step("Testing");
            state.set_progress(50.0);
        }
        {
            let state = shared.lock().unwrap();
            assert_eq!(state.current_step, "Testing");
            assert_eq!(state.progress_percent, 50.0);
        }
    }
}
