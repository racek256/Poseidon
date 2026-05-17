//! Terminal User Interface (TUI) module for Poseidon.
//!
//! This module provides an interactive terminal-based interface for monitoring
//! and interacting with the phishing detection system.
//!
//! # Structure
//!
//! - [`colors`] - Color constants and theme definitions
//! - [`state`] - Thread-safe shared state management
//! - [`trackers`] - Performance tracking and metrics
//! - [`app`] - Main TUI application loop and rendering
//!
//! # Usage
//!
//! ```rust
//! use poseidon::modules::tui::{start_tui_thread, state::TuiState};
//!
//! // Start TUI in background thread
//! let state = start_tui_thread();
//!
//! // Update state from anywhere
//! {
//!     let mut s = state.lock().unwrap();
//!     s.set_step("Analyzing URL...");
//!     s.set_progress(50.0);
//!     s.append_output("Found suspicious patterns");
//! }
//! ```

pub mod app;
pub mod bridge;
pub mod colors;
pub mod state;
pub mod trackers;

pub use app::{run_tui, start_tui_thread};
pub use state::TuiState;
pub use trackers::PerformanceTrackers;
