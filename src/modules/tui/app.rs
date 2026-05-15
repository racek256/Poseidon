//! Main TUI application loop using ratatui and crossterm.
//! Provides an interactive terminal user interface with:
//! - Left panel: Input prompt, statistics, current step, output window
//! - Right panel: Statistics sidebar, server logs

use std::io::{self, stdout};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use ratatui::{backend::CrosstermBackend, Frame, Terminal};
use reqwest::blocking::Client;

use super::colors::{BG, ERROR, HIGHLIGHT, SUCCESS, TEXT, TEXT_DIM, WARNING};
use super::state::TuiState;

/// TUI application that manages the main event loop and rendering.
pub struct App {
    /// Shared state with the rest of the application
    state: Arc<Mutex<TuiState>>,
    /// Whether the application should exit
    should_quit: bool,
    /// Scroll position for output window
    output_scroll: usize,
    /// Scroll position for logs window
    logs_scroll: usize,
    /// API server address
    api_addr: String,
    /// HTTP client for API requests
    http_client: Client,
}

impl App {
    /// Creates a new App instance with shared state.
    pub fn new(state: Arc<Mutex<TuiState>>, api_addr: String) -> Self {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .expect("failed to create HTTP client");
        Self {
            state,
            should_quit: false,
            output_scroll: 0,
            logs_scroll: 0,
            api_addr,
            http_client,
        }
    }

    /// Main event loop - handles input and renders UI.
    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = stdout();
        crossterm::execute!(stdout, EnterAlternateScreen)?;
        
        // Mark TUI as running
        {
            let mut state = self.state.lock().unwrap();
            state.start();
        }

        // Create terminal backend
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Main event loop
        loop {
            if self.should_quit {
                break;
            }

            // Render UI
            terminal.draw(|f| self.render(f))?;

            // Handle events with timeout
            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    self.handle_key_event(key);
                }
            }
        }

        // Cleanup
        disable_raw_mode()?;
        crossterm::execute!(io::stdout(), LeaveAlternateScreen)?;
        
        // Mark TUI as stopped
        {
            let mut state = self.state.lock().unwrap();
            state.stop();
        }

        Ok(())
    }

    /// Handles key press events.
    fn handle_key_event(&mut self, key: event::KeyEvent) {
        // Only handle Press events, ignore Release and Hold
        if key.kind != KeyEventKind::Press {
            return;
        }

        let mut state = self.state.lock().unwrap();

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                drop(state);
                self.should_quit = true;
            }
            KeyCode::Char(c) => {
                state.append_input(c);
            }
            KeyCode::Backspace => {
                state.pop_input();
            }
            KeyCode::Enter => {
                let input = state.input_buffer.clone();
                state.clear_input();
                if !input.is_empty() {
                    state.append_output(format!("> {}", input));
                    state.add_log(format!("User input: {}", input));
                    if state.request_pending {
                        drop(state);
                    } else {
                        state.set_request_pending(true);
                        drop(state);
                        let api_addr = self.api_addr.clone();
                        let client = self.http_client.clone();
                        let state_clone = Arc::clone(&self.state);
                        thread::spawn(move || {
                            let payload = serde_json::json!({"message": input, "user_id": "tui"}).to_string();
                            let result = client
                                .post(format!("http://{}/analyse", api_addr))
                                .header("Content-Type", "application/json")
                                .body(payload)
                                .send();
                            let mut s = state_clone.lock().unwrap();
                            s.set_request_pending(false);
                            match result {
                                Ok(resp) => {
                                    if !resp.status().is_success() {
                                        s.append_output(format!(
                                            "⚠ Request failed: HTTP {}",
                                            resp.status()
                                        ));
                                    }
                                }
                                Err(err) => {
                                    s.append_output(format!("⚠ Request error: {}", err));
                                    s.add_log(format!("Request error: {}", err));
                                }
                            }
                        });
                    }
                } else {
                    drop(state);
                }
            }
            KeyCode::Up => {
                // Scroll output up
                let output_len = {
                    let state = self.state.lock().unwrap();
                    state.output.len()
                };
                if self.output_scroll > 0 && output_len > 0 {
                    self.output_scroll = self.output_scroll.saturating_sub(1);
                }
            }
            KeyCode::Down => {
                // Scroll output down
                let output_len = {
                    let state = self.state.lock().unwrap();
                    state.output.len()
                };
                if self.output_scroll < output_len.saturating_sub(1) {
                    self.output_scroll += 1;
                }
            }
            _ => {}
        }
    }

    /// Renders the main TUI layout.
    fn render(&self, f: &mut Frame) {
        // Clear the entire frame with background color
        let bg_clear = Block::default().style(Style::default().bg(BG));
        f.render_widget(bg_clear, f.area());

        // Get terminal size
        let size = f.area();
        
        // Create main horizontal split (70% left, 30% right)
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(70),
                Constraint::Percentage(30),
            ])
            .split(size);

        // Render left panel
        self.render_left_panel(f, chunks[0]);
        
        // Render right panel
        self.render_right_panel(f, chunks[1]);
    }

    /// Renders the left panel (70% width).
    fn render_left_panel(&self, f: &mut Frame, area: Rect) {
        let state = self.state.lock().unwrap();

        // Vertical split for left panel
        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),  // Input section
                Constraint::Length(6),  // Stats section
                Constraint::Length(4),  // Current step
                Constraint::Min(0),     // Output window (takes remaining)
            ])
            .split(area);

        // Input section with border
        let (input_title, input_border_color) = if state.request_pending {
            (" ⏳ Analyzing... ", WARNING)
        } else {
            (" Input ", HIGHLIGHT)
        };

        let input_block = Block::default()
            .title(input_title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(input_border_color));
        
        let input_paragraph = Paragraph::new(state.input_buffer.as_str())
            .style(Style::default().fg(TEXT))
            .block(input_block.clone());
        f.render_widget(input_paragraph, left_chunks[0]);

        // Stats section
        let stats_block = Block::default()
            .title(" Statistics ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(TEXT_DIM));
        
        let stats_text = vec![
            Line::from(vec![
                Span::raw("Generation Speed: "),
                Span::raw(format!("{:.2} tokens/sec", state.generation_speed)).fg(HIGHLIGHT),
            ]),
            Line::from(vec![
                Span::raw("Progress: "),
                Span::raw(format!("{:.1}%", state.progress_percent)).fg(HIGHLIGHT),
            ]),
        ];
        let stats_paragraph = Paragraph::new(stats_text)
            .style(Style::default().fg(TEXT))
            .block(stats_block);
        f.render_widget(stats_paragraph, left_chunks[1]);

        // Current step section
        let step_block = Block::default()
            .title(" Currently Working On ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(TEXT_DIM));
        
        let step_paragraph = Paragraph::new(state.current_step.as_str())
            .style(Style::default().fg(WARNING))
            .block(step_block);
        f.render_widget(step_paragraph, left_chunks[2]);

        // Output window with scroll
        let output_block = Block::default()
            .title(" Output ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(SUCCESS));

        let visible_lines = left_chunks[3].height as usize;
        let start = self
            .output_scroll
            .min(state.output.len().saturating_sub(visible_lines));
        let output_lines: Vec<Line> = state
            .output
            .iter()
            .skip(start)
            .take(visible_lines)
            .map(|s| Line::from(s.as_str()))
            .collect();

        let output_paragraph = Paragraph::new(output_lines)
            .style(Style::default().fg(TEXT))
            .block(output_block);

        f.render_widget(output_paragraph, left_chunks[3]);
    }

    /// Renders the right panel (30% width).
    fn render_right_panel(&self, f: &mut Frame, area: Rect) {
        let state = self.state.lock().unwrap();

        // Vertical split for right panel
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),  // Stats sidebar (takes remaining)
                Constraint::Length(10),  // Logs window
            ])
            .split(area);

        // Statistics sidebar
        let stats_block = Block::default()
            .title(" Statistics ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(TEXT_DIM))
            .padding(ratatui::widgets::Padding::uniform(1));
        
        let mut stats_lines = vec![
            Line::from(vec![Span::raw("Placeholder Statistics").fg(TEXT_DIM)]),
            Line::from(vec![Span::raw("").fg(TEXT_DIM)]),
        ];

        // Add placeholder stats
        for (key, value) in &state.placeholder_stats {
            stats_lines.push(Line::from(vec![
                Span::raw(format!("{}: ", key)).fg(TEXT),
                Span::raw(value.as_str()).fg(HIGHLIGHT),
            ]));
        }

        // Add default placeholders if no custom stats
        if state.placeholder_stats.is_empty() {
            stats_lines.extend(vec![
                Line::from(vec![Span::raw("Requests: 0").fg(TEXT)]),
                Line::from(vec![Span::raw("Avg Delay: 0ms").fg(TEXT)]),
                Line::from(vec![Span::raw("Uptime: 00:00:00").fg(TEXT)]),
                Line::from(vec![Span::raw("Msgs/sec: 0.00").fg(TEXT)]),
            ]);
        }

        let sidebar_paragraph = Paragraph::new(stats_lines)
            .style(Style::default().fg(TEXT))
            .block(stats_block);
        f.render_widget(sidebar_paragraph, right_chunks[0]);

        // Server logs window
        let logs_block = Block::default()
            .title(" Server Logs ")
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(ERROR));
        
        let log_lines: Vec<Line> = state.logs.iter()
            .rev()  // Show newest first
            .skip(self.logs_scroll)
            .take(10)
            .map(|s| Line::from(s.as_str()))
            .collect();
        
        let logs_paragraph = Paragraph::new(log_lines)
            .style(Style::default().fg(TEXT_DIM))
            .block(logs_block);
        f.render_widget(logs_paragraph, right_chunks[1]);
    }
}

/// Starts the TUI in a separate thread.
/// Returns a handle to the shared state.
pub fn start_tui_thread(addr: &str) -> Arc<Mutex<TuiState>> {
    let state = TuiState::new_shared();

    let _ = set_tui_state_arc(Arc::clone(&state));

    let addr = addr.to_string();
    let addr_for_app = addr.clone();

    thread::spawn(move || {
        let threat_intel = crate::modules::threat_intel::ThreatIntel::from_env()
            .expect("failed to initialize threat intel database");
        let url_db = crate::modules::url_db::UrlDb::from_env()
            .expect("failed to initialize url database");
        let message_memory = crate::modules::message_memory::MessageMemory::from_env()
            .expect("failed to initialize message memory database");
        threat_intel.update_if_due();
        crate::modules::llm_server::ensure();
        if let Err(err) = crate::modules::ai::warmup() {
            crate::modules::tui::bridge::elog(&format!("llm warmup failed: {err}"));
        }
        if let Err(err) = crate::modules::api::serve(&addr, &threat_intel, &url_db, &message_memory) {
            crate::modules::tui::bridge::elog(&format!("api server failed: {err}"));
        }
    });

    let state_clone = Arc::clone(&state);
    thread::spawn(move || {
        let mut app = App::new(state_clone, addr_for_app);
        if let Err(e) = app.run() {
            eprintln!("TUI Error: {}", e);
        }
    });

    state
}

fn set_tui_state_arc(state: Arc<Mutex<TuiState>>) {
    crate::modules::tui::bridge::set_tui_state(state);
}

/// Runs the TUI with server in background thread.
pub fn run_tui(addr: &str) {
    let state = TuiState::new_shared();
    let _ = set_tui_state_arc(Arc::clone(&state));
    let addr = addr.to_string();
    let addr_for_app = addr.clone();
    thread::spawn(move || {
        let threat_intel = crate::modules::threat_intel::ThreatIntel::from_env()
            .expect("failed to initialize threat intel database");
        let url_db = crate::modules::url_db::UrlDb::from_env()
            .expect("failed to initialize url database");
        let message_memory = crate::modules::message_memory::MessageMemory::from_env()
            .expect("failed to initialize message memory database");
        threat_intel.update_if_due();
        crate::modules::llm_server::ensure();
        if let Err(err) = crate::modules::ai::warmup() {
            crate::modules::tui::bridge::elog(&format!("llm warmup failed: {err}"));
        }
        if let Err(err) = crate::modules::api::serve(&addr, &threat_intel, &url_db, &message_memory) {
            crate::modules::tui::bridge::elog(&format!("api server failed: {err}"));
        }
    });
    let mut app = App::new(state, addr_for_app);
    if let Err(e) = app.run() {
        eprintln!("TUI Error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_creation() {
        let state = TuiState::new_shared();
        let app = App::new(state, "127.0.0.1:8080".to_string());
        assert!(!app.should_quit);
    }
}
