//! Main TUI application loop using ratatui and crossterm.
//!
//! Dark, minimal, futuristic design inspired by opencode's CLI:
//! - Near-black background with subtle surface shades for panel separation
//! - Squared corners, no rounded borders
//! - Gray borders and separators, color reserved for status/data
//! - Header bar + footer status bar framing the content
//! - Grid-like layout with generous internal padding

use std::io::{self, stdout};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::{backend::CrosstermBackend, Frame, Terminal};
use reqwest::blocking::Client;

use super::colors::{
    BG, BORDER, BORDER_DIM, HIGHLIGHT, HIGHLIGHT_DIM, SUCCESS, SURFACE, SURFACE_HIGH,
    TEXT, TEXT_BRIGHT, TEXT_DIM, WARNING,
};
use super::state::TuiState;
use ratatui::style::Color;

fn format_response(text: &str) -> Vec<Line<'static>> {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return vec![Line::from(text.to_string())],
    };

    let obj = match value.as_object() {
        Some(o) => o,
        None => return vec![Line::from(text.to_string())],
    };

    let mut lines: Vec<Line<'static>> = Vec::new();

    let decision = obj.get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown").to_string();
    let decision_color = match decision.as_str() {
        "block" => WARNING,
        "allow" => SUCCESS,
        _ => HIGHLIGHT,
    };
    lines.push(Line::from(vec![
        Span::styled("Decision: ", Style::default().fg(TEXT_DIM)),
        Span::styled(decision, Style::default().fg(decision_color)),
    ]));

    let overall_risk = obj.get("overall_risk")
        .and_then(|v| v.as_i64())
        .unwrap_or(0) as u32;
    let overall_risk_color = if overall_risk >= 90 {
        Color::Rgb(255, 87, 87)
    } else if overall_risk >= 75 {
        WARNING
    } else {
        TEXT
    };
    lines.push(Line::from(vec![
        Span::styled("Overall Risk: ", Style::default().fg(TEXT_DIM)),
        Span::styled(format!("{}/100", overall_risk), Style::default().fg(overall_risk_color)),
    ]));

    if let Some(scores) = obj.get("scores").and_then(|v| v.as_object()) {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Scores:", Style::default().fg(HIGHLIGHT)),
        ]));

        let score_entries = [
            ("Phishing:", "phishing"),
            ("Impersonation:", "impersonation"),
            ("Prompt Injection:", "prompt_injection"),
            ("Secret:", "secret"),
            ("URL Reputation:", "url_reputation"),
            ("Risk:", "risk"),
        ];

        for (label, key) in score_entries {
            let value_str = if key == "url_reputation" {
                scores.get(key).map(|v| {
                    if v.is_null() {
                        "N/A".to_string()
                    } else {
                        v.to_string()
                    }
                }).unwrap_or_else(|| "N/A".to_string())
            } else {
                scores.get(key).map(|v| v.to_string()).unwrap_or_else(|| "0".to_string())
            };

            let value_color = if let Ok(num) = value_str.parse::<u32>() {
                if num >= 90 {
                    Color::Rgb(255, 87, 87)
                } else if num >= 75 {
                    WARNING
                } else {
                    TEXT
                }
            } else {
                TEXT
            };

            lines.push(Line::from(vec![
                Span::styled(format!("  {:.<20}", label), Style::default().fg(TEXT_DIM)),
                Span::styled(value_str, Style::default().fg(value_color)),
            ]));
        }
    }

    if let Some(flags) = obj.get("flags").and_then(|v| v.as_array()) {
        if !flags.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("Flags:", Style::default().fg(HIGHLIGHT)),
            ]));
            for flag in flags {
                if let Some(flag_str) = flag.as_str() {
                    lines.push(Line::from(vec![
                        Span::styled("  • ", Style::default().fg(TEXT_DIM)),
                        Span::styled(flag_str.to_string(), Style::default().fg(TEXT)),
                    ]));
                }
            }
        }
    }

    if let Some(urls) = obj.get("urls").and_then(|v| v.as_array()) {
        if !urls.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(format!("URLs: {} found", urls.len()), Style::default().fg(HIGHLIGHT)),
            ]));
            for url_entry in urls {
                if let Some(url_obj) = url_entry.as_object() {
                    let url_str = url_obj.get("url")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown").to_string();
                    let url_risk = url_obj.get("risk")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0) as u32;
                    let risk_color = if url_risk >= 90 {
                        Color::Rgb(255, 87, 87)
                    } else if url_risk >= 75 {
                        WARNING
                    } else {
                        TEXT
                    };
                    lines.push(Line::from(vec![
                        Span::styled("  ", Style::default().fg(TEXT_DIM)),
                        Span::styled(url_str, Style::default().fg(TEXT)),
                        Span::styled(format!(" (risk: {})", url_risk), Style::default().fg(risk_color)),
                    ]));
                }
            }
        }
    }

    if let Some(mem) = obj.get("message_memory").and_then(|v| v.as_object()) {
        lines.push(Line::from(""));
        let stored = mem.get("stored")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let stored_str = if stored { "yes" } else { "no" };
        lines.push(Line::from(vec![
            Span::styled("Message Memory: ", Style::default().fg(TEXT_DIM)),
            Span::styled(format!("stored: {}", stored_str), Style::default().fg(TEXT)),
        ]));

        if mem.get("lookup").is_some() {
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default().fg(TEXT_DIM)),
                Span::styled("lookup present", Style::default().fg(TEXT_DIM)),
            ]));
        }
    }

    if let Some(summary) = obj.get("summary").and_then(|v| v.as_str()) {
        if !summary.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled(summary.to_string(), Style::default().fg(TEXT_DIM).add_modifier(Modifier::ITALIC)),
            ]));
        }
    }

    if lines.is_empty() {
        lines.push(Line::from(text.to_string()));
    }

    lines
}

pub struct App {
    state: Arc<Mutex<TuiState>>,
    should_quit: bool,
    output_scroll: usize,
    logs_scroll: usize,
    api_addr: String,
    http_client: Client,
}

impl App {
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

    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        enable_raw_mode()?;
        let mut stdout = stdout();
        crossterm::execute!(stdout, EnterAlternateScreen)?;

        {
            let mut state = self.state.lock().unwrap();
            state.start();
        }

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        loop {
            if self.should_quit {
                break;
            }

            terminal.draw(|f| self.render(f))?;

            if event::poll(Duration::from_millis(50))? {
                if let Event::Key(key) = event::read()? {
                    self.handle_key_event(key);
                }
            }
        }

        disable_raw_mode()?;
        crossterm::execute!(io::stdout(), LeaveAlternateScreen)?;

        {
            let mut state = self.state.lock().unwrap();
            state.stop();
        }

        Ok(())
    }

    fn handle_key_event(&mut self, key: event::KeyEvent) {
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
                            let payload =
                                serde_json::json!({"message": input, "user_id": "tui"}).to_string();
                            let result = client
                                .post(format!("http://{}/analyse", api_addr))
                                .header("Content-Type", "application/json")
                                .body(payload)
                                .send();
                            let mut s = state_clone.lock().unwrap();
                            s.set_request_pending(false);
                            match result {
                                Ok(resp) => {
                                    if resp.status().is_success() {
                                        let body = resp.text().unwrap_or_else(|e| format!("<read error: {e}>"));
                                        s.append_output(body);
                                    } else {
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
                if self.output_scroll > 0 {
                    self.output_scroll -= 1;
                }
            }
            KeyCode::Down => {
                let total_lines: usize = state.output.iter().map(|s| format_response(s).len()).sum();
                if self.output_scroll < total_lines.saturating_sub(1) {
                    self.output_scroll += 1;
                }
            }
            _ => {}
        }
    }

    fn render(&self, f: &mut Frame) {
        let bg_clear = Block::default().style(Style::default().bg(BG));
        f.render_widget(bg_clear, f.area());

        let size = f.area();

        // ── Top-level layout: header | main | footer ──
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // header bar
                Constraint::Min(0),    // main content
                Constraint::Length(1), // footer bar
            ])
            .split(size);

        self.render_header(f, outer[0]);
        self.render_main(f, outer[1]);
        self.render_footer(f, outer[2]);
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let state = self.state.lock().unwrap();

        let db_status = if state.request_pending {
            Span::styled(" ● ", Style::default().fg(WARNING))
        } else {
            Span::styled(" ● ", Style::default().fg(SUCCESS))
        };

        let header_line = Line::from(vec![
            Span::styled(" POSEIDON ", Style::default().fg(TEXT_BRIGHT).add_modifier(Modifier::BOLD)),
            Span::styled("  ", Style::default()),
            db_status,
            Span::styled("ready", Style::default().fg(TEXT_DIM)),
            Span::styled("  ", Style::default()),
            Span::styled(
                format!("  step: {} ", state.current_step),
                Style::default().fg(TEXT_DIM),
            ),
            if state.progress_percent > 0.0 {
                Span::styled(
                    format!("({:.0}%) ", state.progress_percent),
                    Style::default().fg(HIGHLIGHT_DIM),
                )
            } else {
                Span::raw("")
            },
        ]);

        let header = Paragraph::new(header_line)
            .style(Style::default().bg(SURFACE).fg(TEXT));
        f.render_widget(header, area);
    }

    fn render_main(&self, f: &mut Frame, area: Rect) {
        // ── Main horizontal split: left 70% | right 30% ──
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(70),
                Constraint::Percentage(30),
            ])
            .split(area);

        self.render_left_column(f, columns[0]);
        self.render_right_column(f, columns[1]);
    }

    fn render_left_column(&self, f: &mut Frame, area: Rect) {
        let state = self.state.lock().unwrap();

        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(0),    // output (top)
                Constraint::Length(1), // step indicator (middle)
                Constraint::Length(3),  // input (bottom)
            ])
            .split(area);

        // ── Input area ──
        let input_style = if state.request_pending {
            Style::default().fg(WARNING)
        } else {
            Style::default().fg(HIGHLIGHT)
        };

        let input_block = Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(BORDER))
            .title(Line::from(vec![
                Span::styled(" Input ", Style::default().fg(TEXT_DIM)),
            ]))
            .title_position(ratatui::widgets::block::Position::Top)
            .style(Style::default().bg(SURFACE))
            .padding(ratatui::widgets::Padding::new(1, 1, 0, 0));

        let prompt = if state.request_pending {
            "⏳ "
        } else {
            "› "
        };
        let input_text = Line::from(vec![
            Span::styled(prompt, input_style.add_modifier(Modifier::BOLD)),
            Span::styled(state.input_buffer.as_str(), Style::default().fg(TEXT_BRIGHT)),
        ]);

        let input_paragraph = Paragraph::new(input_text)
            .style(Style::default().bg(SURFACE))
            .block(input_block);
        f.render_widget(input_paragraph, left_chunks[2]);

        // ── Output area ──
        let output_block = Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(BORDER))
            .title(Line::from(vec![
                Span::styled(" Output ", Style::default().fg(TEXT_DIM)),
            ]))
            .title_position(ratatui::widgets::block::Position::Top)
            .style(Style::default().bg(BG))
            .padding(ratatui::widgets::Padding::new(1, 1, 0, 0));

let visible_lines = left_chunks[0].height.saturating_sub(2) as usize;

        let all_lines: Vec<Line> = state.output.iter().flat_map(|s| format_response(s)).collect();
        let start = self.output_scroll.min(all_lines.len().saturating_sub(visible_lines));
        let output_lines: Vec<Line> = all_lines.into_iter().skip(start).take(visible_lines).collect();

        let output_paragraph = Paragraph::new(output_lines)
            .style(Style::default().fg(TEXT))
            .wrap(Wrap { trim: true })
            .block(output_block);
        f.render_widget(output_paragraph, left_chunks[0]);

        // ── Step indicator (single line, no border) ──
        let step_text = if state.request_pending {
            format!("  ⏳ {}", state.current_step)
        } else {
            format!("  {}", state.current_step)
        };
        let step_style = if state.request_pending {
            Style::default().fg(WARNING)
        } else {
            Style::default().fg(TEXT_DIM)
        };
        let step_line = Paragraph::new(step_text).style(step_style);
        f.render_widget(step_line, left_chunks[1]);
    }

    fn render_right_column(&self, f: &mut Frame, area: Rect) {
        let state = self.state.lock().unwrap();

        // Vertical separator line between columns
        let separator = Block::default()
            .borders(Borders::LEFT)
            .border_style(Style::default().fg(BORDER_DIM));
        f.render_widget(separator, area);

        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8), // metrics
                Constraint::Min(0),    // logs
            ])
            .split(area);

        // ── Metrics panel ──
        let metrics_block = Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(BORDER))
            .title(Line::from(vec![
                Span::styled(" Metrics ", Style::default().fg(TEXT_DIM)),
            ]))
            .title_position(ratatui::widgets::block::Position::Top)
            .style(Style::default().bg(SURFACE_HIGH))
            .padding(ratatui::widgets::Padding::new(1, 1, 0, 0));

        let mut metrics_lines: Vec<Line> = vec![];

        if state.placeholder_stats.is_empty() {
            metrics_lines.push(Line::from(vec![
                Span::styled("Requests ", Style::default().fg(TEXT_DIM)),
                Span::styled("0", Style::default().fg(TEXT)),
            ]));
            metrics_lines.push(Line::from(vec![
                Span::styled("Avg Delay ", Style::default().fg(TEXT_DIM)),
                Span::styled("0ms", Style::default().fg(TEXT)),
            ]));
            metrics_lines.push(Line::from(vec![
                Span::styled("Msgs/sec  ", Style::default().fg(TEXT_DIM)),
                Span::styled("0.00", Style::default().fg(TEXT)),
            ]));
            metrics_lines.push(Line::from(vec![
                Span::styled("Uptime    ", Style::default().fg(TEXT_DIM)),
                Span::styled("00:00:00", Style::default().fg(TEXT)),
            ]));
            metrics_lines.push(Line::from(vec![
                Span::styled("Speed     ", Style::default().fg(TEXT_DIM)),
                Span::styled(format!("{:.2} t/s", state.generation_speed), Style::default().fg(TEXT)),
            ]));
        } else {
            for (key, value) in &state.placeholder_stats {
                let padded_key = format!("{:<10}", key);
                metrics_lines.push(Line::from(vec![
                    Span::styled(padded_key, Style::default().fg(TEXT_DIM)),
                    Span::styled(value.as_str(), Style::default().fg(HIGHLIGHT)),
                ]));
            }
        }

        let metrics_paragraph = Paragraph::new(metrics_lines)
            .style(Style::default().bg(SURFACE_HIGH))
            .block(metrics_block);
        f.render_widget(metrics_paragraph, right_chunks[0]);

        // ── Logs panel ──
        let logs_block = Block::default()
            .borders(Borders::TOP)
            .border_style(Style::default().fg(BORDER))
            .title(Line::from(vec![
                Span::styled(" Logs ", Style::default().fg(TEXT_DIM)),
            ]))
            .title_position(ratatui::widgets::block::Position::Top)
            .style(Style::default().bg(BG))
            .padding(ratatui::widgets::Padding::new(1, 1, 0, 0));

        let log_lines: Vec<Line> = state
            .logs
            .iter()
            .rev()
            .skip(self.logs_scroll)
            .take(right_chunks[1].height.saturating_sub(2) as usize)
            .map(|s| Line::from(Span::styled(s.as_str(), Style::default().fg(TEXT_DIM))))
            .collect();

        let logs_paragraph = Paragraph::new(log_lines)
            .style(Style::default().bg(BG))
            .block(logs_block);
        f.render_widget(logs_paragraph, right_chunks[1]);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let footer_line = Line::from(vec![
            Span::styled(" q", Style::default().fg(HIGHLIGHT)),
            Span::styled(":quit", Style::default().fg(TEXT_DIM)),
            Span::styled("  ", Style::default()),
            Span::styled(" enter", Style::default().fg(HIGHLIGHT)),
            Span::styled(":send", Style::default().fg(TEXT_DIM)),
            Span::styled("  ", Style::default()),
            Span::styled(" ↑↓", Style::default().fg(HIGHLIGHT)),
            Span::styled(":scroll", Style::default().fg(TEXT_DIM)),
            Span::styled("  ", Style::default()),
            Span::styled(" esc", Style::default().fg(HIGHLIGHT)),
            Span::styled(":quit", Style::default().fg(TEXT_DIM)),
        ]);

        let footer = Paragraph::new(footer_line)
            .style(Style::default().bg(SURFACE).fg(TEXT_DIM));
        f.render_widget(footer, area);
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
        if let Err(err) =
            crate::modules::api::serve(&addr, &threat_intel, &url_db, &message_memory)
        {
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
        if let Err(err) =
            crate::modules::api::serve(&addr, &threat_intel, &url_db, &message_memory)
        {
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