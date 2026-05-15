//! Color constants for the TUI theme.
//! Provides a consistent color palette across all TUI components.

use ratatui::style::Color;

/// Main background color - dark theme base
pub const BG: Color = Color::from_u32(0x0f0f0f);

/// Highlight/accent color - used for important elements and selections
pub const HIGHLIGHT: Color = Color::from_u32(0x3365e6);

/// Default text color
pub const TEXT: Color = Color::Gray;

/// Success indicators and positive states
pub const SUCCESS: Color = Color::Green;

/// Warning indicators and caution states
pub const WARNING: Color = Color::Yellow;

/// Error indicators and negative states
pub const ERROR: Color = Color::Red;

/// Secondary text color for less important information
pub const TEXT_DIM: Color = Color::DarkGray;

/// Border color for panels and containers
pub const BORDER: Color = Color::DarkGray;
