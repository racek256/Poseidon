//! Color constants for the TUI theme.
//! Provides a consistent color palette across all TUI components.
//!
//! Design philosophy: dark, minimal, futuristic — inspired by opencode's CLI.
//! - Background is near-black (#0f0f0f)
//! - Panels use subtle surface shades for separation, not bright borders
//! - One muted accent color for highlights
//! - Color is reserved for status/data, not decoration

use ratatui::style::Color;

// ── Backgrounds ──────────────────────────────────────────────────────

/// Main background color — near-black base
pub const BG: Color = Color::from_u32(0x0f0f0f);

/// Surface level 1 — subtle panel background for input/output areas
pub const SURFACE: Color = Color::from_u32(0x1a1a1a);

/// Surface level 2 — slightly raised surface for sidebar/metrics
pub const SURFACE_HIGH: Color = Color::from_u32(0x252525);

// ── Borders & Separators ────────────────────────────────────────────

/// Border color — visible gray for panel borders and separator lines
pub const BORDER: Color = Color::from_u32(0x484848);

/// Dim border — for subtle separators (e.g. between header and content)
pub const BORDER_DIM: Color = Color::from_u32(0x3c3c3c);

// ── Accent ───────────────────────────────────────────────────────────

/// Highlight/accent color — muted blue for selections, active elements, key data
pub const HIGHLIGHT: Color = Color::from_u32(0x5c8aff);

/// Highlight dim — for less prominent accent elements (progress bars, secondary highlights)
pub const HIGHLIGHT_DIM: Color = Color::from_u32(0x3a5a9e);

// ── Text ─────────────────────────────────────────────────────────────

/// Primary text color — light gray for readable content
pub const TEXT: Color = Color::from_u32(0xd4d4d4);

/// Secondary text — for labels, descriptions, less important info
pub const TEXT_DIM: Color = Color::from_u32(0x808080);

/// Bright text — for emphasis on important content
pub const TEXT_BRIGHT: Color = Color::from_u32(0xeeeeee);

// ── Status Colors (used sparingly, only for actual status indicators) ─

/// Success — used only for positive status indicators, not borders
pub const SUCCESS: Color = Color::from_u32(0x4caf50);

/// Warning — used only for caution status indicators, not borders
pub const WARNING: Color = Color::from_u32(0xffa726);

/// Error — used only for error status indicators, not borders
pub const ERROR: Color = Color::from_u32(0xef5350);