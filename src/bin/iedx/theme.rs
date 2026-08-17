//! Colours and styles.
//!
//! The palette is chosen to stay legible on both light and dark terminals:
//! everything is drawn with the terminal's own background except where a
//! selection or a header deliberately inverts it.

use ratatui::style::{Color, Modifier, Style};

pub const ACCENT: Color = Color::Rgb(0x58, 0xa6, 0xff);
pub const OK: Color = Color::Rgb(0x3f, 0xb9, 0x50);
pub const WARN: Color = Color::Rgb(0xd2, 0x99, 0x22);
pub const ERR: Color = Color::Rgb(0xf8, 0x51, 0x49);
pub const MUTED: Color = Color::Rgb(0x8b, 0x94, 0x9e);
pub const BORDER: Color = Color::Rgb(0x50, 0x5a, 0x66);
pub const SEL_BG: Color = Color::Rgb(0x1f, 0x6f, 0xeb);
pub const SEL_FG: Color = Color::Rgb(0xff, 0xff, 0xff);

pub fn header() -> Style {
    Style::default()
        .fg(SEL_FG)
        .bg(SEL_BG)
        .add_modifier(Modifier::BOLD)
}

pub fn tab() -> Style {
    Style::default().fg(MUTED)
}

pub fn tab_active() -> Style {
    Style::default()
        .fg(SEL_FG)
        .bg(SEL_BG)
        .add_modifier(Modifier::BOLD)
}

pub fn cursor() -> Style {
    Style::default().fg(SEL_FG).bg(SEL_BG)
}

pub fn label() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

pub fn value() -> Style {
    Style::default().fg(OK)
}

pub fn muted() -> Style {
    Style::default().fg(MUTED)
}

pub fn accent() -> Style {
    Style::default().fg(ACCENT)
}

pub fn error() -> Style {
    Style::default().fg(ERR)
}

pub fn warn() -> Style {
    Style::default().fg(WARN)
}

pub fn border() -> Style {
    Style::default().fg(BORDER)
}

pub fn help() -> Style {
    Style::default().fg(MUTED).add_modifier(Modifier::DIM)
}

/// How a status line is coloured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusKind {
    #[default]
    Info,
    Ok,
    Err,
}

impl StatusKind {
    pub fn style(self) -> Style {
        match self {
            StatusKind::Info => muted(),
            StatusKind::Ok => Style::default().fg(OK),
            StatusKind::Err => Style::default().fg(ERR),
        }
    }
}
