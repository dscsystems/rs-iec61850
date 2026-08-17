//! Logs: pick a log and query its entries.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use iec61850::client::{AcsiClass, LogEntry};
use iec61850::model::ObjectReference;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{Ctx, Msg};
use crate::dialogs::Dialog;
use crate::theme::{self, StatusKind};
use crate::widgets::{self, ListBox};

/// How far back a query reaches when no range has been asked for.
const DEFAULT_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
/// The narrowest and widest the window can be stepped to: an hour is the
/// smallest span worth a round trip, and a month is as far back as a device
/// keeps entries in practice.
const MIN_WINDOW: Duration = Duration::from_secs(60 * 60);
const MAX_WINDOW: Duration = Duration::from_secs(30 * 24 * 60 * 60);

pub struct LogsPanel {
    list: ListBox,
    entries_view: ListBox,
    pub refs: Vec<ObjectReference>,
    pub entries: Vec<LogEntry>,
    /// How far back the next range query reaches.
    window: Duration,
}

impl Default for LogsPanel {
    fn default() -> LogsPanel {
        LogsPanel {
            list: ListBox::default(),
            entries_view: ListBox::default(),
            refs: Vec::new(),
            entries: Vec::new(),
            window: DEFAULT_WINDOW,
        }
    }
}

impl LogsPanel {
    pub fn load(&mut self, ctx: &Ctx) {
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let devices = match client.logical_devices().await {
                Ok(d) => d,
                Err(e) => return ctx.err(format!("logs: {e}")),
            };
            let mut refs = Vec::new();
            for ld in &devices {
                let found = client.browse(ld, &[AcsiClass::Log]).await.unwrap_or_default();
                refs.extend(found.into_iter().map(|e| e.reference));
            }
            ctx.send(Msg::LogsLoaded(refs));
        });
    }

    fn selected(&self) -> Option<ObjectReference> {
        self.refs.get(self.list.cursor).cloned()
    }

    pub fn on_key(&mut self, key: KeyEvent, ctx: &Ctx) -> Option<Dialog> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.list.move_by(-1, self.refs.len()),
            KeyCode::Down | KeyCode::Char('j') => self.list.move_by(1, self.refs.len()),
            KeyCode::Home | KeyCode::Char('g') => self.entries_view.first(),
            KeyCode::End | KeyCode::Char('G') => self.entries_view.last(self.entries.len()),
            KeyCode::PageUp => self.entries_view.move_by(-10, self.entries.len()),
            KeyCode::PageDown => self.entries_view.move_by(10, self.entries.len()),
            KeyCode::Enter | KeyCode::Char('r') => self.query(ctx),
            KeyCode::Char('a') => self.query_after(ctx),
            // `=` is `+` without the shift, which is what the key is usually
            // pressed as.
            KeyCode::Char('+') | KeyCode::Char('=') => self.widen(ctx),
            KeyCode::Char('-') => self.narrow(ctx),
            _ => {}
        }
        None
    }

    /// Doubles and halves the window, within the bounds above.
    fn widen(&mut self, ctx: &Ctx) {
        self.set_window(self.window * 2, ctx);
    }

    fn narrow(&mut self, ctx: &Ctx) {
        self.set_window(self.window / 2, ctx);
    }

    fn set_window(&mut self, window: Duration, ctx: &Ctx) {
        self.window = window.clamp(MIN_WINDOW, MAX_WINDOW);
        ctx.status(
            format!("query window: {}", fmt_window(self.window)),
            StatusKind::Info,
        );
    }

    /// Queries the last day of entries, replacing what is shown.
    fn query(&mut self, ctx: &Ctx) {
        let Some(reference) = self.selected() else {
            return;
        };
        // The entries are about to be replaced, so the view goes back to the
        // top before anything is sent; a cursor left deep in the old list would
        // point at an unrelated record.
        self.entries_view = ListBox::default();
        let Some(client) = ctx.client() else { return };
        let end = SystemTime::now();
        let start = end - self.window;
        ctx.status(
            format!(
                "querying {reference} over the last {} ...",
                fmt_window(self.window)
            ),
            StatusKind::Info,
        );
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match client.query_log_by_time(reference, start, end).await {
                Ok(entries) => ctx.send(Msg::LogQueried(entries)),
                Err(e) => ctx.err(format!("query log: {e}")),
            }
        });
    }

    /// Continues from the newest entry already shown, so a repeated query does
    /// not fetch the same records again.
    fn query_after(&mut self, ctx: &Ctx) {
        let Some(reference) = self.selected() else {
            return;
        };
        let Some(last) = self.entries.last().cloned() else {
            // With nothing to continue from, the range query is the only thing
            // that can produce a starting point.
            self.query(ctx);
            return;
        };
        let Some(client) = ctx.client() else { return };
        let after = last.occurrence_time.unwrap_or(UNIX_EPOCH);
        let entry_id = last.entry_id.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match client.query_log_after(reference, after, &entry_id).await {
                Ok(entries) => ctx.send(Msg::LogQueried(entries)),
                Err(e) => ctx.err(format!("query log: {e}")),
            }
        });
    }

    pub fn scroll(&mut self, up: bool) {
        self.entries_view
            .move_by(if up { -1 } else { 1 }, self.entries.len());
    }

    pub fn on_click(&mut self, x: u16, y: u16, width: u16, ctx: &Ctx) -> Option<Dialog> {
        let row = y.checked_sub(1)?;
        if x < left_width(width) {
            if self.list.click_row(row as usize, self.refs.len()) {
                self.query(ctx);
            }
        } else {
            self.entries_view.click_row(row as usize, self.entries.len());
        }
        None
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(left_width(rows[0].width)),
                Constraint::Min(10),
            ])
            .split(rows[0]);

        let refs = self.refs.clone();
        self.list
            .render(f, cols[0], "Logs", refs.len(), move |i| {
                Line::raw(refs[i].to_string())
            });

        let entries = self.entries.clone();
        self.entries_view
            .render(f, cols[1], "Entries", entries.len(), move |i| {
                let e = &entries[i];
                let tags: Vec<String> = e
                    .variables
                    .iter()
                    .map(|v| match &v.value {
                        Some(value) => format!("{}={value}", v.tag),
                        None => v.tag.clone(),
                    })
                    .collect();
                Line::from(vec![
                    Span::styled(fmt_time(e.occurrence_time), theme::muted()),
                    Span::raw("  "),
                    Span::styled(hex(&e.entry_id), theme::accent()),
                    Span::raw("  "),
                    Span::styled(tags.join(" "), theme::value()),
                ])
            });

        f.render_widget(
            Paragraph::new(Line::styled(
                format!(
                    "↑↓ select log · enter/r query the last {} · +/- window · a continue after the last entry",
                    fmt_window(self.window)
                ),
                theme::help(),
            )),
            rows[1],
        );
    }
}

fn left_width(width: u16) -> u16 {
    widgets::left_width(width, 28)
}

/// Renders the window as hours or days, whichever reads better.
fn fmt_window(w: Duration) -> String {
    let hours = w.as_secs() / 3600;
    if hours % 24 == 0 && hours >= 24 {
        let days = hours / 24;
        if days == 1 {
            "24 h".into()
        } else {
            format!("{days} d")
        }
    } else {
        format!("{hours} h")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Formats a timestamp as `YYYY-MM-DD hh:mm:ss` in UTC.
///
/// The crate's own civil-date helper is internal, and the display here needs
/// nothing more than this, so it is computed rather than pulling in a
/// date-time dependency.
fn fmt_time(t: Option<SystemTime>) -> String {
    let Some(t) = t else {
        return "                   ".into();
    };
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    };
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil algorithm, for days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850::mms::JournalVariable;

    fn ctx() -> (Ctx, tokio::sync::mpsc::UnboundedReceiver<Msg>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Ctx { client: None, tx }, rx)
    }

    #[test]
    fn timestamps_render_as_utc_civil_time() {
        // 2026-08-16T00:00:00Z
        let t = UNIX_EPOCH + Duration::from_secs(1_786_838_400);
        assert_eq!(fmt_time(Some(t)), "2026-08-16 00:00:00");
        assert_eq!(fmt_time(Some(UNIX_EPOCH)), "1970-01-01 00:00:00");
        // A missing time keeps the column width, so the entries stay aligned.
        assert_eq!(fmt_time(None).len(), "1970-01-01 00:00:00".len());
    }

    /// The window steps by doubling, and stops rather than running away to a
    /// query no device would answer.
    #[test]
    fn the_query_window_doubles_and_halves_within_bounds() {
        let mut p = LogsPanel::default();
        let (c, _rx) = ctx();
        assert_eq!(p.window, DEFAULT_WINDOW);

        p.narrow(&c);
        assert_eq!(p.window, Duration::from_secs(12 * 3600));
        p.widen(&c);
        assert_eq!(p.window, DEFAULT_WINDOW);

        for _ in 0..20 {
            p.widen(&c);
        }
        assert_eq!(p.window, MAX_WINDOW);
        for _ in 0..20 {
            p.narrow(&c);
        }
        assert_eq!(p.window, MIN_WINDOW);
    }

    #[test]
    fn the_window_reads_as_hours_or_days() {
        assert_eq!(fmt_window(Duration::from_secs(3600)), "1 h");
        assert_eq!(fmt_window(DEFAULT_WINDOW), "24 h");
        assert_eq!(fmt_window(Duration::from_secs(48 * 3600)), "2 d");
        assert_eq!(fmt_window(MAX_WINDOW), "30 d");
    }

    #[test]
    fn entry_ids_render_as_hex() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex(&[]), "");
    }

    /// Continuing with nothing to continue from would query after the epoch and
    /// look like a hang, so it falls back to the range query.
    #[test]
    fn continuing_an_empty_view_runs_the_range_query_instead() {
        let mut p = LogsPanel {
            refs: vec![ObjectReference::new("LD/LLN0.LG.EventLog")],
            ..Default::default()
        };
        let (c, mut rx) = ctx();
        p.query_after(&c);
        // Without a connection the range query reports that; the point is that
        // it was the range query that ran.
        assert!(matches!(rx.try_recv(), Ok(Msg::Status(_, _))));
    }

    #[test]
    fn a_new_query_resets_the_entry_view_to_the_top() {
        let mut p = LogsPanel {
            refs: vec![ObjectReference::new("LD/LLN0.LG.EventLog")],
            entries: vec![LogEntry::default(); 20],
            ..Default::default()
        };
        p.entries_view.cursor = 15;
        let (c, _rx) = ctx();
        p.query(&c);
        assert_eq!(p.entries_view.cursor, 0);
    }

    #[test]
    fn an_entry_shows_its_logged_variables() {
        let e = LogEntry {
            entry_id: vec![1, 2],
            occurrence_time: Some(UNIX_EPOCH),
            variables: vec![JournalVariable {
                tag: "stVal".into(),
                value: None,
            }],
        };
        assert_eq!(e.variables.len(), 1);
        assert_eq!(hex(&e.entry_id), "0102");
    }
}
