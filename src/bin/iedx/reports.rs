//! Report control blocks: enable, general interrogation, and a live feed.

use std::sync::Arc;

use iec61850::client::{AcsiClass, ReportSubscription};
use iec61850::model::{ObjectReference, OptFlds, TrgOps};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{Ctx, Msg};
use crate::dialogs::Dialog;
use crate::theme::{self, StatusKind};
use crate::widgets::{self, ListBox};

/// How many feed lines are kept. A busy dataset would otherwise grow the
/// buffer without bound over a long session.
const FEED_LIMIT: usize = 500;

#[derive(Debug, Clone)]
pub struct RcbItem {
    pub reference: ObjectReference,
    pub buffered: bool,
}

#[derive(Default)]
pub struct ReportsPanel {
    list: ListBox,
    pub rcbs: Vec<RcbItem>,
    feed: Vec<String>,
    enabled: Option<ObjectReference>,
    /// Held so the subscription lives as long as the panel; dropping it stops
    /// delivery.
    subscription: Option<Arc<ReportSubscription>>,
}

impl ReportsPanel {
    pub fn load(&mut self, ctx: &Ctx) {
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let devices = match client.logical_devices().await {
                Ok(d) => d,
                Err(e) => return ctx.err(format!("reports: {e}")),
            };
            let mut rcbs = Vec::new();
            for ld in &devices {
                let found = client
                    .browse(ld, &[AcsiClass::Urcb, AcsiClass::Brcb])
                    .await
                    .unwrap_or_default();
                for e in found {
                    rcbs.push(RcbItem {
                        buffered: e.class == AcsiClass::Brcb,
                        reference: e.reference,
                    });
                }
            }
            ctx.send(Msg::RcbsLoaded(rcbs));
        });
    }

    pub fn on_enabled(&mut self, reference: ObjectReference, sub: Arc<ReportSubscription>) {
        self.feed.push(format!("● enabled {reference}"));
        self.enabled = Some(reference);
        self.subscription = Some(sub);
    }

    pub fn push_line(&mut self, line: String) {
        self.feed.push(line);
        if self.feed.len() > FEED_LIMIT {
            self.feed.drain(..self.feed.len() - FEED_LIMIT);
        }
    }

    fn selected(&self) -> Option<&RcbItem> {
        self.rcbs.get(self.list.cursor)
    }

    pub fn on_key(&mut self, key: KeyEvent, ctx: &Ctx) -> Option<Dialog> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.list.move_by(-1, self.rcbs.len()),
            KeyCode::Down | KeyCode::Char('j') => self.list.move_by(1, self.rcbs.len()),
            KeyCode::Char('e') | KeyCode::Enter => self.enable(ctx),
            KeyCode::Char('g') => self.trigger_gi(ctx),
            KeyCode::Char('x') => self.disable(ctx),
            KeyCode::Char('c') => self.feed.clear(),
            _ => {}
        }
        None
    }

    fn enable(&mut self, ctx: &Ctx) {
        let Some(item) = self.selected().cloned() else {
            return;
        };
        let Some(client) = ctx.client() else { return };
        ctx.status(format!("enabling {} ...", item.reference), StatusKind::Info);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut rcb = match client.get_rcb(item.reference.clone()).await {
                Ok(r) => r,
                Err(e) => return ctx.err(format!("enable failed: {e}")),
            };
            rcb.opt_flds = OptFlds::SEQ_NUM
                | OptFlds::REASON_CODE
                | OptFlds::DATA_SET_NAME
                | OptFlds::CONF_REV;
            rcb.trg_ops = TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE | TrgOps::GI;

            let feed = ctx.clone();
            let subscription = client
                .enable_reporting(&rcb, move |report| {
                    feed.send(Msg::ReportLine(format!(
                        "{} seq={} entries={}",
                        report.rpt_id,
                        report.seq_num,
                        report.entries.len()
                    )));
                    for e in &report.entries {
                        feed.send(Msg::ReportLine(format!(
                            "    {} = {} ({})",
                            e.reference, e.value, e.reason
                        )));
                    }
                })
                .await;
            match subscription {
                Ok(sub) => {
                    // The subscription is handed to the panel before the
                    // interrogation is asked for: dropping it here would stop
                    // delivery before the first report, and posting it after
                    // would put the "enabled" line below the reports it
                    // announces.
                    ctx.send(Msg::ReportEnabled(item.reference.clone(), Arc::new(sub)));
                    // A general interrogation fills the feed immediately, so
                    // the panel is not blank until something changes.
                    let _ = client.trigger_gi(&rcb).await;
                    ctx.ok(format!("reporting enabled on {}", item.reference));
                }
                Err(e) => ctx.err(format!("enable failed: {e}")),
            }
        });
    }

    fn trigger_gi(&mut self, ctx: &Ctx) {
        let Some(reference) = self.enabled.clone() else {
            ctx.err("enable a report first");
            return;
        };
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match client.get_rcb(reference).await {
                Ok(rcb) => match client.trigger_gi(&rcb).await {
                    Ok(()) => ctx.ok("general interrogation sent"),
                    Err(e) => ctx.err(format!("GI failed: {e}")),
                },
                Err(e) => ctx.err(format!("GI failed: {e}")),
            }
        });
    }

    fn disable(&mut self, ctx: &Ctx) {
        if self.enabled.take().is_none() {
            return;
        }
        let Some(sub) = self.subscription.take() else {
            return;
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match sub.disable().await {
                Ok(()) => ctx.status("reporting disabled", StatusKind::Info),
                Err(e) => ctx.err(format!("disable failed: {e}")),
            }
        });
    }

    pub fn scroll(&mut self, up: bool) {
        self.list.move_by(if up { -1 } else { 1 }, self.rcbs.len());
    }

    pub fn on_click(&mut self, x: u16, y: u16, width: u16, ctx: &Ctx) -> Option<Dialog> {
        if x < left_width(width) {
            if let Some(row) = y.checked_sub(1) {
                if self.list.click_row(row as usize, self.rcbs.len()) {
                    self.enable(ctx);
                }
            }
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

        let rcbs = self.rcbs.clone();
        let enabled = self.enabled.clone();
        self.list
            .render(f, cols[0], "Control blocks", rcbs.len(), move |i| {
                let it = &rcbs[i];
                let live = enabled.as_ref() == Some(&it.reference);
                Line::from(vec![
                    Span::styled(
                        if live { "● " } else { "  " },
                        theme::value(),
                    ),
                    Span::raw(it.reference.to_string()),
                    Span::styled(
                        if it.buffered { "  BRCB" } else { "  URCB" },
                        theme::muted(),
                    ),
                ])
            });

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .title("Feed");
        let inner = block.inner(cols[1]);
        f.render_widget(block, cols[1]);
        let lines: Vec<Line> = if self.feed.is_empty() {
            vec![Line::styled(
                "select a control block and press e to enable reporting",
                theme::muted(),
            )]
        } else {
            // Show the tail: the newest report is the interesting one.
            let start = self.feed.len().saturating_sub(inner.height as usize);
            self.feed[start..]
                .iter()
                .map(|l| {
                    if l.starts_with("    ") {
                        Line::styled(l.clone(), theme::value())
                    } else if l.starts_with('●') {
                        Line::styled(l.clone(), theme::accent())
                    } else {
                        Line::raw(l.clone())
                    }
                })
                .collect()
        };
        f.render_widget(Paragraph::new(lines), inner);

        f.render_widget(
            Paragraph::new(Line::styled(
                "↑↓ select · e enable+GI · g GI · x disable · c clear feed",
                theme::help(),
            )),
            rows[1],
        );
    }
}

fn left_width(width: u16) -> u16 {
    widgets::left_width(width, 30)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panel_with(n: usize) -> ReportsPanel {
        ReportsPanel {
            rcbs: (0..n)
                .map(|i| RcbItem {
                    reference: ObjectReference::new(format!("LD/LLN0.RP.urcb{i:02}")),
                    buffered: i % 2 == 1,
                })
                .collect(),
            ..Default::default()
        }
    }

    /// A long session on a busy dataset would otherwise grow without bound.
    #[test]
    fn the_feed_keeps_only_its_tail() {
        let mut p = ReportsPanel::default();
        for i in 0..FEED_LIMIT + 250 {
            p.push_line(format!("line {i}"));
        }
        assert_eq!(p.feed.len(), FEED_LIMIT);
        assert_eq!(
            p.feed.last().unwrap(),
            &format!("line {}", FEED_LIMIT + 249),
            "the newest lines are the ones kept"
        );
        assert!(!p.feed.contains(&"line 0".to_string()));
    }

    #[test]
    fn enabling_marks_the_block_and_notes_it_in_the_feed() {
        let mut p = panel_with(3);
        let reference = ObjectReference::new("LD/LLN0.RP.urcb01");
        p.feed.push(format!("● enabled {reference}"));
        p.enabled = Some(reference.clone());
        assert_eq!(p.enabled.as_ref(), Some(&reference));
        assert!(p.feed[0].contains("enabled"));
    }

    #[test]
    fn selection_stays_within_the_list() {
        let mut p = panel_with(3);
        let ctx = Ctx {
            client: None,
            tx: tokio::sync::mpsc::unbounded_channel().0,
        };
        for _ in 0..10 {
            p.on_key(KeyEvent::from(KeyCode::Down), &ctx);
        }
        assert_eq!(p.list.cursor, 2);
        assert!(p.selected().is_some());
        for _ in 0..10 {
            p.on_key(KeyEvent::from(KeyCode::Up), &ctx);
        }
        assert_eq!(p.list.cursor, 0);
    }

    #[test]
    fn an_empty_panel_has_nothing_selected() {
        let p = ReportsPanel::default();
        assert!(p.selected().is_none());
    }

    #[test]
    fn clearing_the_feed_leaves_the_selection_alone() {
        let mut p = panel_with(2);
        p.list.cursor = 1;
        p.push_line("something".into());
        let ctx = Ctx {
            client: None,
            tx: tokio::sync::mpsc::unbounded_channel().0,
        };
        p.on_key(KeyEvent::from(KeyCode::Char('c')), &ctx);
        assert!(p.feed.is_empty());
        assert_eq!(p.list.cursor, 1);
    }
}
