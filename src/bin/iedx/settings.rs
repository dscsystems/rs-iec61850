//! Setting group control blocks: read them and activate a group.

use iec61850::client::AcsiClass;
use iec61850::model::ObjectReference;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::{Ctx, Msg};
use crate::dialogs::Dialog;
use crate::theme;
use crate::widgets::{self, ListBox};

/// A setting group control block as the panel shows it.
#[derive(Debug, Clone)]
pub struct SgInfo {
    pub reference: ObjectReference,
    pub num_of_sg: u8,
    pub act_sg: u8,
    pub edit_sg: u8,
}

#[derive(Default)]
pub struct SettingsPanel {
    list: ListBox,
    pub refs: Vec<ObjectReference>,
    pub current: Option<SgInfo>,
}

impl SettingsPanel {
    pub fn load(&mut self, ctx: &Ctx) {
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let devices = match client.logical_devices().await {
                Ok(d) => d,
                Err(e) => return ctx.err(format!("setting groups: {e}")),
            };
            let mut refs = Vec::new();
            for ld in &devices {
                let found = client
                    .browse(ld, &[AcsiClass::Sgcb])
                    .await
                    .unwrap_or_default();
                refs.extend(found.into_iter().map(|e| e.reference));
            }
            ctx.send(Msg::SgcbsLoaded(refs));
        });
    }

    pub fn read_selected(&mut self, ctx: &Ctx) {
        let Some(reference) = self.refs.get(self.list.cursor).cloned() else {
            return;
        };
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match client.setting_groups(reference.clone()).await {
                Ok(sg) => ctx.send(Msg::SgLoaded(SgInfo {
                    reference,
                    num_of_sg: sg.num_of_sg,
                    act_sg: sg.act_sg,
                    edit_sg: sg.edit_sg,
                })),
                Err(e) => ctx.err(format!("read SGCB: {e}")),
            }
        });
    }

    /// Whether the digits mean "activate this group" here.
    ///
    /// They only do once a control block has been read; with nothing to act on
    /// they belong to the tab bar, or a device without setting groups would
    /// leave this tab with no way out but the tab key.
    pub fn takes_digits(&self) -> bool {
        self.current.is_some()
    }

    pub fn on_key(&mut self, key: KeyEvent, ctx: &Ctx) -> Option<Dialog> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.list.move_by(-1, self.refs.len());
                self.read_selected(ctx);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.list.move_by(1, self.refs.len());
                self.read_selected(ctx);
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.list.first();
                self.read_selected(ctx);
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.list.last(self.refs.len());
                self.read_selected(ctx);
            }
            // The digits activate a group here rather than switching tabs.
            KeyCode::Char(c @ '1'..='9') => {
                self.activate(c as u8 - b'0', ctx);
            }
            _ => {}
        }
        None
    }

    fn activate(&mut self, group: u8, ctx: &Ctx) {
        let Some(info) = self.current.clone() else {
            ctx.err("no setting group control block selected");
            return;
        };
        if group > info.num_of_sg {
            ctx.err(format!("only {} setting groups", info.num_of_sg));
            return;
        }
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let mut sg = match client.setting_groups(info.reference.clone()).await {
                Ok(sg) => sg,
                Err(e) => return ctx.err(format!("select active SG: {e}")),
            };
            match sg.select_active_sg(group).await {
                Ok(()) => {
                    ctx.ok(format!("active setting group = {group}"));
                    ctx.send(Msg::SgLoaded(SgInfo {
                        reference: info.reference,
                        num_of_sg: sg.num_of_sg,
                        act_sg: sg.act_sg,
                        edit_sg: sg.edit_sg,
                    }));
                }
                Err(e) => ctx.err(format!("select active SG: {e}")),
            }
        });
    }

    pub fn scroll(&mut self, up: bool) {
        self.list.move_by(if up { -1 } else { 1 }, self.refs.len());
    }

    pub fn on_click(&mut self, x: u16, y: u16, width: u16, ctx: &Ctx) -> Option<Dialog> {
        if x < left_width(width) {
            if let Some(row) = y.checked_sub(1) {
                if self.list.click_row(row as usize, self.refs.len()) {
                    self.read_selected(ctx);
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

        let refs = self.refs.clone();
        self.list
            .render(f, cols[0], "Control blocks", refs.len(), move |i| {
                Line::raw(refs[i].to_string())
            });

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .title("Setting groups");
        let inner = block.inner(cols[1]);
        f.render_widget(block, cols[1]);

        let lines: Vec<Line> = match &self.current {
            None => vec![Line::styled(
                "select a setting group control block",
                theme::muted(),
            )],
            Some(sg) => vec![
                Line::styled(sg.reference.to_string(), theme::label()),
                Line::raw(""),
                field("Number of groups", sg.num_of_sg),
                field("Active group", sg.act_sg),
                field("Edit group", sg.edit_sg),
                Line::raw(""),
                Line::styled("press 1-9 to activate that group", theme::muted()),
            ],
        };
        f.render_widget(Paragraph::new(lines), inner);

        f.render_widget(
            Paragraph::new(Line::styled(
                "↑↓ select block · 1-9 activate a group",
                theme::help(),
            )),
            rows[1],
        );
    }
}

fn field(name: &str, value: u8) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("{name:<18}: ")),
        Span::styled(value.to_string(), theme::value()),
    ])
}

fn left_width(width: u16) -> u16 {
    widgets::left_width(width, 30)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::StatusKind;

    fn ctx() -> (Ctx, tokio::sync::mpsc::UnboundedReceiver<Msg>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Ctx { client: None, tx }, rx)
    }

    /// Asking for a group the device does not have would be refused on the
    /// wire; saying so here explains why rather than showing an access error.
    #[test]
    fn a_group_beyond_the_declared_count_is_refused_locally() {
        let mut p = SettingsPanel {
            current: Some(SgInfo {
                reference: ObjectReference::new("LD/LLN0.SP.SGCB"),
                num_of_sg: 4,
                act_sg: 1,
                edit_sg: 0,
            }),
            ..Default::default()
        };
        let (c, mut rx) = ctx();
        p.activate(9, &c);
        let msg = rx.try_recv().expect("the user is told why");
        match msg {
            Msg::Status(text, StatusKind::Err) => assert!(text.contains("only 4")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn activating_without_a_selection_says_so() {
        let mut p = SettingsPanel::default();
        let (c, mut rx) = ctx();
        p.activate(1, &c);
        assert!(matches!(rx.try_recv(), Ok(Msg::Status(_, StatusKind::Err))));
    }

    #[test]
    fn the_digits_activate_a_group_rather_than_moving_the_selection() {
        let mut p = SettingsPanel {
            refs: vec![ObjectReference::new("LD/LLN0.SP.SGCB")],
            current: Some(SgInfo {
                reference: ObjectReference::new("LD/LLN0.SP.SGCB"),
                num_of_sg: 4,
                act_sg: 1,
                edit_sg: 0,
            }),
            ..Default::default()
        };
        let (c, _rx) = ctx();
        p.on_key(KeyEvent::from(KeyCode::Char('2')), &c);
        assert_eq!(p.list.cursor, 0, "the selection is unchanged");
    }
}
