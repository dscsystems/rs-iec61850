//! Controllable objects: find them and open the operate dialog.

use iec61850::mms::ObjectClass;
use iec61850::model::ObjectReference;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{Ctx, Msg};
use crate::dialogs::Dialog;
use crate::theme;
use crate::widgets::ListBox;

#[derive(Default)]
pub struct ControlsPanel {
    list: ListBox,
    pub refs: Vec<ObjectReference>,
}

impl ControlsPanel {
    pub fn load(&mut self, ctx: &Ctx) {
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let devices = match client.logical_devices().await {
                Ok(d) => d,
                Err(e) => return ctx.err(format!("controls: {e}")),
            };
            let mut refs: Vec<ObjectReference> = Vec::new();
            for ld in &devices {
                let names = client
                    .mms()
                    .get_name_list(ObjectClass::NamedVariable, ld)
                    .await
                    .unwrap_or_default();
                for n in &names {
                    if let Some(reference) = controllable_ref(ld, n) {
                        if !refs.contains(&reference) {
                            refs.push(reference);
                        }
                    }
                }
            }
            ctx.send(Msg::ControlsLoaded(refs));
        });
    }

    fn selected(&self) -> Option<ObjectReference> {
        self.refs.get(self.list.cursor).cloned()
    }

    pub fn on_key(&mut self, key: KeyEvent, _ctx: &Ctx) -> Option<Dialog> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.list.move_by(-1, self.refs.len()),
            KeyCode::Down | KeyCode::Char('j') => self.list.move_by(1, self.refs.len()),
            KeyCode::Home | KeyCode::Char('g') => self.list.first(),
            KeyCode::End | KeyCode::Char('G') => self.list.last(self.refs.len()),
            KeyCode::Enter | KeyCode::Char('o') => {
                return self.selected().map(Dialog::control);
            }
            _ => {}
        }
        None
    }

    pub fn scroll(&mut self, up: bool) {
        self.list.move_by(if up { -1 } else { 1 }, self.refs.len());
    }

    pub fn on_click(&mut self, _x: u16, y: u16, _width: u16, _ctx: &Ctx) -> Option<Dialog> {
        let row = y.checked_sub(1)?;
        if self.list.click_row(row as usize, self.refs.len()) {
            return self.selected().map(Dialog::control);
        }
        None
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);

        let refs = self.refs.clone();
        self.list
            .render(f, rows[0], "Controllable objects", refs.len(), move |i| {
                Line::from(vec![
                    Span::styled("⚡ ", theme::accent()),
                    Span::raw(refs[i].to_string()),
                ])
            });

        f.render_widget(
            Paragraph::new(Line::styled(
                "↑↓ select · enter/o operate (opens the operate dialog)",
                theme::help(),
            )),
            rows[1],
        );
    }
}

/// Recognises a controllable object from an MMS variable name.
///
/// `LN$CO$DO[$SDO]$Oper` is what marks one: the control constraint plus an
/// operate attribute. The reference drops the constraint, since a control
/// object is addressed without it.
fn controllable_ref(ld: &str, name: &str) -> Option<ObjectReference> {
    let parts: Vec<&str> = name.split('$').collect();
    if parts.len() < 4 || parts[1] != "CO" || *parts.last()? != "Oper" {
        return None;
    }
    let object = parts[2..parts.len() - 1].join(".");
    Some(ObjectReference::new(format!("{ld}/{}.{object}", parts[0])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_operate_attribute_marks_a_controllable_object() {
        assert_eq!(
            controllable_ref("LD", "GGIO1$CO$SPCSO1$Oper"),
            Some(ObjectReference::new("LD/GGIO1.SPCSO1"))
        );
        // A sub-object path is kept.
        assert_eq!(
            controllable_ref("LD", "XCBR1$CO$Pos$Oper"),
            Some(ObjectReference::new("LD/XCBR1.Pos"))
        );
    }

    #[test]
    fn other_names_are_not_controllable_objects() {
        assert!(controllable_ref("LD", "GGIO1$ST$Ind1$stVal").is_none());
        assert!(controllable_ref("LD", "GGIO1$CO$SPCSO1$SBOw").is_none());
        assert!(
            controllable_ref("LD", "GGIO1$CO$SPCSO1$Oper$ctlVal").is_none(),
            "a member inside Oper names the same object; one entry is enough"
        );
        assert!(controllable_ref("LD", "GGIO1").is_none());
        assert!(controllable_ref("LD", "").is_none());
    }

    #[test]
    fn enter_opens_the_operate_dialog_for_the_selected_object() {
        let mut p = ControlsPanel {
            refs: vec![ObjectReference::new("LD/GGIO1.SPCSO1")],
            ..Default::default()
        };
        let ctx = Ctx {
            client: None,
            tx: tokio::sync::mpsc::unbounded_channel().0,
        };
        let d = p.on_key(KeyEvent::from(KeyCode::Enter), &ctx);
        assert!(matches!(d, Some(Dialog::Control(_))));
    }

    #[test]
    fn an_empty_panel_opens_nothing() {
        let mut p = ControlsPanel::default();
        let ctx = Ctx {
            client: None,
            tx: tokio::sync::mpsc::unbounded_channel().0,
        };
        assert!(p.on_key(KeyEvent::from(KeyCode::Enter), &ctx).is_none());
    }
}
