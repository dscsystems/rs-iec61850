//! Datasets: list them and read their members.

use iec61850::client::{AcsiClass, DataSet};
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

#[derive(Default)]
pub struct DatasetsPanel {
    list: ListBox,
    pub refs: Vec<ObjectReference>,
    pub current: Option<DataSet>,
}

impl DatasetsPanel {
    pub fn load(&mut self, ctx: &Ctx) {
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let devices = match client.logical_devices().await {
                Ok(d) => d,
                Err(e) => return ctx.err(format!("datasets: {e}")),
            };
            let mut refs = Vec::new();
            for ld in &devices {
                let found = client
                    .browse(ld, &[AcsiClass::DataSet])
                    .await
                    .unwrap_or_default();
                refs.extend(found.into_iter().map(|e| e.reference));
            }
            ctx.send(Msg::DatasetsLoaded(refs));
        });
    }

    pub fn on_key(&mut self, key: KeyEvent, ctx: &Ctx) -> Option<Dialog> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.list.move_by(-1, self.refs.len()),
            KeyCode::Down | KeyCode::Char('j') => self.list.move_by(1, self.refs.len()),
            KeyCode::Home | KeyCode::Char('g') => self.list.first(),
            KeyCode::End | KeyCode::Char('G') => self.list.last(self.refs.len()),
            KeyCode::Enter | KeyCode::Char('r') => self.read(ctx),
            _ => {}
        }
        None
    }

    fn read(&mut self, ctx: &Ctx) {
        let Some(reference) = self.refs.get(self.list.cursor).cloned() else {
            return;
        };
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match client.read_data_set(reference).await {
                Ok(ds) => ctx.send(Msg::DatasetRead(Box::new(ds))),
                Err(e) => ctx.err(format!("read dataset: {e}")),
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
                    self.read(ctx);
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
            .render(f, cols[0], "Datasets", refs.len(), move |i| {
                Line::raw(refs[i].to_string())
            });

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .title("Members");
        let inner = block.inner(cols[1]);
        f.render_widget(block, cols[1]);

        let lines: Vec<Line> = match &self.current {
            None => vec![Line::styled(
                "select a dataset and press enter",
                theme::muted(),
            )],
            Some(ds) => {
                let mut out = vec![
                    Line::styled(ds.reference.to_string(), theme::label()),
                    Line::raw(""),
                ];
                for m in &ds.members {
                    out.push(Line::from(vec![
                        Span::raw(m.reference.to_string()),
                        Span::styled(format!(" [{}] = ", m.fc), theme::muted()),
                        Span::styled(
                            m.value
                                .as_ref()
                                .map_or("(none)".to_string(), |v| v.to_string()),
                            theme::value(),
                        ),
                    ]));
                }
                out
            }
        };
        f.render_widget(Paragraph::new(lines), inner);

        f.render_widget(
            Paragraph::new(Line::styled(
                "↑↓ select · enter/r read the dataset",
                theme::help(),
            )),
            rows[1],
        );
    }
}

fn left_width(width: u16) -> u16 {
    widgets::left_width(width, 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_stays_within_the_list() {
        let mut p = DatasetsPanel {
            refs: (0..3)
                .map(|i| ObjectReference::new(format!("LD/LLN0.DS{i}")))
                .collect(),
            ..Default::default()
        };
        let ctx = Ctx {
            client: None,
            tx: tokio::sync::mpsc::unbounded_channel().0,
        };
        for _ in 0..10 {
            p.on_key(KeyEvent::from(KeyCode::Down), &ctx);
        }
        assert_eq!(p.list.cursor, 2);
        p.scroll(true);
        assert_eq!(p.list.cursor, 1);
    }

    #[test]
    fn the_panes_split_sensibly_at_any_width() {
        for width in [40u16, 80, 200] {
            let left = left_width(width);
            assert!(left > 0 && left < width, "width={width}");
        }
    }
}
