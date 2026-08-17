//! The filestore: list entries and download one.

use iec61850::client::FileEntry;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{Ctx, Msg};
use crate::dialogs::Dialog;
use crate::theme::{self, StatusKind};
use crate::widgets::ListBox;

#[derive(Default)]
pub struct FilesPanel {
    list: ListBox,
    pub entries: Vec<FileEntry>,
    /// The directory being shown, empty for the filestore root.
    path: String,
}

impl FilesPanel {
    pub fn load(&mut self, ctx: &Ctx) {
        self.path.clear();
        self.list = ListBox::default();
        self.fetch(String::new(), ctx);
    }

    fn fetch(&mut self, path: String, ctx: &Ctx) {
        let Some(client) = ctx.client() else { return };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match client.file_directory(&path).await {
                Ok(entries) => ctx.send(Msg::FilesLoaded(entries)),
                Err(e) => ctx.err(format!("file directory: {e}")),
            }
        });
    }

    fn selected(&self) -> Option<&FileEntry> {
        self.entries.get(self.list.cursor)
    }

    pub fn on_key(&mut self, key: KeyEvent, ctx: &Ctx) -> Option<Dialog> {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.list.move_by(-1, self.entries.len()),
            KeyCode::Down | KeyCode::Char('j') => self.list.move_by(1, self.entries.len()),
            KeyCode::Home | KeyCode::Char('g') => self.list.first(),
            KeyCode::End | KeyCode::Char('G') => self.list.last(self.entries.len()),
            KeyCode::Enter => self.open(ctx),
            KeyCode::Char('d') => self.download(ctx),
            KeyCode::Backspace | KeyCode::Left => self.up(ctx),
            _ => {}
        }
        None
    }

    /// Descends into a directory, or downloads a file.
    ///
    /// Servers differ on whether they mark directories, so the trailing
    /// separator is what distinguishes them where it is present.
    fn open(&mut self, ctx: &Ctx) {
        let Some(entry) = self.selected() else { return };
        if let Some(dir) = entry.name.strip_suffix('/') {
            let dir = dir.to_string();
            self.path.clone_from(&dir);
            self.list = ListBox::default();
            self.fetch(dir, ctx);
        } else {
            self.download(ctx);
        }
    }

    fn up(&mut self, ctx: &Ctx) {
        if self.path.is_empty() {
            return;
        }
        let parent = match self.path.rsplit_once('/') {
            Some((p, _)) => p.to_string(),
            None => String::new(),
        };
        self.path.clone_from(&parent);
        self.list = ListBox::default();
        self.fetch(parent, ctx);
    }

    fn download(&mut self, ctx: &Ctx) {
        let Some(entry) = self.selected() else { return };
        if entry.name.ends_with('/') {
            ctx.err("that is a directory; press enter to open it");
            return;
        }
        let name = entry.name.clone();
        let Some(client) = ctx.client() else { return };
        ctx.status(format!("downloading {name} ..."), StatusKind::Info);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let data = match client.read_file(&name).await {
                Ok(d) => d,
                Err(e) => return ctx.err(format!("download failed: {e}")),
            };
            // Save under the base name in the working directory, so a nested
            // COMTRADE path does not need directories creating.
            let out = name.rsplit('/').next().unwrap_or(&name).to_string();
            match std::fs::write(&out, &data) {
                Ok(()) => ctx.ok(format!(
                    "saved {name} ({} octets) to ./{out}",
                    data.len()
                )),
                Err(e) => ctx.err(format!("save failed: {e}")),
            }
        });
    }

    pub fn scroll(&mut self, up: bool) {
        self.list
            .move_by(if up { -1 } else { 1 }, self.entries.len());
    }

    pub fn on_click(&mut self, _x: u16, y: u16, _width: u16, _ctx: &Ctx) -> Option<Dialog> {
        if let Some(row) = y.checked_sub(1) {
            self.list.click_row(row as usize, self.entries.len());
        }
        None
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);

        let title = if self.path.is_empty() {
            "Filestore /".to_string()
        } else {
            format!("Filestore /{}", self.path)
        };
        let entries = self.entries.clone();
        self.list
            .render(f, rows[0], &title, entries.len(), move |i| {
                let e = &entries[i];
                let is_dir = e.name.ends_with('/');
                Line::from(vec![
                    Span::styled(
                        if is_dir {
                            "         dir".to_string()
                        } else {
                            format!("{:>12}", e.size)
                        },
                        theme::muted(),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        e.name.clone(),
                        if is_dir {
                            theme::accent()
                        } else {
                            ratatui::style::Style::default()
                        },
                    ),
                ])
            });

        f.render_widget(
            Paragraph::new(Line::styled(
                "↑↓ select · enter open/download · d download · backspace up",
                theme::help(),
            )),
            rows[1],
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, size: u32) -> FileEntry {
        FileEntry {
            name: name.into(),
            size,
            last_modified: None,
        }
    }

    fn ctx() -> (Ctx, tokio::sync::mpsc::UnboundedReceiver<Msg>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (Ctx { client: None, tx }, rx)
    }

    #[test]
    fn entering_a_directory_descends_and_backspace_returns() {
        let mut p = FilesPanel {
            entries: vec![entry("COMTRADE/", 0), entry("readme.txt", 7)],
            ..Default::default()
        };
        let (c, _rx) = ctx();

        p.list.cursor = 0;
        p.open(&c);
        assert_eq!(p.path, "COMTRADE");
        assert_eq!(p.list.cursor, 0, "a new directory starts at the top");

        p.up(&c);
        assert_eq!(p.path, "");
        // At the root there is nowhere further up.
        p.up(&c);
        assert_eq!(p.path, "");
    }

    #[test]
    fn a_nested_path_goes_up_one_level_at_a_time() {
        let mut p = FilesPanel {
            path: "a/b/c".into(),
            ..Default::default()
        };
        let (c, _rx) = ctx();
        p.up(&c);
        assert_eq!(p.path, "a/b");
        p.up(&c);
        assert_eq!(p.path, "a");
        p.up(&c);
        assert_eq!(p.path, "");
    }

    /// Downloading a directory would fail on the wire; saying so points at the
    /// key that does work.
    #[test]
    fn downloading_a_directory_is_refused_with_advice() {
        let mut p = FilesPanel {
            entries: vec![entry("COMTRADE/", 0)],
            ..Default::default()
        };
        let (c, mut rx) = ctx();
        p.download(&c);
        match rx.try_recv().expect("the user is told") {
            Msg::Status(text, StatusKind::Err) => assert!(text.contains("directory")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn an_empty_listing_has_nothing_to_open() {
        let mut p = FilesPanel::default();
        let (c, _rx) = ctx();
        p.open(&c);
        p.download(&c);
        assert!(p.selected().is_none());
    }
}
