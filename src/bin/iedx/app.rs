//! The application: tabs, the message loop's state, and the frame layout.

use std::sync::Arc;

use iec61850::client::{Client, DataSet, FileEntry, LogEntry, Options};
use iec61850::model::ObjectReference;
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;
use tokio::sync::mpsc::UnboundedSender;

use crate::browse::BrowsePanel;
use crate::controls::ControlsPanel;
use crate::datasets::DatasetsPanel;
use crate::dialogs::{ConnectForm, Dialog};
use crate::files::FilesPanel;
use crate::logs::LogsPanel;
use crate::reports::{ReportsPanel, RcbItem};
use crate::settings::{SettingsPanel, SgInfo};
use crate::theme::{self, StatusKind};
use crate::widgets::clip;

/// Everything a background task sends back to the UI.
///
/// The Go original returns a `tea.Cmd`; here a task owns a clone of the sender
/// and posts its result, which keeps every await off the render path.
#[derive(Debug)]
pub enum Msg {
    Connected {
        client: Arc<Client>,
        ident: String,
    },
    ConnectFailed(String),
    Status(String, StatusKind),

    ModelLoaded(Vec<crate::browse::Node>),
    /// A value read for one node of the browse tree, addressed by its index in
    /// the arena rather than by pointer.
    Value {
        node: usize,
        text: String,
        is_err: bool,
    },

    RcbsLoaded(Vec<RcbItem>),
    ReportEnabled(ObjectReference, Arc<iec61850::client::ReportSubscription>),
    ReportLine(String),

    DatasetsLoaded(Vec<ObjectReference>),
    DatasetRead(Box<DataSet>),

    ControlsLoaded(Vec<ObjectReference>),

    SgcbsLoaded(Vec<ObjectReference>),
    SgLoaded(SgInfo),

    FilesLoaded(Vec<FileEntry>),
    LogsLoaded(Vec<ObjectReference>),
    LogQueried(Vec<LogEntry>),
}

/// What a panel needs to do its work: the connection and a way to answer.
#[derive(Clone)]
pub struct Ctx {
    pub client: Option<Arc<Client>>,
    pub tx: UnboundedSender<Msg>,
}

impl Ctx {
    /// Returns the connection, reporting the problem if there is none.
    pub fn client(&self) -> Option<Arc<Client>> {
        match &self.client {
            Some(c) => Some(Arc::clone(c)),
            None => {
                self.status("not connected", StatusKind::Err);
                None
            }
        }
    }

    pub fn send(&self, m: Msg) {
        let _ = self.tx.send(m);
    }

    pub fn status(&self, text: impl Into<String>, kind: StatusKind) {
        self.send(Msg::Status(text.into(), kind));
    }

    pub fn ok(&self, text: impl Into<String>) {
        self.status(text, StatusKind::Ok);
    }

    pub fn err(&self, text: impl Into<String>) {
        self.status(text, StatusKind::Err);
    }
}

/// The tabs, in the order they appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Browse,
    Reports,
    Datasets,
    Controls,
    SettingGroups,
    Files,
    Logs,
}

impl Tab {
    pub const ALL: [Tab; 7] = [
        Tab::Browse,
        Tab::Reports,
        Tab::Datasets,
        Tab::Controls,
        Tab::SettingGroups,
        Tab::Files,
        Tab::Logs,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Browse => "Browse",
            Tab::Reports => "Reports",
            Tab::Datasets => "Datasets",
            Tab::Controls => "Controls",
            Tab::SettingGroups => "SetGroups",
            Tab::Files => "Files",
            Tab::Logs => "Logs",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

pub struct App {
    pub addr: String,
    pub password: String,
    pub tls: bool,

    pub ctx: Ctx,
    pub ident: String,
    pub connected: bool,
    /// Which tabs have fetched their data, so switching back is instant.
    loaded: [bool; 7],

    pub active: Tab,
    pub dialog: Option<Dialog>,
    pub connect_form: Option<ConnectForm>,

    pub status: String,
    pub status_kind: StatusKind,
    pub should_quit: bool,

    pub browse: BrowsePanel,
    pub reports: ReportsPanel,
    pub datasets: DatasetsPanel,
    pub controls: ControlsPanel,
    pub settings: SettingsPanel,
    pub files: FilesPanel,
    pub logs: LogsPanel,

    /// The content area of the last frame, so a mouse click can be mapped back
    /// to it without the panels having to know the chrome's height.
    content: Rect,
    tab_spans: Vec<(u16, u16)>,
}

impl App {
    pub fn new(addr: String, password: String, tls: bool, tx: UnboundedSender<Msg>) -> App {
        App {
            addr,
            password,
            tls,
            ctx: Ctx { client: None, tx },
            ident: String::new(),
            connected: false,
            loaded: [false; 7],
            active: Tab::Browse,
            dialog: None,
            connect_form: None,
            status: String::new(),
            status_kind: StatusKind::Info,
            should_quit: false,
            browse: BrowsePanel::default(),
            reports: ReportsPanel::default(),
            datasets: DatasetsPanel::default(),
            controls: ControlsPanel::default(),
            settings: SettingsPanel::default(),
            files: FilesPanel::default(),
            logs: LogsPanel::default(),
            content: Rect::default(),
            tab_spans: Vec::new(),
        }
    }

    /// Starts the first connection, or opens the form when no address was
    /// given on the command line.
    pub fn start(&mut self) {
        if self.addr.is_empty() {
            self.connect_form = Some(ConnectForm::new(&self.addr, &self.password, self.tls));
        } else {
            self.connect();
        }
    }

    pub fn connect(&mut self) {
        self.set_status(
            format!("connecting to {} ...", self.addr),
            StatusKind::Info,
        );
        let (addr, password, tls) = (self.addr.clone(), self.password.clone(), self.tls);
        let tx = self.ctx.tx.clone();
        tokio::spawn(async move {
            let mut opts = Options::new().with_timeout(std::time::Duration::from_secs(6));
            if !password.is_empty() {
                opts = opts.with_password(password);
            }
            if tls {
                // The TLS path needs a trust configuration the UI has no way to
                // ask for; say so rather than silently connecting in the clear.
                let _ = tx.send(Msg::ConnectFailed(
                    "TLS needs a certificate configuration; use the library API".into(),
                ));
                return;
            }
            match Client::dial_with(&addr, opts).await {
                Ok(c) => {
                    let ident = match c.mms().identify().await {
                        Ok((v, m, r)) => {
                            format!("{v} {m} {r}").split_whitespace().collect::<Vec<_>>().join(" ")
                        }
                        Err(_) => String::new(),
                    };
                    let _ = tx.send(Msg::Connected {
                        client: Arc::new(c),
                        ident,
                    });
                }
                Err(e) => {
                    let _ = tx.send(Msg::ConnectFailed(e.to_string()));
                }
            }
        });
    }

    pub fn set_status(&mut self, text: impl Into<String>, kind: StatusKind) {
        self.status = text.into();
        self.status_kind = kind;
    }

    /// Loads the active tab's data, once.
    fn load_active(&mut self) {
        let i = self.active.index();
        if self.loaded[i] {
            return;
        }
        self.loaded[i] = true;
        self.reload_active();
    }

    fn reload_active(&mut self) {
        let ctx = self.ctx.clone();
        match self.active {
            Tab::Browse => self.browse.load(&ctx),
            Tab::Reports => self.reports.load(&ctx),
            Tab::Datasets => self.datasets.load(&ctx),
            Tab::Controls => self.controls.load(&ctx),
            Tab::SettingGroups => self.settings.load(&ctx),
            Tab::Files => self.files.load(&ctx),
            Tab::Logs => self.logs.load(&ctx),
        }
    }

    // ---- messages ----

    pub fn on_msg(&mut self, msg: Msg) {
        match msg {
            Msg::Connected { client, ident } => {
                self.ctx.client = Some(client);
                self.ident = ident;
                self.connected = true;
                self.connect_form = None;
                let addr = self.addr.clone();
                self.set_status(format!("connected to {addr}"), StatusKind::Ok);
                self.load_active();
            }
            Msg::ConnectFailed(e) => {
                self.set_status(format!("connect failed: {e}"), StatusKind::Err);
                if self.connect_form.is_none() {
                    self.connect_form =
                        Some(ConnectForm::new(&self.addr, &self.password, self.tls));
                }
            }
            Msg::Status(text, kind) => self.set_status(text, kind),

            Msg::ModelLoaded(nodes) => {
                let n = self.browse.set_model(nodes);
                self.set_status(format!("model loaded: {n} logical devices"), StatusKind::Ok);
            }
            Msg::Value { node, text, is_err } => self.browse.set_value(node, text, is_err),

            Msg::RcbsLoaded(rcbs) => {
                self.set_status(
                    format!("{} report control blocks", rcbs.len()),
                    StatusKind::Ok,
                );
                self.reports.rcbs = rcbs;
            }
            Msg::ReportEnabled(reference, sub) => self.reports.on_enabled(reference, sub),
            Msg::ReportLine(line) => self.reports.push_line(line),

            Msg::DatasetsLoaded(refs) => {
                self.set_status(format!("{} datasets", refs.len()), StatusKind::Ok);
                self.datasets.refs = refs;
            }
            Msg::DatasetRead(ds) => {
                self.set_status(
                    format!("{}: {} members", ds.reference, ds.members.len()),
                    StatusKind::Ok,
                );
                self.datasets.current = Some(*ds);
            }

            Msg::ControlsLoaded(refs) => {
                self.set_status(
                    format!("{} controllable objects", refs.len()),
                    StatusKind::Ok,
                );
                self.controls.refs = refs;
            }

            Msg::SgcbsLoaded(refs) => {
                if refs.is_empty() {
                    self.set_status("no setting group control blocks", StatusKind::Info);
                } else {
                    self.set_status(
                        format!("{} setting group control blocks", refs.len()),
                        StatusKind::Ok,
                    );
                }
                self.settings.refs = refs;
                let ctx = self.ctx.clone();
                self.settings.read_selected(&ctx);
            }
            Msg::SgLoaded(info) => self.settings.current = Some(info),

            Msg::FilesLoaded(entries) => {
                self.set_status(format!("{} entries", entries.len()), StatusKind::Ok);
                self.files.entries = entries;
            }
            Msg::LogsLoaded(refs) => {
                self.set_status(format!("{} logs", refs.len()), StatusKind::Ok);
                self.logs.refs = refs;
            }
            Msg::LogQueried(entries) => {
                self.set_status(format!("{} log entries", entries.len()), StatusKind::Ok);
                self.logs.entries = entries;
            }
        }
    }

    // ---- input ----

    pub fn on_key(&mut self, key: KeyEvent) {
        // Ctrl-C always quits, whatever has focus.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.should_quit = true;
            return;
        }

        // A modal dialog captures everything while it is open.
        if let Some(mut d) = self.dialog.take() {
            let ctx = self.ctx.clone();
            if !d.on_key(key, &ctx) {
                self.dialog = Some(d);
            }
            return;
        }

        if !self.connected {
            if let Some(mut form) = self.connect_form.take() {
                match form.on_key(key) {
                    crate::dialogs::FormAction::Stay => self.connect_form = Some(form),
                    crate::dialogs::FormAction::Quit => self.should_quit = true,
                    crate::dialogs::FormAction::Submit => {
                        // An address typed here gets the default port just as
                        // one given on the command line does.
                        self.addr = crate::normalise_addr(&form.address());
                        self.password = form.password();
                        self.tls = form.tls();
                        self.connect_form = Some(form);
                        if self.addr.is_empty() {
                            self.set_status("enter an address", StatusKind::Err);
                        } else {
                            self.connect();
                        }
                    }
                }
            }
            return;
        }

        // Global keys, then the active panel — unless the panel is taking
        // text, in which case every key is its own: a browse filter has to be
        // able to contain a 'q' or a digit.
        let capturing = self.active == Tab::Browse && self.browse.is_capturing();
        match key.code {
            _ if capturing => {}
            KeyCode::Char('q') => {
                self.should_quit = true;
                return;
            }
            KeyCode::Tab | KeyCode::Char(']') => {
                let i = (self.active.index() + 1) % Tab::ALL.len();
                self.active = Tab::ALL[i];
                self.load_active();
                return;
            }
            KeyCode::BackTab | KeyCode::Char('[') => {
                let i = (self.active.index() + Tab::ALL.len() - 1) % Tab::ALL.len();
                self.active = Tab::ALL[i];
                self.load_active();
                return;
            }
            KeyCode::Char(c @ '1'..='7') => {
                // The setting-groups panel uses the digits to activate a group,
                // so it keeps them for itself while it has a block to act on.
                if self.active != Tab::SettingGroups || !self.settings.takes_digits() {
                    self.active = Tab::ALL[c as usize - '1' as usize];
                    self.load_active();
                    return;
                }
            }
            KeyCode::Char('R') => {
                self.reload_active();
                return;
            }
            KeyCode::Char('?') => {
                self.dialog = Some(Dialog::help());
                return;
            }
            _ => {}
        }

        let ctx = self.ctx.clone();
        let dialog = match self.active {
            Tab::Browse => self.browse.on_key(key, &ctx),
            Tab::Reports => self.reports.on_key(key, &ctx),
            Tab::Datasets => self.datasets.on_key(key, &ctx),
            Tab::Controls => self.controls.on_key(key, &ctx),
            Tab::SettingGroups => self.settings.on_key(key, &ctx),
            Tab::Files => self.files.on_key(key, &ctx),
            Tab::Logs => self.logs.on_key(key, &ctx),
        };
        if let Some(d) = dialog {
            self.dialog = Some(d);
        }
    }

    pub fn on_mouse(&mut self, m: MouseEvent) {
        if self.dialog.is_some() {
            // A click anywhere dismisses the help; the other dialogs are
            // keyboard-driven and ignore the mouse rather than acting on a
            // stray click near a confirm button.
            if matches!(m.kind, MouseEventKind::Down(_)) {
                if let Some(d) = &self.dialog {
                    if d.dismissable_by_click() {
                        self.dialog = None;
                    }
                }
            }
            return;
        }
        if !self.connected {
            return;
        }

        let ctx = self.ctx.clone();
        match m.kind {
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                let up = matches!(m.kind, MouseEventKind::ScrollUp);
                match self.active {
                    Tab::Browse => self.browse.scroll(up),
                    Tab::Reports => self.reports.scroll(up),
                    Tab::Datasets => self.datasets.scroll(up),
                    Tab::Controls => self.controls.scroll(up),
                    Tab::SettingGroups => {
                        self.settings.scroll(up);
                        self.settings.read_selected(&ctx);
                    }
                    Tab::Files => self.files.scroll(up),
                    Tab::Logs => self.logs.scroll(up),
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                // The tab bar is the second row.
                if m.row == 1 {
                    for (i, (start, end)) in self.tab_spans.iter().enumerate() {
                        if m.column >= *start && m.column < *end {
                            self.active = Tab::ALL[i];
                            self.load_active();
                            return;
                        }
                    }
                    return;
                }
                if !rect_contains(self.content, m.column, m.row) {
                    return;
                }
                let x = m.column - self.content.x;
                let y = m.row - self.content.y;
                let dialog = match self.active {
                    Tab::Browse => self.browse.on_click(x, y, self.content.width, &ctx),
                    Tab::Reports => self.reports.on_click(x, y, self.content.width, &ctx),
                    Tab::Datasets => self.datasets.on_click(x, y, self.content.width, &ctx),
                    Tab::Controls => self.controls.on_click(x, y, self.content.width, &ctx),
                    Tab::SettingGroups => {
                        self.settings.on_click(x, y, self.content.width, &ctx)
                    }
                    Tab::Files => self.files.on_click(x, y, self.content.width, &ctx),
                    Tab::Logs => self.logs.on_click(x, y, self.content.width, &ctx),
                };
                if let Some(d) = dialog {
                    self.dialog = Some(d);
                }
            }
            _ => {}
        }
    }

    // ---- rendering ----

    pub fn draw(&mut self, f: &mut Frame) {
        let area = f.area();
        if !self.connected {
            self.draw_disconnected(f, area);
            return;
        }

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // header
                Constraint::Length(1), // tabs
                Constraint::Min(3),    // content
                Constraint::Length(1), // status
                Constraint::Length(1), // help
            ])
            .split(area);

        let title = if self.ident.is_empty() {
            format!(" iedx  ·  {} ", self.addr)
        } else {
            format!(" iedx  ·  {}  ·  {} ", self.ident, self.addr)
        };
        f.render_widget(
            Paragraph::new(Line::styled(
                clip(&title, area.width as usize),
                theme::header(),
            ))
            .style(theme::header()),
            rows[0],
        );

        self.draw_tabs(f, rows[1]);

        self.content = rows[2];
        let ctx = self.ctx.clone();
        match self.active {
            Tab::Browse => self.browse.draw(f, rows[2]),
            Tab::Reports => self.reports.draw(f, rows[2]),
            Tab::Datasets => self.datasets.draw(f, rows[2]),
            Tab::Controls => self.controls.draw(f, rows[2]),
            Tab::SettingGroups => self.settings.draw(f, rows[2]),
            Tab::Files => self.files.draw(f, rows[2]),
            Tab::Logs => self.logs.draw(f, rows[2]),
        }
        let _ = ctx;

        f.render_widget(
            Paragraph::new(Line::styled(
                clip(&self.status, area.width as usize),
                self.status_kind.style(),
            )),
            rows[3],
        );
        f.render_widget(
            Paragraph::new(Line::styled(
                clip(
                    "tab/1-7 switch · R refresh · ? help · q quit · mouse: click tabs & rows, wheel scrolls",
                    area.width as usize,
                ),
                theme::help(),
            )),
            rows[4],
        );

        if let Some(d) = &self.dialog {
            d.draw(f, area);
        }
    }

    fn draw_tabs(&mut self, f: &mut Frame, area: Rect) {
        let mut spans: Vec<Span> = Vec::new();
        self.tab_spans.clear();
        let mut x = area.x;
        for (i, t) in Tab::ALL.iter().enumerate() {
            let label = format!(" {} {} ", i + 1, t.title());
            let w = label.chars().count() as u16;
            self.tab_spans.push((x, x + w));
            x += w;
            let style = if *t == self.active {
                theme::tab_active()
            } else {
                theme::tab()
            };
            spans.push(Span::styled(label, style));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn draw_disconnected(&mut self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);
        match &self.connect_form {
            Some(form) => form.draw(f, rows[0]),
            None => f.render_widget(
                Paragraph::new(Line::styled("iedx: connecting...", theme::muted())),
                rows[0],
            ),
        }
        f.render_widget(
            Paragraph::new(Line::styled(
                clip(&self.status, area.width as usize),
                self.status_kind.style(),
            )),
            rows[1],
        );
        if let Some(d) = &self.dialog {
            d.draw(f, area);
        }
    }
}

fn rect_contains(r: Rect, x: u16, y: u16) -> bool {
    x >= r.x && x < r.x + r.width && y >= r.y && y < r.y + r.height
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        App::new("127.0.0.1:102".into(), String::new(), false, tx)
    }

    #[test]
    fn every_tab_has_a_distinct_title_and_index() {
        let mut titles: Vec<&str> = Tab::ALL.iter().map(|t| t.title()).collect();
        titles.sort_unstable();
        titles.dedup();
        assert_eq!(titles.len(), Tab::ALL.len());
        for (i, t) in Tab::ALL.iter().enumerate() {
            assert_eq!(t.index(), i);
        }
    }

    #[test]
    fn tab_keys_cycle_in_both_directions_and_wrap() {
        let mut a = app();
        a.connected = true;
        assert_eq!(a.active, Tab::Browse);

        a.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(a.active, Tab::Reports);

        a.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
        assert_eq!(a.active, Tab::Browse);

        // Wrapping backwards from the first tab lands on the last.
        a.on_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
        assert_eq!(a.active, Tab::Logs);
        a.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(a.active, Tab::Browse);
    }

    #[test]
    fn number_keys_select_a_tab_directly() {
        let mut a = app();
        a.connected = true;
        a.on_key(KeyEvent::new(KeyCode::Char('4'), KeyModifiers::NONE));
        assert_eq!(a.active, Tab::Controls);
        a.on_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE));
        assert_eq!(a.active, Tab::Browse);
    }

    /// The setting-groups panel uses the digits to activate a group, so it has
    /// to keep them rather than have the tab bar swallow them.
    #[test]
    fn the_setting_groups_panel_keeps_the_number_keys() {
        let mut a = app();
        a.connected = true;
        a.active = Tab::SettingGroups;
        a.settings.current = Some(SgInfo {
            reference: ObjectReference::new("LD/LLN0.SP.SGCB"),
            num_of_sg: 4,
            act_sg: 1,
            edit_sg: 0,
        });
        a.on_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
        assert_eq!(a.active, Tab::SettingGroups, "the tab must not change");
    }

    /// A device without setting groups has nothing for the digits to do, and
    /// swallowing them there would leave the tab with no way out.
    #[test]
    fn the_digits_switch_tabs_again_when_there_is_no_group_to_activate() {
        let mut a = app();
        a.connected = true;
        a.active = Tab::SettingGroups;
        assert!(a.settings.current.is_none());
        a.on_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE));
        assert_eq!(a.active, Tab::Browse);
    }

    /// `q` and the digits are ordinary characters while the filter is open;
    /// letting the tab bar have them would quit on a reference containing a q.
    #[test]
    fn the_browse_filter_keeps_every_key_it_is_typed() {
        let mut a = app();
        a.connected = true;
        a.on_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        for c in "q1R?".chars() {
            a.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert!(!a.should_quit, "the q was text");
        assert_eq!(a.active, Tab::Browse, "the 1 was text");
        assert!(a.dialog.is_none(), "the ? was text");
        assert_eq!(a.browse.filter(), "q1R?");

        // Ctrl-C still gets out, whatever is being typed.
        a.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert!(a.should_quit);
    }

    #[test]
    fn ctrl_c_quits_from_anywhere() {
        for connected in [false, true] {
            let mut a = app();
            a.connected = connected;
            a.dialog = Some(Dialog::help());
            a.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
            assert!(a.should_quit, "connected={connected}");
        }
    }

    /// A dialog is modal: keys must not reach the tab bar behind it, or a
    /// confirm prompt could be navigated away from mid-decision.
    #[test]
    fn a_dialog_captures_keys() {
        let mut a = app();
        a.connected = true;
        a.dialog = Some(Dialog::help());
        a.on_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(a.active, Tab::Browse, "the tab must not have changed");
        assert!(a.dialog.is_none(), "any key closes the help");
    }

    #[test]
    fn q_does_not_quit_while_a_dialog_is_open() {
        let mut a = app();
        a.connected = true;
        a.dialog = Some(Dialog::write(
            "LD/LN.DO.da".into(),
            iec61850::model::Fc::Cf,
            Some(iec61850::mms::Type::Boolean),
        ));
        a.on_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!a.should_quit, "q is text for the dialog's field");
    }

    #[test]
    fn a_tab_loads_once_and_reload_forces_it_again() {
        let mut a = app();
        a.connected = true;
        assert!(!a.loaded[Tab::Browse.index()]);
        a.load_active();
        assert!(a.loaded[Tab::Browse.index()]);
        // Loading again is a no-op; only R re-fetches, which is what keeps
        // switching back to a tab instant.
        a.load_active();
    }

    #[test]
    fn a_status_message_updates_the_line_and_its_colour() {
        let mut a = app();
        a.on_msg(Msg::Status("hello".into(), StatusKind::Ok));
        assert_eq!(a.status, "hello");
        assert_eq!(a.status_kind, StatusKind::Ok);
    }

    /// The form takes a bare host just as the command line does, or the
    /// connection would be attempted against an address with no port.
    /// Submitting starts the dial, which needs a runtime to spawn on.
    #[tokio::test]
    async fn an_address_typed_into_the_form_gets_the_default_port() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut a = App::new(String::new(), String::new(), false, tx);
        a.start();
        for c in "192.0.2.7".chars() {
            a.on_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        a.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(a.addr, "192.0.2.7:102");
    }

    #[test]
    fn a_failed_connection_reopens_the_form() {
        let mut a = app();
        assert!(a.connect_form.is_none());
        a.on_msg(Msg::ConnectFailed("refused".into()));
        assert!(a.connect_form.is_some(), "the user needs a way to retry");
        assert_eq!(a.status_kind, StatusKind::Err);
        assert!(a.status.contains("refused"));
    }

    #[test]
    fn rect_containment_excludes_the_far_edges() {
        let r = Rect::new(2, 3, 10, 5);
        assert!(rect_contains(r, 2, 3));
        assert!(rect_contains(r, 11, 7));
        assert!(!rect_contains(r, 12, 7), "x is exclusive at the right edge");
        assert!(!rect_contains(r, 11, 8), "y is exclusive at the bottom");
        assert!(!rect_contains(r, 1, 3));
    }
}
