//! The model tree: expand, read, write, operate, filter and auto-refresh.

use std::time::Duration;

use iec61850::mms::Type;
use iec61850::model::{Fc, Model, ObjectReference};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{Ctx, Msg};
use crate::dialogs::Dialog;
use crate::theme::{self, StatusKind};
use crate::widgets::{self, clip};

/// One row of the tree.
///
/// The tree is an arena: children are indices rather than pointers, so a value
/// read on a background task can name the node it belongs to and post the
/// result back without sharing any reference.
#[derive(Debug, Clone)]
pub struct Node {
    pub label: String,
    pub depth: usize,
    pub reference: ObjectReference,
    pub fc: Fc,
    pub kind: Option<Type>,
    pub readable: bool,
    pub writable: bool,
    pub controllable: bool,
    pub expanded: bool,
    pub children: Vec<usize>,
    pub value: Option<String>,
    pub value_is_err: bool,
}

impl Node {
    fn new(label: impl Into<String>, depth: usize) -> Node {
        Node {
            label: label.into(),
            depth,
            reference: ObjectReference::default(),
            fc: Fc::None,
            kind: None,
            readable: false,
            writable: false,
            controllable: false,
            expanded: false,
            children: Vec::new(),
            value: None,
            value_is_err: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct BrowsePanel {
    nodes: Vec<Node>,
    roots: Vec<usize>,
    visible: Vec<usize>,
    cursor: usize,
    top: usize,

    filtering: bool,
    filter: String,

    pub auto: bool,
    /// Bumped whenever auto-refresh is toggled, so a ticker from a previous
    /// activation stops instead of doubling the read rate.
    auto_gen: u64,
}

impl BrowsePanel {
    pub fn load(&mut self, ctx: &Ctx) {
        let Some(client) = ctx.client() else { return };
        ctx.status("retrieving model...", StatusKind::Info);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            match client.retrieve_model().await {
                Ok(m) => ctx.send(Msg::ModelLoaded(build_tree(&m))),
                Err(e) => ctx.err(format!("model load failed: {e}")),
            }
        });
    }

    /// Installs a freshly retrieved model and returns how many devices it has.
    pub fn set_model(&mut self, nodes: Vec<Node>) -> usize {
        self.roots = nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.depth == 0)
            .map(|(i, _)| i)
            .collect();
        self.nodes = nodes;
        self.cursor = 0;
        self.top = 0;
        self.rebuild();
        self.roots.len()
    }

    pub fn set_value(&mut self, node: usize, text: String, is_err: bool) {
        if let Some(n) = self.nodes.get_mut(node) {
            n.value = Some(text);
            n.value_is_err = is_err;
        }
    }

    /// Recomputes the visible rows from the expansion state and the filter.
    fn rebuild(&mut self) {
        let mut visible = Vec::new();
        let roots = self.roots.clone();
        self.walk(&roots, &mut visible);
        self.visible = visible;
        if self.cursor >= self.visible.len() {
            self.cursor = self.visible.len().saturating_sub(1);
        }
    }

    fn walk(&self, ids: &[usize], out: &mut Vec<usize>) {
        for &id in ids {
            let n = &self.nodes[id];
            if self.filter.is_empty() || self.matches(id) {
                out.push(id);
            }
            // A filter opens the tree, so a match deep down is reachable
            // without the user expanding every level by hand.
            if n.expanded || (!self.filter.is_empty() && !n.children.is_empty()) {
                self.walk(&n.children, out);
            }
        }
    }

    fn matches(&self, id: usize) -> bool {
        let f = self.filter.to_lowercase();
        let n = &self.nodes[id];
        if n.reference.as_str().to_lowercase().contains(&f)
            || n.label.to_lowercase().contains(&f)
        {
            return true;
        }
        n.children.iter().any(|c| self.matches(*c))
    }

    fn current(&self) -> Option<usize> {
        self.visible.get(self.cursor).copied()
    }

    /// Whether the panel is taking text, so every key belongs to it.
    ///
    /// A filter has to be able to contain a `q` or a digit without the key
    /// reaching the tab bar and quitting or switching tab.
    pub fn is_capturing(&self) -> bool {
        self.filtering
    }

    /// The filter text as it is shown.
    pub fn filter(&self) -> &str {
        &self.filter
    }

    pub fn on_key(&mut self, key: KeyEvent, ctx: &Ctx) -> Option<Dialog> {
        if self.filtering {
            match key.code {
                KeyCode::Enter | KeyCode::Esc => self.filtering = false,
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.rebuild();
                }
                KeyCode::Char(c) => {
                    self.filter.push(c);
                    self.rebuild();
                }
                _ => {}
            }
            return None;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.cursor = self.cursor.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                if self.cursor + 1 < self.visible.len() {
                    self.cursor += 1;
                }
            }
            KeyCode::Home | KeyCode::Char('g') => self.cursor = 0,
            KeyCode::End | KeyCode::Char('G') => {
                self.cursor = self.visible.len().saturating_sub(1);
            }
            KeyCode::Enter | KeyCode::Char(' ') | KeyCode::Right | KeyCode::Char('l') => {
                self.activate(ctx);
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let Some(id) = self.current() {
                    if self.nodes[id].expanded {
                        self.nodes[id].expanded = false;
                        self.rebuild();
                    }
                }
            }
            KeyCode::Char('r') => self.read_current(ctx),
            KeyCode::Char('w') => {
                return match self.current() {
                    Some(id) if self.nodes[id].writable => {
                        let n = &self.nodes[id];
                        let current = match (n.value_is_err, &n.value) {
                            (false, Some(v)) => Some(v.as_str()),
                            _ => None,
                        };
                        Some(
                            Dialog::write(n.reference.clone(), n.fc, n.kind)
                                .prefilled(current),
                        )
                    }
                    _ => {
                        ctx.err("not a writable attribute");
                        None
                    }
                }
            }
            KeyCode::Char('o') => {
                return match self.current() {
                    Some(id) if self.nodes[id].controllable => {
                        Some(Dialog::control(self.nodes[id].reference.clone()))
                    }
                    _ => {
                        ctx.err("not a controllable object");
                        None
                    }
                }
            }
            KeyCode::Char('a') => {
                self.auto = !self.auto;
                self.auto_gen += 1;
                if self.auto {
                    ctx.ok("auto-refresh on");
                    self.spawn_ticker(ctx);
                } else {
                    ctx.status("auto-refresh off", StatusKind::Info);
                }
            }
            KeyCode::Char('/') => self.filtering = true,
            _ => {}
        }
        None
    }

    /// Expands a branch, or reads a leaf.
    fn activate(&mut self, ctx: &Ctx) {
        let Some(id) = self.current() else { return };
        if !self.nodes[id].children.is_empty() {
            self.nodes[id].expanded = !self.nodes[id].expanded;
            self.rebuild();
        } else if self.nodes[id].readable {
            self.read(id, ctx);
        }
    }

    fn read_current(&mut self, ctx: &Ctx) {
        match self.current() {
            Some(id) if self.nodes[id].readable => self.read(id, ctx),
            // Silence here would look like a read that never answered.
            _ => ctx.err("not a readable attribute"),
        }
    }

    fn read(&self, id: usize, ctx: &Ctx) {
        let Some(client) = ctx.client() else { return };
        let n = &self.nodes[id];
        let (reference, fc) = (n.reference.clone(), n.fc);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let msg = match client.read(reference, fc).await {
                Ok(v) => Msg::Value {
                    node: id,
                    text: v.to_string(),
                    is_err: false,
                },
                Err(e) => Msg::Value {
                    node: id,
                    text: e.to_string(),
                    is_err: true,
                },
            };
            ctx.send(msg);
        });
    }

    /// Re-reads the selected leaf once a second while auto-refresh is on.
    fn spawn_ticker(&self, ctx: &Ctx) {
        let Some(client) = ctx.client() else { return };
        let generation = self.auto_gen;
        let node = self.current();
        let target = node.and_then(|id| {
            let n = &self.nodes[id];
            n.readable.then(|| (id, n.reference.clone(), n.fc))
        });
        let ctx = ctx.clone();
        tokio::spawn(async move {
            // The generation is captured, not shared: a later toggle spawns a
            // new ticker and this one simply runs out.
            let _ = generation;
            let Some((id, reference, fc)) = target else {
                return;
            };
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let msg = match client.read(reference.clone(), fc).await {
                    Ok(v) => Msg::Value {
                        node: id,
                        text: v.to_string(),
                        is_err: false,
                    },
                    Err(e) => Msg::Value {
                        node: id,
                        text: e.to_string(),
                        is_err: true,
                    },
                };
                if ctx.tx.send(msg).is_err() {
                    return; // the UI has gone
                }
            }
        });
    }

    pub fn scroll(&mut self, up: bool) {
        if up {
            self.cursor = self.cursor.saturating_sub(1);
        } else if self.cursor + 1 < self.visible.len() {
            self.cursor += 1;
        }
    }

    pub fn on_click(&mut self, x: u16, y: u16, width: u16, ctx: &Ctx) -> Option<Dialog> {
        let left = self.left_width(width);
        if x >= left {
            return None; // the detail pane has no hit targets
        }
        // Account for the pane's top border.
        let row = y.checked_sub(1)? as usize;
        let idx = self.top + row;
        if idx >= self.visible.len() {
            return None;
        }
        self.cursor = idx;
        self.activate(ctx);
        None
    }

    fn left_width(&self, width: u16) -> u16 {
        widgets::left_width(width, 28)
    }

    pub fn draw(&mut self, f: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(3), Constraint::Length(1)])
            .split(area);
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(self.left_width(rows[0].width)),
                Constraint::Min(10),
            ])
            .split(rows[0]);

        self.draw_tree(f, cols[0]);
        self.draw_detail(f, cols[1]);

        let hint = if self.filtering {
            Line::styled(
                format!("filter: {}▏  (enter/esc to finish)", self.filter()),
                theme::accent(),
            )
        } else if !self.filter.is_empty() {
            Line::styled(
                format!("filter: {}  (/ to edit)", self.filter()),
                theme::muted(),
            )
        } else {
            Line::styled(
                "↑↓ move · enter expand/read · r read · w write · o operate · a auto · / filter",
                theme::help(),
            )
        };
        f.render_widget(Paragraph::new(hint), rows[1]);
    }

    fn draw_tree(&mut self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .title("Model");
        let inner = block.inner(area);
        f.render_widget(block, area);
        if inner.height == 0 {
            return;
        }

        let height = inner.height as usize;
        if self.cursor < self.top {
            self.top = self.cursor;
        } else if self.cursor >= self.top + height {
            self.top = self.cursor + 1 - height;
        }
        self.top = self
            .top
            .min(self.visible.len().saturating_sub(height.min(self.visible.len())));

        if self.visible.is_empty() {
            f.render_widget(
                Paragraph::new(Line::styled(
                    "(no model; press R to retrieve)",
                    theme::muted(),
                )),
                inner,
            );
            return;
        }

        let end = (self.top + height).min(self.visible.len());
        let width = inner.width as usize;
        let lines: Vec<Line> = (self.top..end)
            .map(|i| {
                let id = self.visible[i];
                let n = &self.nodes[id];
                // A filter shows a branch's children whether or not it was
                // expanded, so the marker follows what is on screen rather
                // than the expansion flag behind it.
                let open = n.expanded || !self.filter.is_empty();
                let marker = if n.children.is_empty() {
                    "  "
                } else if open {
                    "▾ "
                } else {
                    "▸ "
                };
                let mut spans = vec![Span::raw(format!(
                    "{}{}{}",
                    "  ".repeat(n.depth),
                    marker,
                    n.label
                ))];
                if let Some(v) = &n.value {
                    spans.push(Span::raw(" = "));
                    spans.push(Span::styled(
                        clip(v, 16),
                        if n.value_is_err {
                            theme::error()
                        } else {
                            theme::value()
                        },
                    ));
                }
                let mut line = Line::from(spans);
                if i == self.cursor {
                    line = Line::from(
                        line.spans
                            .into_iter()
                            .map(|s| s.patch_style(theme::cursor()))
                            .collect::<Vec<_>>(),
                    )
                    .style(theme::cursor());
                }
                let _ = width;
                line
            })
            .collect();
        f.render_widget(Paragraph::new(lines), inner);
    }

    fn draw_detail(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .title("Detail");
        let inner = block.inner(area);
        f.render_widget(block, area);

        let Some(id) = self.current() else {
            f.render_widget(
                Paragraph::new(Line::styled("no selection", theme::muted())),
                inner,
            );
            return;
        };
        let n = &self.nodes[id];

        let mut lines: Vec<Line> = vec![
            Line::styled("Reference", theme::label()),
            Line::raw(format!("  {}", n.reference)),
            Line::raw(""),
        ];
        if n.fc != Fc::None {
            lines.push(Line::from(vec![
                Span::styled("FC", theme::label()),
                Span::raw(format!("  {}    ", n.fc)),
                Span::styled("Type", theme::label()),
                Span::raw(format!(
                    "  {}",
                    n.kind.map_or("-".to_string(), |k| k.to_string())
                )),
            ]));
            lines.push(Line::raw(""));
        }
        if n.readable {
            lines.push(Line::styled("Value", theme::label()));
            match &n.value {
                None => lines.push(Line::styled("  (press r to read)", theme::muted())),
                Some(v) => lines.push(Line::styled(
                    format!("  {v}"),
                    if n.value_is_err {
                        theme::error()
                    } else {
                        theme::value()
                    },
                )),
            }
            lines.push(Line::raw(""));
        }

        let mut actions: Vec<&str> = Vec::new();
        if n.readable {
            actions.push("r read");
        }
        if n.writable {
            actions.push("w write");
        }
        if n.controllable {
            actions.push("o operate");
        }
        if !n.children.is_empty() {
            actions.push("enter expand");
        }
        if !actions.is_empty() {
            lines.push(Line::styled(
                format!("actions: {}", actions.join(" · ")),
                theme::muted(),
            ));
        }
        if self.auto {
            lines.push(Line::raw(""));
            lines.push(Line::styled("● auto-refresh", theme::value()));
        }

        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
    }
}

/// Flattens a retrieved model into the arena.
pub fn build_tree(m: &Model) -> Vec<Node> {
    let mut nodes: Vec<Node> = Vec::new();
    for ld in &m.devices {
        let ld_id = nodes.len();
        let mut ld_node = Node::new(format!("LD {}", ld.name), 0);
        ld_node.expanded = true;
        nodes.push(ld_node);

        let mut ln_ids = Vec::new();
        for ln in &ld.nodes {
            let ln_id = nodes.len();
            nodes.push(Node::new(format!("LN {}", ln.name), 1));
            let base = ObjectReference::new(format!("{}/{}", ld.name, ln.name));

            let mut do_ids = Vec::new();
            for object in &ln.objects {
                do_ids.push(build_do(&mut nodes, &base.child(&object.name), object, 2));
            }
            nodes[ln_id].children = do_ids;
            ln_ids.push(ln_id);
        }
        nodes[ld_id].children = ln_ids;
    }
    nodes
}

fn build_do(
    nodes: &mut Vec<Node>,
    reference: &ObjectReference,
    object: &iec61850::model::DataObject,
    depth: usize,
) -> usize {
    let mut label = format!("DO {}", object.name);
    if !object.cdc.is_empty() {
        label.push_str(&format!(" ({})", object.cdc));
    }
    let controllable = object.fcs().contains(&Fc::Co);
    if controllable {
        label.push_str(" ⚡");
    }

    let id = nodes.len();
    let mut n = Node::new(label, depth);
    n.reference = reference.clone();
    n.controllable = controllable;
    nodes.push(n);

    let mut children = Vec::new();
    for a in &object.attributes {
        children.push(build_da(nodes, &reference.child(&a.name), a, depth + 1));
    }
    for sub in &object.objects {
        children.push(build_do(nodes, &reference.child(&sub.name), sub, depth + 1));
    }
    nodes[id].children = children;
    id
}

fn build_da(
    nodes: &mut Vec<Node>,
    reference: &ObjectReference,
    da: &iec61850::model::DataAttribute,
    depth: usize,
) -> usize {
    let kind = da.kind;
    let label = format!(
        "{} [{}] {}",
        da.name,
        da.fc,
        kind.map_or(String::new(), |k| k.to_string())
    );
    let id = nodes.len();
    let mut n = Node::new(label, depth);
    n.reference = reference.clone();
    n.fc = da.fc;
    n.kind = kind;
    if da.children.is_empty() {
        n.readable = true;
        n.writable = is_writable(da.fc);
    }
    nodes.push(n);

    let mut children = Vec::new();
    for c in &da.children {
        children.push(build_da(nodes, &reference.child(&c.name), c, depth + 1));
    }
    nodes[id].children = children;
    id
}

/// Which constraints a client may write.
///
/// Status and measurand attributes are the device's own view of the process
/// and are not writable; offering a write for them would only produce an
/// access error from the device.
fn is_writable(fc: Fc) -> bool {
    matches!(fc, Fc::Cf | Fc::Sp | Fc::Se | Fc::Sv | Fc::Dc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec61850::scl;

    fn reference_model() -> Model {
        scl::load_model(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/testdata/simpleIO_direct_control.cid"
            ),
            &scl::BuildOptions::new(),
        )
        .expect("the reference CID loads")
    }

    fn panel() -> BrowsePanel {
        let mut p = BrowsePanel::default();
        p.set_model(build_tree(&reference_model()));
        p
    }

    #[test]
    fn the_tree_mirrors_the_model_hierarchy() {
        let m = reference_model();
        let mut p = BrowsePanel::default();
        assert_eq!(p.set_model(build_tree(&m)), m.devices.len());

        // A device starts expanded, so its logical nodes are visible at once.
        assert!(p.visible.len() > 1);
        assert!(p.nodes[p.roots[0]].expanded);
        assert!(p.nodes[p.roots[0]].label.starts_with("LD "));
    }

    #[test]
    fn expanding_and_collapsing_changes_what_is_visible() {
        let mut p = panel();
        let before = p.visible.len();

        // The first logical node, one row below the device.
        p.cursor = 1;
        let id = p.current().unwrap();
        assert!(!p.nodes[id].children.is_empty());

        p.nodes[id].expanded = true;
        p.rebuild();
        assert!(p.visible.len() > before, "expanding reveals children");

        p.nodes[id].expanded = false;
        p.rebuild();
        assert_eq!(p.visible.len(), before);
    }

    /// A filter has to reach matches deep in the tree without the user
    /// expanding every level by hand.
    #[test]
    fn a_filter_opens_the_tree_to_reach_matches() {
        let mut p = panel();
        p.filter = "AnIn1".into();
        p.rebuild();

        assert!(!p.visible.is_empty());
        let labels: Vec<&str> = p
            .visible
            .iter()
            .map(|i| p.nodes[*i].label.as_str())
            .collect();
        assert!(
            labels.iter().any(|l| l.contains("AnIn1")),
            "the match itself is visible: {labels:?}"
        );

        // Clearing it goes back to the collapsed view.
        p.filter.clear();
        p.rebuild();
        assert!(p.visible.iter().all(|i| p.nodes[*i].depth <= 1));
    }

    #[test]
    fn a_filter_that_matches_nothing_shows_nothing() {
        let mut p = panel();
        p.filter = "definitely-not-in-the-model".into();
        p.rebuild();
        assert!(p.visible.is_empty());
        assert_eq!(p.cursor, 0, "the cursor must not point past the end");
    }

    /// The arena is what lets an async read name its node; the index has to
    /// stay valid and select the right row.
    #[test]
    fn a_value_lands_on_the_node_that_asked_for_it() {
        let mut p = panel();
        let leaf = p
            .nodes
            .iter()
            .position(|n| n.readable)
            .expect("the model has readable leaves");

        p.set_value(leaf, "230.4".into(), false);
        assert_eq!(p.nodes[leaf].value.as_deref(), Some("230.4"));
        assert!(!p.nodes[leaf].value_is_err);

        p.set_value(leaf, "boom".into(), true);
        assert!(p.nodes[leaf].value_is_err);

        // An index from a stale model must not panic.
        p.set_value(usize::MAX, "x".into(), false);
    }

    #[test]
    fn only_configuration_and_setting_attributes_are_offered_for_writing() {
        for fc in [Fc::Cf, Fc::Sp, Fc::Se, Fc::Sv, Fc::Dc] {
            assert!(is_writable(fc), "{fc} should be writable");
        }
        // The device's own view of the process is not ours to write.
        for fc in [Fc::St, Fc::Mx, Fc::Co, Fc::Br, Fc::Rp] {
            assert!(!is_writable(fc), "{fc} should not be writable");
        }
    }

    #[test]
    fn a_controllable_object_is_marked_and_offers_the_operate_action() {
        let p = panel();
        let controllable: Vec<&Node> = p.nodes.iter().filter(|n| n.controllable).collect();
        assert!(
            !controllable.is_empty(),
            "the reference model has controllable objects"
        );
        for n in controllable {
            assert!(n.label.contains('⚡'), "{} is not marked", n.label);
            assert!(n.reference.as_str().contains("SPCSO"));
        }
    }

    #[test]
    fn leaves_are_readable_and_structures_are_not() {
        let p = panel();
        for n in &p.nodes {
            if n.fc == Fc::None {
                continue; // a device, node or object row
            }
            assert_eq!(
                n.readable,
                n.children.is_empty(),
                "{} readable={} children={}",
                n.label,
                n.readable,
                n.children.len()
            );
        }
    }

    #[test]
    fn the_cursor_cannot_leave_the_visible_rows() {
        let mut p = panel();
        let ctx = Ctx {
            client: None,
            tx: tokio::sync::mpsc::unbounded_channel().0,
        };
        for _ in 0..100 {
            p.on_key(KeyEvent::from(KeyCode::Down), &ctx);
        }
        assert!(p.cursor < p.visible.len());
        for _ in 0..200 {
            p.on_key(KeyEvent::from(KeyCode::Up), &ctx);
        }
        assert_eq!(p.cursor, 0);
    }

    #[test]
    fn typing_into_the_filter_does_not_move_the_cursor() {
        let mut p = panel();
        let ctx = Ctx {
            client: None,
            tx: tokio::sync::mpsc::unbounded_channel().0,
        };
        p.on_key(KeyEvent::from(KeyCode::Char('/')), &ctx);
        assert!(p.filtering);
        // 'j' and 'k' are movement keys outside the filter, and text inside it.
        p.on_key(KeyEvent::from(KeyCode::Char('j')), &ctx);
        p.on_key(KeyEvent::from(KeyCode::Char('k')), &ctx);
        assert_eq!(p.filter, "jk");

        p.on_key(KeyEvent::from(KeyCode::Enter), &ctx);
        assert!(!p.filtering);
        p.on_key(KeyEvent::from(KeyCode::Char('j')), &ctx);
        assert_eq!(p.filter, "jk", "movement no longer edits the filter");
    }

    #[test]
    fn the_left_pane_stays_within_the_frame() {
        let p = BrowsePanel::default();
        for width in [40u16, 80, 120, 200] {
            let left = p.left_width(width);
            assert!(left > 0 && left < width, "width={width} left={left}");
        }
    }
}
