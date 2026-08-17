//! Small reusable pieces: a scrolling selection list and a text field.
//!
//! ratatui draws immediately from state, so both types hold only the state
//! that has to survive between frames: where the cursor is and how far the
//! view has scrolled.

use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::theme;

/// The width of the left pane in a two-pane panel.
///
/// Two fifths of the frame, widened to `min` columns where there is room, but
/// the detail pane always keeps twenty: on a narrow terminal a reference list
/// with nothing beside it is of no use, so the detail pane wins.
pub fn left_width(width: u16, min: u16) -> u16 {
    let max = width.saturating_sub(20).max(1);
    // u32 because a wide frame doubled would overflow the u16.
    let preferred = (u32::from(width) * 2 / 5) as u16;
    preferred.clamp(min.min(max), max)
}

/// A vertical selection list with scrolling.
#[derive(Debug, Default, Clone)]
pub struct ListBox {
    pub cursor: usize,
    pub top: usize,
}

impl ListBox {
    /// Moves the cursor by `delta`, clamped to `count`.
    pub fn move_by(&mut self, delta: isize, count: usize) {
        if count == 0 {
            self.cursor = 0;
            return;
        }
        let next = self.cursor as isize + delta;
        self.cursor = next.clamp(0, count as isize - 1) as usize;
    }

    pub fn first(&mut self) {
        self.cursor = 0;
    }

    pub fn last(&mut self, count: usize) {
        self.cursor = count.saturating_sub(1);
    }

    /// Maps a row within the list's viewport to an index, selecting it.
    ///
    /// Returns whether a row was actually hit; a click below the last item
    /// should leave the selection alone rather than jumping to the end.
    pub fn click_row(&mut self, row: usize, count: usize) -> bool {
        let idx = self.top + row;
        if idx >= count {
            return false;
        }
        self.cursor = idx;
        true
    }

    /// Scrolls so the cursor is visible in a viewport `height` rows tall.
    pub fn scroll_into_view(&mut self, count: usize, height: usize) {
        if count == 0 || height == 0 {
            self.top = 0;
            return;
        }
        self.cursor = self.cursor.min(count - 1);
        if self.cursor < self.top {
            self.top = self.cursor;
        } else if self.cursor >= self.top + height {
            self.top = self.cursor + 1 - height;
        }
        // A shrinking list must not leave the view past its end.
        self.top = self.top.min(count.saturating_sub(height.min(count)));
    }

    /// Renders `count` rows inside `area`, drawing each with `row`.
    pub fn render<F>(&mut self, f: &mut Frame, area: Rect, title: &str, count: usize, row: F)
    where
        F: Fn(usize) -> Line<'static>,
    {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(theme::border())
            .title(title.to_string());
        let inner = block.inner(area);
        f.render_widget(block, area);
        if inner.height == 0 {
            return;
        }

        self.scroll_into_view(count, inner.height as usize);
        if count == 0 {
            f.render_widget(
                Paragraph::new(Line::styled("(nothing here)", theme::muted())),
                inner,
            );
            return;
        }

        let end = (self.top + inner.height as usize).min(count);
        let lines: Vec<Line> = (self.top..end)
            .map(|i| {
                let line = row(i);
                if i == self.cursor {
                    // Restyle the whole row, so the highlight is a solid bar
                    // rather than showing through the gaps between spans.
                    Line::from(
                        line.spans
                            .into_iter()
                            .map(|s| s.patch_style(theme::cursor()))
                            .collect::<Vec<_>>(),
                    )
                    .style(theme::cursor())
                } else {
                    line
                }
            })
            .collect();
        f.render_widget(Paragraph::new(lines), inner);
    }
}

/// A single-line text field.
#[derive(Debug, Default, Clone)]
pub struct TextField {
    pub value: String,
    pub cursor: usize,
    pub masked: bool,
    pub placeholder: String,
}

impl TextField {
    pub fn new(value: impl Into<String>) -> TextField {
        let value = value.into();
        TextField {
            cursor: value.chars().count(),
            value,
            masked: false,
            placeholder: String::new(),
        }
    }

    pub fn with_placeholder(mut self, s: impl Into<String>) -> TextField {
        self.placeholder = s.into();
        self
    }

    pub fn masked(mut self) -> TextField {
        self.masked = true;
        self
    }

    /// Replaces the contents, leaving the cursor at the end.
    pub fn set(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.cursor = self.value.chars().count();
    }

    /// Handles a key, returning whether it was consumed.
    ///
    /// Keys the field does not use are handed back so the surrounding form can
    /// act on them; otherwise a dialog could never be dismissed while a field
    /// has focus.
    pub fn on_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(c) => {
                let byte = self.byte_at(self.cursor);
                self.value.insert(byte, c);
                self.cursor += 1;
                true
            }
            KeyCode::Backspace if self.cursor > 0 => {
                let byte = self.byte_at(self.cursor - 1);
                self.value.remove(byte);
                self.cursor -= 1;
                true
            }
            KeyCode::Delete if self.cursor < self.value.chars().count() => {
                let byte = self.byte_at(self.cursor);
                self.value.remove(byte);
                true
            }
            KeyCode::Left if self.cursor > 0 => {
                self.cursor -= 1;
                true
            }
            KeyCode::Right if self.cursor < self.value.chars().count() => {
                self.cursor += 1;
                true
            }
            KeyCode::Home => {
                self.cursor = 0;
                true
            }
            KeyCode::End => {
                self.cursor = self.value.chars().count();
                true
            }
            _ => false,
        }
    }

    fn byte_at(&self, char_idx: usize) -> usize {
        self.value
            .char_indices()
            .nth(char_idx)
            .map_or(self.value.len(), |(i, _)| i)
    }

    /// Renders the field as a line, showing a cursor when focused.
    pub fn line(&self, focused: bool) -> Line<'static> {
        if self.value.is_empty() && !focused {
            return Line::styled(
                format!("  {}", self.placeholder),
                theme::help(),
            );
        }
        let shown: String = if self.masked {
            "•".repeat(self.value.chars().count())
        } else {
            self.value.clone()
        };
        let text = if focused {
            // A block cursor at the insertion point, so the caret is visible
            // without the terminal's own cursor having to be moved.
            let mut with_caret: String = shown.chars().take(self.cursor).collect();
            with_caret.push('▏');
            with_caret.extend(shown.chars().skip(self.cursor));
            with_caret
        } else {
            shown
        };
        Line::styled(
            format!("  {text}"),
            if focused {
                Style::default().fg(theme::ACCENT)
            } else {
                Style::default()
            },
        )
    }
}

/// Truncates a string to `width` display columns, with an ellipsis.
pub fn clip(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    if width <= 1 {
        return String::new();
    }
    let mut out: String = s.chars().take(width - 1).collect();
    out.push('…');
    out
}

/// Centres a rectangle of the given size inside `area`.
pub fn centred(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::{KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// The split has to hold on a narrow terminal too: a left pane as wide as
    /// the frame would leave the detail pane nothing, and the arithmetic must
    /// not fold over on a very wide one.
    #[test]
    fn the_left_pane_leaves_room_for_the_detail_pane_at_any_width() {
        for width in [20u16, 30, 40, 60, 80, 120, 200, 400, u16::MAX] {
            let left = left_width(width, 32);
            assert!(left > 0, "width={width} left={left}");
            assert!(left < width, "width={width} left={left}");
        }
    }

    #[test]
    fn a_roomy_frame_gets_two_fifths_but_never_less_than_the_minimum() {
        assert_eq!(left_width(200, 32), 80);
        // Two fifths of 60 is 24, which is below the minimum asked for.
        assert_eq!(left_width(60, 32), 32);
    }

    #[test]
    fn the_cursor_stays_inside_the_list() {
        let mut l = ListBox::default();
        l.move_by(-1, 5);
        assert_eq!(l.cursor, 0, "moving up from the top stays at the top");
        l.move_by(10, 5);
        assert_eq!(l.cursor, 4, "moving past the end stops at the last item");
        l.last(5);
        assert_eq!(l.cursor, 4);
        l.first();
        assert_eq!(l.cursor, 0);
    }

    #[test]
    fn an_empty_list_has_no_cursor_to_move() {
        let mut l = ListBox::default();
        l.move_by(1, 0);
        assert_eq!(l.cursor, 0);
        l.last(0);
        assert_eq!(l.cursor, 0);
    }

    #[test]
    fn scrolling_follows_the_cursor_in_both_directions() {
        let mut l = ListBox {
            cursor: 20,
            ..Default::default()
        };
        l.scroll_into_view(50, 10);
        assert!(l.top <= 20 && 20 < l.top + 10, "top={}", l.top);

        l.cursor = 0;
        l.scroll_into_view(50, 10);
        assert_eq!(l.top, 0);
    }

    /// A list that shrinks under the cursor must not leave the view pointing
    /// past the end, or the panel renders blank.
    #[test]
    fn a_shrinking_list_pulls_the_view_back() {
        let mut l = ListBox {
            cursor: 40,
            ..Default::default()
        };
        l.scroll_into_view(50, 10);
        assert!(l.top > 0);

        l.scroll_into_view(3, 10);
        assert_eq!(l.top, 0);
        assert_eq!(l.cursor, 2);
    }

    /// A click below the last row should leave the selection alone rather than
    /// jumping to the end.
    #[test]
    fn clicking_past_the_last_row_selects_nothing() {
        let mut l = ListBox {
            cursor: 1,
            ..Default::default()
        };
        assert!(!l.click_row(9, 3));
        assert_eq!(l.cursor, 1, "the selection is unchanged");
        assert!(l.click_row(2, 3));
        assert_eq!(l.cursor, 2);
    }

    #[test]
    fn clicking_accounts_for_the_scroll_offset() {
        let mut l = ListBox {
            top: 10,
            ..Default::default()
        };
        assert!(l.click_row(3, 50));
        assert_eq!(l.cursor, 13);
    }

    #[test]
    fn a_text_field_edits_at_the_cursor() {
        let mut f = TextField::new("");
        for c in "hello".chars() {
            f.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(f.value, "hello");
        assert_eq!(f.cursor, 5);

        f.on_key(key(KeyCode::Home));
        f.on_key(key(KeyCode::Char('>')));
        assert_eq!(f.value, ">hello");
        assert_eq!(f.cursor, 1);

        f.on_key(key(KeyCode::End));
        f.on_key(key(KeyCode::Backspace));
        assert_eq!(f.value, ">hell");
    }

    #[test]
    fn a_text_field_edits_multi_byte_text_by_character() {
        let mut f = TextField::new("héllo");
        assert_eq!(f.cursor, 5);
        f.on_key(key(KeyCode::Home));
        f.on_key(key(KeyCode::Right));
        f.on_key(key(KeyCode::Backspace));
        assert_eq!(f.value, "héllo".chars().skip(1).collect::<String>());
    }

    /// Keys the field does not use have to reach the surrounding form, or a
    /// dialog with a focused field could never be dismissed.
    #[test]
    fn unhandled_keys_are_passed_back() {
        let mut f = TextField::new("x");
        assert!(f.on_key(key(KeyCode::Char('y'))));
        assert!(!f.on_key(key(KeyCode::Enter)));
        assert!(!f.on_key(key(KeyCode::Esc)));
        assert!(!f.on_key(key(KeyCode::Tab)));
    }

    #[test]
    fn edits_at_the_ends_are_refused_rather_than_wrapping() {
        let mut f = TextField::new("");
        assert!(!f.on_key(key(KeyCode::Backspace)));
        assert!(!f.on_key(key(KeyCode::Left)));
        assert!(!f.on_key(key(KeyCode::Delete)));
        assert!(!f.on_key(key(KeyCode::Right)));
        assert_eq!(f.value, "");
    }

    #[test]
    fn a_masked_field_hides_its_value_but_keeps_it() {
        let f = TextField::new("secret").masked();
        let rendered = f.line(false);
        let text: String = rendered.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(!text.contains("secret"));
        assert!(text.contains('•'));
        assert_eq!(f.value, "secret", "the value is still readable in code");
    }

    #[test]
    fn clipping_marks_what_it_cut() {
        assert_eq!(clip("short", 10), "short");
        assert_eq!(clip("truncate me", 5), "trun…");
        assert_eq!(clip("abc", 3), "abc");
        assert_eq!(clip("abc", 1), "");
    }

    #[test]
    fn centring_fits_inside_the_area_it_is_given() {
        let area = Rect::new(0, 0, 100, 40);
        let r = centred(area, 60, 20);
        assert_eq!((r.width, r.height), (60, 20));
        assert_eq!((r.x, r.y), (20, 10));

        // A dialog larger than the screen is clamped, not drawn off-screen.
        let r = centred(Rect::new(0, 0, 20, 10), 60, 20);
        assert_eq!((r.width, r.height), (20, 10));
        assert_eq!((r.x, r.y), (0, 0));
    }
}
