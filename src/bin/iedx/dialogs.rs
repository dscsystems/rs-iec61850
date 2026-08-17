//! Modal overlays: writing a value, operating a control, help, and the
//! connection form.

use iec61850::client::{ControlOptions, Error as ClientError};
use iec61850::mms::{Type, Value};
use iec61850::model::{Fc, ObjectReference, OrCat};
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::Ctx;
use crate::theme;
use crate::widgets::{centred, TextField};

/// A modal overlay.
pub enum Dialog {
    Write {
        reference: ObjectReference,
        fc: Fc,
        kind: Option<Type>,
        field: TextField,
    },
    Control(Box<ControlDialog>),
    Help,
}

impl std::fmt::Debug for Dialog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Dialog::Write { reference, .. } => write!(f, "Write({reference})"),
            Dialog::Control(c) => write!(f, "Control({})", c.reference),
            Dialog::Help => f.write_str("Help"),
        }
    }
}

impl Dialog {
    pub fn write(reference: ObjectReference, fc: Fc, kind: Option<Type>) -> Dialog {
        let placeholder = match kind {
            Some(Type::Boolean) => "true / false",
            Some(Type::Float32) | Some(Type::Float64) => "number",
            Some(Type::Integer) | Some(Type::Unsigned) => "integer",
            _ => "value",
        };
        Dialog::Write {
            reference,
            fc,
            kind,
            field: TextField::new("").with_placeholder(placeholder),
        }
    }

    /// Starts the field from the value last read, so an edit begins at the
    /// present setting rather than an empty line.
    ///
    /// Only the types whose rendering parses back unchanged are prefilled; a
    /// string is shown quoted and a timestamp formatted, and either would be
    /// written back as something else.
    pub fn prefilled(mut self, current: Option<&str>) -> Dialog {
        if let Dialog::Write { kind, field, .. } = &mut self {
            let round_trips = matches!(
                kind,
                Some(Type::Boolean)
                    | Some(Type::Integer)
                    | Some(Type::Unsigned)
                    | Some(Type::Float32)
                    | Some(Type::Float64)
            );
            if let (true, Some(v)) = (round_trips, current) {
                field.set(v.trim());
            }
        }
        self
    }

    pub fn control(reference: ObjectReference) -> Dialog {
        Dialog::Control(Box::new(ControlDialog::new(reference)))
    }

    pub fn help() -> Dialog {
        Dialog::Help
    }

    /// Reports whether a stray click should close it.
    ///
    /// The help closes on anything; a confirm prompt must not, or a misplaced
    /// click could operate switchgear.
    pub fn dismissable_by_click(&self) -> bool {
        matches!(self, Dialog::Help)
    }

    /// Handles a key. Returns whether the dialog is finished.
    pub fn on_key(&mut self, key: KeyEvent, ctx: &Ctx) -> bool {
        match self {
            Dialog::Help => true, // any key closes it
            Dialog::Write {
                reference,
                fc,
                kind,
                field,
            } => match key.code {
                KeyCode::Esc => true,
                KeyCode::Enter => {
                    match parse_value(*kind, &field.value) {
                        Ok(v) => {
                            spawn_write(ctx, reference.clone(), *fc, v);
                            true
                        }
                        Err(e) => {
                            ctx.err(format!("bad value: {e}"));
                            false
                        }
                    }
                }
                _ => {
                    field.on_key(key);
                    false
                }
            },
            Dialog::Control(d) => d.on_key(key, ctx),
        }
    }

    pub fn draw(&self, f: &mut Frame, area: Rect) {
        match self {
            Dialog::Help => draw_box(
                f,
                area,
                60,
                18,
                "iedx — keys",
                theme::ACCENT,
                vec![
                    Line::raw("tab / shift+tab / 1-7   switch tab"),
                    Line::raw("R                       refresh the current tab"),
                    Line::raw("↑ ↓ j k / wheel         move / scroll"),
                    Line::raw("enter / space / click   expand or read"),
                    Line::raw(""),
                    Line::raw("r  read       w  write       o  operate"),
                    Line::raw("a  auto-refresh            /  filter (Browse)"),
                    Line::raw("e  enable report + GI   g  GI   x  disable   c  clear"),
                    Line::raw("d  download (Files)        +/- window (Logs)"),
                    Line::raw("1-9 activate setting group (SetGroups)"),
                    Line::raw(""),
                    Line::styled("mouse: click tabs and rows, wheel to scroll", theme::help()),
                    Line::styled("press any key to close", theme::help()),
                ],
            ),
            Dialog::Write {
                reference,
                fc,
                kind,
                field,
            } => {
                let lines = vec![
                    Line::styled(
                        format!(
                            "{reference}  [{fc}]  {}",
                            kind.map_or("-".to_string(), |k| k.to_string())
                        ),
                        theme::muted(),
                    ),
                    Line::raw(""),
                    field.line(true),
                    Line::raw(""),
                    Line::styled("enter write · esc cancel", theme::help()),
                ];
                draw_box(f, area, 64, 9, "Write value", theme::ACCENT, lines);
            }
            Dialog::Control(d) => d.draw(f, area),
        }
    }
}

/// The operate dialog, with a confirmation step.
pub struct ControlDialog {
    pub reference: ObjectReference,
    on: bool,
    test: bool,
    interlock: bool,
    synchro: bool,
    originator: TextField,
    focus: usize,
    confirm: bool,
}

/// The rows the dialog can focus, in order.
const FIELD_COUNT: usize = 6;
const F_VALUE: usize = 0;
const F_TEST: usize = 1;
const F_INTERLOCK: usize = 2;
const F_SYNCHRO: usize = 3;
const F_ORIGINATOR: usize = 4;
const F_OPERATE: usize = 5;

impl ControlDialog {
    fn new(reference: ObjectReference) -> ControlDialog {
        ControlDialog {
            reference,
            on: true,
            test: false,
            interlock: false,
            synchro: false,
            originator: TextField::new("iedx"),
            focus: F_VALUE,
            confirm: false,
        }
    }

    fn on_key(&mut self, key: KeyEvent, ctx: &Ctx) -> bool {
        if self.confirm {
            // Only an explicit yes proceeds; anything else backs out, because
            // the thing on the other end may be real switchgear.
            return match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    spawn_operate(ctx, self);
                    true
                }
                _ => {
                    self.confirm = false;
                    false
                }
            };
        }

        match key.code {
            KeyCode::Esc => return true,
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % FIELD_COUNT,
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + FIELD_COUNT - 1) % FIELD_COUNT;
            }
            KeyCode::Char(' ') if self.focus != F_ORIGINATOR => match self.focus {
                F_VALUE => self.on = !self.on,
                F_TEST => self.test = !self.test,
                F_INTERLOCK => self.interlock = !self.interlock,
                F_SYNCHRO => self.synchro = !self.synchro,
                _ => {}
            },
            KeyCode::Enter => {
                if self.focus == F_OPERATE {
                    self.confirm = true;
                }
            }
            _ => {
                if self.focus == F_ORIGINATOR {
                    self.originator.on_key(key);
                }
            }
        }
        false
    }

    fn draw(&self, f: &mut Frame, area: Rect) {
        if self.confirm {
            let lines = vec![
                Line::from(vec![
                    Span::raw("Operate "),
                    Span::styled(self.reference.to_string(), theme::accent()),
                    Span::raw(" = "),
                    Span::styled(
                        if self.on { "ON" } else { "OFF" },
                        theme::accent(),
                    ),
                    Span::raw("?"),
                ]),
                Line::styled("Real switchgear may be attached.", theme::warn()),
                Line::raw(""),
                Line::styled(
                    "y / enter confirm · any other key cancels",
                    theme::help(),
                ),
            ];
            draw_box(f, area, 64, 8, "⚠ Confirm operate", theme::WARN, lines);
            return;
        }

        let check = |b: bool| if b { "[x]" } else { "[ ]" };
        let row = |i: usize, text: String| -> Line<'static> {
            if self.focus == i {
                Line::styled(format!("▸ {text}"), theme::label())
            } else {
                Line::raw(format!("  {text}"))
            }
        };

        let mut lines = vec![
            Line::styled(self.reference.to_string(), theme::muted()),
            Line::raw(""),
            row(
                F_VALUE,
                format!(
                    "Value       {}  (space toggles)",
                    if self.on { "ON" } else { "OFF" }
                ),
            ),
            row(F_TEST, format!("Test        {}", check(self.test))),
            row(
                F_INTERLOCK,
                format!("Interlock   {}", check(self.interlock)),
            ),
            row(F_SYNCHRO, format!("Synchro     {}", check(self.synchro))),
            row(
                F_ORIGINATOR,
                format!("Originator  {}", self.originator.value),
            ),
            Line::raw(""),
        ];
        lines.push(if self.focus == F_OPERATE {
            Line::styled("  [ Operate ]", theme::tab_active())
        } else {
            Line::styled("  [ Operate ]", theme::muted())
        });
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "tab move · space toggle · enter operate · esc cancel",
            theme::help(),
        ));

        draw_box(f, area, 64, 14, "Operate control", theme::ACCENT, lines);
    }
}

/// Draws a centred bordered box over whatever is behind it.
fn draw_box(
    f: &mut Frame,
    area: Rect,
    width: u16,
    height: u16,
    title: &str,
    border: ratatui::style::Color,
    lines: Vec<Line<'static>>,
) {
    let r = centred(area, width, height);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ratatui::style::Style::default().fg(border))
        .title(Span::styled(
            format!(" {title} "),
            ratatui::style::Style::default()
                .fg(border)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ));
    let inner = block.inner(r);
    // Clear first, or the panel behind shows through the gaps.
    f.render_widget(Clear, r);
    f.render_widget(block, r);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        inner,
    );
}

/// Parses a value for the attribute's declared type.
///
/// A device rejects a write whose type does not match, so the text is parsed
/// as the type the model reports rather than guessed from its spelling.
pub fn parse_value(kind: Option<Type>, s: &str) -> Result<Value, String> {
    let s = s.trim();
    match kind {
        Some(Type::Boolean) => match s {
            "true" | "1" | "on" => Ok(Value::boolean(true)),
            "false" | "0" | "off" => Ok(Value::boolean(false)),
            _ => Err("expected true or false".into()),
        },
        Some(Type::Integer) => s
            .parse::<i64>()
            .map(Value::int64)
            .map_err(|e| e.to_string()),
        Some(Type::Unsigned) => s
            .parse::<u32>()
            .map(Value::uint32)
            .map_err(|e| e.to_string()),
        Some(Type::Float32) => s
            .parse::<f32>()
            .map(Value::float32)
            .map_err(|e| e.to_string()),
        Some(Type::Float64) => s
            .parse::<f64>()
            .map(Value::float64)
            .map_err(|e| e.to_string()),
        Some(Type::VisibleString) => Ok(Value::visible_string(s)),
        Some(Type::MmsString) => Ok(Value::mms_string(s)),
        Some(k) => Err(format!("unsupported type {k}")),
        None => Err("unknown type".into()),
    }
}

fn spawn_write(ctx: &Ctx, reference: ObjectReference, fc: Fc, value: Value) {
    let Some(client) = ctx.client() else { return };
    let ctx = ctx.clone();
    tokio::spawn(async move {
        let shown = value.to_string();
        match client.write(reference.clone(), fc, value).await {
            Ok(()) => ctx.ok(format!("wrote {reference} = {shown}")),
            Err(e) => ctx.err(format!("write failed: {e}")),
        }
    });
}

fn spawn_operate(ctx: &Ctx, d: &ControlDialog) {
    let Some(client) = ctx.client() else { return };
    let reference = d.reference.clone();
    let (on, test, interlock, synchro) = (d.on, d.test, d.interlock, d.synchro);
    let originator = d.originator.value.clone();
    let ctx = ctx.clone();
    tokio::spawn(async move {
        let control = match client.control_for(reference.clone()).await {
            Ok(c) => c,
            Err(e) => {
                ctx.err(format!("control setup failed: {e}"));
                return;
            }
        };
        let model = control.model();
        let opts = ControlOptions::new()
            .with_originator(OrCat::StationControl, originator)
            .with_test(test)
            .with_interlock_check(interlock)
            .with_synchro_check(synchro);

        match control.operate(Value::boolean(on), &opts).await {
            Ok(()) => ctx.ok(format!("operated {reference} = {on} ({model})")),
            // A control error carries the device's own diagnosis, which says
            // far more than the transport error underneath it.
            Err(ClientError::Control(e)) => {
                ctx.err(format!("operate rejected ({}): {}", e.stage, e.add_cause));
            }
            Err(e) => ctx.err(format!("operate failed: {e}")),
        }
    });
}

/// What the connection form wants the app to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormAction {
    Stay,
    Submit,
    Quit,
}

/// The initial connection screen.
pub struct ConnectForm {
    address: TextField,
    password: TextField,
    tls: bool,
    focus: usize,
}

const CF_FIELDS: usize = 4;
const CF_ADDRESS: usize = 0;
const CF_PASSWORD: usize = 1;
const CF_TLS: usize = 2;
const CF_CONNECT: usize = 3;

impl ConnectForm {
    pub fn new(address: &str, password: &str, tls: bool) -> ConnectForm {
        ConnectForm {
            address: TextField::new(address).with_placeholder("host:port"),
            password: TextField::new(password)
                .with_placeholder("(optional)")
                .masked(),
            tls,
            focus: CF_ADDRESS,
        }
    }

    pub fn address(&self) -> String {
        self.address.value.trim().to_string()
    }

    pub fn password(&self) -> String {
        self.password.value.clone()
    }

    pub fn tls(&self) -> bool {
        self.tls
    }

    pub fn on_key(&mut self, key: KeyEvent) -> FormAction {
        match key.code {
            KeyCode::Esc => return FormAction::Quit,
            KeyCode::Tab | KeyCode::Down => {
                self.focus = (self.focus + 1) % CF_FIELDS;
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.focus = (self.focus + CF_FIELDS - 1) % CF_FIELDS;
            }
            KeyCode::Enter => {
                if self.focus == CF_TLS {
                    self.tls = !self.tls;
                } else {
                    return FormAction::Submit;
                }
            }
            KeyCode::Char(' ') if self.focus == CF_TLS => self.tls = !self.tls,
            _ => match self.focus {
                CF_ADDRESS => {
                    self.address.on_key(key);
                }
                CF_PASSWORD => {
                    self.password.on_key(key);
                }
                _ => {}
            },
        }
        FormAction::Stay
    }

    pub fn draw(&self, f: &mut Frame, area: Rect) {
        let label = |i: usize, s: &str| -> Line<'static> {
            if self.focus == i {
                Line::styled(format!("▸ {s}"), theme::label())
            } else {
                Line::styled(format!("  {s}"), theme::muted())
            }
        };
        let lines = vec![
            label(CF_ADDRESS, "Address"),
            self.address.line(self.focus == CF_ADDRESS),
            label(CF_PASSWORD, "Password"),
            self.password.line(self.focus == CF_PASSWORD),
            Line::from(vec![
                Span::styled(
                    if self.focus == CF_TLS {
                        "▸ TLS (62351-3)  "
                    } else {
                        "  TLS (62351-3)  "
                    },
                    if self.focus == CF_TLS {
                        theme::label()
                    } else {
                        theme::muted()
                    },
                ),
                Span::styled(
                    if self.tls { "[x] on" } else { "[ ] off" },
                    theme::value(),
                ),
            ]),
            Line::raw(""),
            if self.focus == CF_CONNECT {
                Line::styled("  [ Connect ]", theme::tab_active())
            } else {
                Line::styled("  [ Connect ]", theme::muted())
            },
            Line::raw(""),
            Line::styled(
                "tab/↑↓ move · enter connect · space toggles TLS · esc quit",
                theme::help(),
            ),
        ];
        draw_box(f, area, 64, 13, "Connect to an IED", theme::ACCENT, lines);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyModifiers;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctx() -> Ctx {
        Ctx {
            client: None,
            tx: tokio::sync::mpsc::unbounded_channel().0,
        }
    }

    #[test]
    fn a_value_is_parsed_as_the_type_the_model_declares() {
        assert_eq!(
            parse_value(Some(Type::Boolean), "true").unwrap(),
            Value::boolean(true)
        );
        assert_eq!(
            parse_value(Some(Type::Boolean), "off").unwrap(),
            Value::boolean(false)
        );
        assert_eq!(
            parse_value(Some(Type::Integer), "-5").unwrap(),
            Value::int64(-5)
        );
        assert_eq!(
            parse_value(Some(Type::Unsigned), "230").unwrap(),
            Value::uint32(230)
        );
        assert_eq!(
            parse_value(Some(Type::Float32), "230.4").unwrap(),
            Value::float32(230.4)
        );
        assert_eq!(
            parse_value(Some(Type::VisibleString), " text ").unwrap(),
            Value::visible_string("text")
        );
    }

    /// A device rejects a mistyped write anyway; catching it here says what is
    /// wrong instead of showing a bare access error.
    #[test]
    fn a_value_of_the_wrong_shape_is_refused_before_it_is_sent() {
        assert!(parse_value(Some(Type::Boolean), "yes").is_err());
        assert!(parse_value(Some(Type::Integer), "1.5").is_err());
        assert!(parse_value(Some(Type::Unsigned), "-1").is_err());
        assert!(parse_value(Some(Type::Float32), "abc").is_err());
        assert!(parse_value(Some(Type::UtcTime), "now").is_err());
        assert!(parse_value(None, "x").is_err());
    }

    /// Editing a setpoint starts from what is there now; a string is rendered
    /// quoted, so prefilling it would write the quotes back into the device.
    #[test]
    fn the_write_dialog_prefills_only_what_parses_back() {
        let d = Dialog::write("LD/LN.DO.da".into(), Fc::Sp, Some(Type::Float32))
            .prefilled(Some("230.4"));
        let Dialog::Write { field, .. } = &d else {
            panic!("expected a write dialog");
        };
        assert_eq!(field.value, "230.4");
        assert_eq!(field.cursor, 5, "the cursor sits at the end, ready to edit");

        let d = Dialog::write("LD/LN.DO.da".into(), Fc::Sp, Some(Type::VisibleString))
            .prefilled(Some("\"text\""));
        let Dialog::Write { field, .. } = &d else {
            panic!("expected a write dialog");
        };
        assert!(field.value.is_empty());

        // A read that failed leaves an error message, not a value.
        let d = Dialog::write("LD/LN.DO.da".into(), Fc::Sp, Some(Type::Integer)).prefilled(None);
        let Dialog::Write { field, .. } = &d else {
            panic!("expected a write dialog");
        };
        assert!(field.value.is_empty());
    }

    #[test]
    fn the_write_dialog_closes_on_escape_and_stays_on_a_bad_value() {
        let mut d = Dialog::write("LD/LN.DO.da".into(), Fc::Cf, Some(Type::Integer));
        // A bad value keeps the dialog open so it can be corrected.
        if let Dialog::Write { field, .. } = &mut d {
            field.set("not a number");
        }
        assert!(!d.on_key(key(KeyCode::Enter), &ctx()));
        assert!(d.on_key(key(KeyCode::Esc), &ctx()));
    }

    /// Operating switchgear should take a deliberate confirmation, not a
    /// single keystroke.
    #[test]
    fn operating_requires_reaching_the_button_and_confirming() {
        let mut d = ControlDialog::new("LD/GGIO1.SPCSO1".into());
        assert_eq!(d.focus, F_VALUE);
        assert!(!d.confirm);

        // Enter anywhere but the button does not arm it.
        assert!(!d.on_key(key(KeyCode::Enter), &ctx()));
        assert!(!d.confirm);

        for _ in 0..F_OPERATE {
            d.on_key(key(KeyCode::Tab), &ctx());
        }
        assert_eq!(d.focus, F_OPERATE);
        assert!(!d.on_key(key(KeyCode::Enter), &ctx()));
        assert!(d.confirm, "the button arms the confirmation");

        // Any key but yes backs out, leaving the dialog open.
        assert!(!d.on_key(key(KeyCode::Char('n')), &ctx()));
        assert!(!d.confirm);
    }

    #[test]
    fn a_confirm_prompt_is_not_dismissed_by_a_stray_click() {
        assert!(Dialog::help().dismissable_by_click());
        assert!(!Dialog::control("LD/GGIO1.SPCSO1".into()).dismissable_by_click());
        assert!(!Dialog::write("LD/LN.DO.da".into(), Fc::Cf, None).dismissable_by_click());
    }

    #[test]
    fn the_control_dialog_toggles_its_checks_with_space() {
        let mut d = ControlDialog::new("LD/GGIO1.SPCSO1".into());
        assert!(d.on, "a control defaults to ON");
        d.on_key(key(KeyCode::Char(' ')), &ctx());
        assert!(!d.on);

        d.focus = F_INTERLOCK;
        d.on_key(key(KeyCode::Char(' ')), &ctx());
        assert!(d.interlock);
        d.focus = F_SYNCHRO;
        d.on_key(key(KeyCode::Char(' ')), &ctx());
        assert!(d.synchro);
        assert!(!d.test, "the other flags are untouched");
    }

    /// A space in the originator has to be text, not a toggle.
    #[test]
    fn the_originator_field_takes_spaces_as_text() {
        let mut d = ControlDialog::new("LD/GGIO1.SPCSO1".into());
        d.focus = F_ORIGINATOR;
        d.originator.set("");
        for c in "bay 1".chars() {
            d.on_key(key(KeyCode::Char(c)), &ctx());
        }
        assert_eq!(d.originator.value, "bay 1");
        assert!(d.on, "typing must not have toggled the value");
    }

    #[test]
    fn focus_wraps_in_both_directions() {
        let mut d = ControlDialog::new("LD/GGIO1.SPCSO1".into());
        d.on_key(key(KeyCode::BackTab), &ctx());
        assert_eq!(d.focus, F_OPERATE, "back from the first row wraps to the last");
        d.on_key(key(KeyCode::Tab), &ctx());
        assert_eq!(d.focus, F_VALUE);
    }

    #[test]
    fn the_connect_form_submits_and_quits() {
        let mut f = ConnectForm::new("", "", false);
        for c in "127.0.0.1:102".chars() {
            f.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(f.address(), "127.0.0.1:102");
        assert_eq!(f.on_key(key(KeyCode::Enter)), FormAction::Submit);
        assert_eq!(f.on_key(key(KeyCode::Esc)), FormAction::Quit);
    }

    #[test]
    fn the_connect_form_toggles_tls_rather_than_submitting() {
        let mut f = ConnectForm::new("host:102", "", false);
        f.focus = CF_TLS;
        assert_eq!(f.on_key(key(KeyCode::Enter)), FormAction::Stay);
        assert!(f.tls(), "enter on the toggle flips it instead of connecting");
        f.on_key(key(KeyCode::Char(' ')));
        assert!(!f.tls());
    }

    #[test]
    fn the_password_is_typed_into_the_focused_field_only() {
        let mut f = ConnectForm::new("host:102", "", false);
        f.focus = CF_PASSWORD;
        for c in "secret".chars() {
            f.on_key(key(KeyCode::Char(c)));
        }
        assert_eq!(f.password(), "secret");
        assert_eq!(f.address(), "host:102", "the address is untouched");
    }

    #[test]
    fn the_address_is_trimmed_so_a_stray_space_does_not_break_the_dial() {
        let mut f = ConnectForm::new("  host:102  ", "", false);
        assert_eq!(f.address(), "host:102");
        let _ = &mut f;
    }
}
