//! `iedx` — an interactive IEC 61850 client for the terminal.
//!
//! Browse a server's model, read and write values, subscribe to reports,
//! operate controls, switch setting groups, fetch files and query logs, all
//! from one screen.
//!
//! ```text
//! iedx 127.0.0.1:102
//! iedx                       # opens the connect form
//! ```

mod app;
mod browse;
mod controls;
mod datasets;
mod dialogs;
mod files;
mod logs;
mod reports;
mod settings;
mod theme;
mod widgets;

use std::io::{self, Stdout};
use std::time::Duration;

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind,
};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::Terminal;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::app::{App, Msg};

const USAGE: &str = "\
iedx — interactive IEC 61850 client

usage: iedx [options] [host[:port]]

options:
  -p, --password <s>   password for the ACSE authentication value
      --tls            connect with TLS (IEC 62351-3)
  -h, --help           show this help

The port defaults to 102. With no address the connect form opens.
";

struct Args {
    addr: String,
    password: String,
    tls: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut out = Args {
        addr: String::new(),
        password: String::new(),
        tls: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-p" | "--password" => {
                out.password = it.next().ok_or("--password needs a value")?;
            }
            "--tls" => out.tls = true,
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other}"));
            }
            other => out.addr = normalise_addr(other),
        }
    }
    Ok(out)
}

/// Adds the default MMS port when the address gives only a host.
///
/// A bare IPv6 address has colons of its own, so only a bracketed form or a
/// single colon is taken as carrying a port.
pub fn normalise_addr(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    if s.starts_with('[') {
        return if s.ends_with(']') {
            format!("{s}:102")
        } else {
            s.to_string()
        };
    }
    match s.matches(':').count() {
        0 => format!("{s}:102"),
        1 => s.to_string(),
        // Unbracketed IPv6: bracket it so it can carry a port.
        _ => format!("[{s}]:102"),
    }
}

type Term = Terminal<CrosstermBackend<Stdout>>;

fn setup_terminal() -> io::Result<Term> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    Terminal::new(CrosstermBackend::new(out))
}

fn restore_terminal() {
    // Best effort: this also runs from the panic hook, where returning an
    // error would only replace one failure with another.
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
}

/// Reads terminal events on a blocking thread.
///
/// crossterm's read is a blocking syscall, so it must not run on a runtime
/// worker; the poll timeout is what lets the thread notice the UI has quit.
fn spawn_input(tx: UnboundedSender<Event>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || loop {
        match ratatui::crossterm::event::poll(Duration::from_millis(200)) {
            Ok(true) => match ratatui::crossterm::event::read() {
                Ok(ev) => {
                    if tx.send(ev).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            },
            Ok(false) => {
                if tx.is_closed() {
                    return;
                }
            }
            Err(_) => return,
        }
    })
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("iedx: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    // A panic would otherwise leave the terminal in raw mode on the alternate
    // screen, with the message invisible.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));

    let mut term = match setup_terminal() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("iedx: terminal setup failed: {e}");
            std::process::exit(1);
        }
    };

    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::unbounded_channel();
    let input = spawn_input(ev_tx);

    let mut app = App::new(args.addr, args.password, args.tls, msg_tx);
    app.start();

    let result = run(&mut term, &mut app, msg_rx, ev_rx).await;

    restore_terminal();
    // The reader thread ends once its channel closes, which the drop above
    // has already done; joining keeps it from writing after the restore.
    drop(term);
    let _ = input.join();

    if let Err(e) = result {
        eprintln!("iedx: {e}");
        std::process::exit(1);
    }
}

/// The event loop: redraw, then wait for whichever arrives first.
async fn run(
    term: &mut Term,
    app: &mut App,
    mut msg_rx: UnboundedReceiver<Msg>,
    mut ev_rx: UnboundedReceiver<Event>,
) -> io::Result<()> {
    loop {
        term.draw(|f| app.draw(f))?;
        if app.should_quit {
            return Ok(());
        }

        tokio::select! {
            Some(msg) = msg_rx.recv() => {
                app.on_msg(msg);
                // Drain whatever else is already queued before redrawing, so a
                // burst of report lines costs one frame rather than one each.
                while let Ok(m) = msg_rx.try_recv() {
                    app.on_msg(m);
                }
            }
            ev = ev_rx.recv() => {
                let Some(ev) = ev else { return Ok(()) };
                match ev {
                    // Windows reports both press and release; acting on both
                    // would run every key twice.
                    Event::Key(k) if k.kind == KeyEventKind::Press => app.on_key(k),
                    Event::Mouse(m) => app.on_mouse(m),
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }
            else => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_without_a_port_gets_the_default() {
        assert_eq!(normalise_addr("192.0.2.1"), "192.0.2.1:102");
        assert_eq!(normalise_addr("ied.example"), "ied.example:102");
    }

    #[test]
    fn an_explicit_port_is_kept() {
        assert_eq!(normalise_addr("192.0.2.1:10102"), "192.0.2.1:10102");
        assert_eq!(normalise_addr("[::1]:10102"), "[::1]:10102");
    }

    /// A bare IPv6 address has colons of its own, so it has to be bracketed
    /// before a port can be appended.
    #[test]
    fn a_bare_ipv6_address_is_bracketed() {
        assert_eq!(normalise_addr("::1"), "[::1]:102");
        assert_eq!(normalise_addr("[::1]"), "[::1]:102");
        assert_eq!(normalise_addr("fe80::1"), "[fe80::1]:102");
    }

    #[test]
    fn an_empty_address_stays_empty_so_the_form_opens() {
        assert_eq!(normalise_addr(""), "");
    }
}
