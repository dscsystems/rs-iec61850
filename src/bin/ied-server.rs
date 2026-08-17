//! A test IED server: serves an SCL model over MMS with simulated live data,
//! accepts controls, and optionally serves files.
//!
//! ```sh
//! ied-server --scl testdata/simpleIO_direct_control.cid --addr :10102 --files /tmp/comtrade
//! ```

use std::time::Duration;

use iec61850::model::{AddCause, Fc, Quality};
use iec61850::scl;
use iec61850::server::{Identity, Options, Server};

struct Args {
    scl: String,
    addr: String,
    files: Option<String>,
    ied: String,
    setting_groups: u8,
    quiet: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: ied-server [options]

  --scl PATH       SCL file to serve (default testdata/simpleIO_direct_control.cid)
  --addr ADDR      listen address (default 0.0.0.0:10102; \":port\" is accepted)
  --ied NAME       IED to instantiate when the file holds several
  --files DIR      serve MMS file services from DIR
  --setting-groups N  enable N setting groups
  --quiet          do not log connections and controls
  --help"
    );
    std::process::exit(2)
}

fn parse_args() -> Args {
    let mut a = Args {
        scl: "testdata/simpleIO_direct_control.cid".into(),
        addr: "0.0.0.0:10102".into(),
        files: None,
        ied: String::new(),
        setting_groups: 0,
        quiet: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--scl" => a.scl = it.next().unwrap_or_else(|| usage()),
            "--addr" => a.addr = it.next().unwrap_or_else(|| usage()),
            "--ied" => a.ied = it.next().unwrap_or_else(|| usage()),
            "--files" => a.files = Some(it.next().unwrap_or_else(|| usage())),
            "--setting-groups" => {
                a.setting_groups = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--quiet" => a.quiet = true,
            "--help" | "-h" => usage(),
            other => {
                eprintln!("unknown option {other}");
                usage()
            }
        }
    }
    // ":10102" is the conventional shorthand for every interface.
    if let Some(port) = a.addr.strip_prefix(':') {
        a.addr = format!("0.0.0.0:{port}");
    }
    a
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();

    let model = scl::load_model(
        &args.scl,
        &scl::BuildOptions::new().for_ied(args.ied.clone()),
    )?;
    let devices: Vec<String> = model.devices.iter().map(|d| d.name.clone()).collect();
    println!(
        "ied-server: {} from {} ({} logical device{})",
        model.name,
        args.scl,
        devices.len(),
        if devices.len() == 1 { "" } else { "s" }
    );
    for d in &devices {
        println!("  {d}");
    }

    let mut opts = Options::new().with_identity(Identity {
        vendor: "DSC Systems".into(),
        model: model.name.clone(),
        revision: env!("CARGO_PKG_VERSION").into(),
    });
    if let Some(dir) = &args.files {
        println!("  file services from {dir}");
        opts = opts.with_file_store(dir);
    }
    if args.setting_groups > 0 {
        println!("  {} setting groups", args.setting_groups);
        opts = opts.with_setting_groups(args.setting_groups);
    }

    let server = Server::new(model, opts);

    if !args.quiet {
        server.on_connection(|ev| {
            println!(
                "ied-server: connection {} from {:?} ({} open)",
                ev.state, ev.peer, ev.open
            );
        });
    }

    // Accept every control, logging who sent it.
    let quiet = args.quiet;
    for ld in &devices {
        for i in 1..=4 {
            server.on_control(format!("{ld}/GGIO1.SPCSO{i}"), move |ctx| {
                if !quiet {
                    println!(
                        "ied-server: {} {} = {} by {:?} ctlNum={} test={} from {:?}",
                        if ctx.select { "select" } else { "operate" },
                        ctx.reference,
                        ctx.value,
                        ctx.or_ident,
                        ctx.ctl_num,
                        ctx.test,
                        ctx.peer
                    );
                }
                AddCause::NONE
            });
        }
    }

    spawn_simulation(server.clone(), devices);

    println!("ied-server: listening on {}", args.addr);
    server.listen_and_serve(&args.addr).await?;
    Ok(())
}

/// Drives the process image so configured reports have something to fire on:
/// measurands drift, status points toggle, and every value carries a fresh
/// quality and timestamp.
fn spawn_simulation(server: Server, devices: Vec<String>) {
    tokio::spawn(async move {
        let mut tick: u32 = 0;
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            tick += 1;
            server.update(|tx| {
                for ld in &devices {
                    for i in 1..=4u32 {
                        let phase = (tick as f32) * 0.1 + i as f32;
                        tx.set_float32(
                            format!("{ld}/GGIO1.AnIn{i}.mag.f"),
                            230.0 + 10.0 * phase.sin(),
                        );
                        tx.set_quality(format!("{ld}/GGIO1.AnIn{i}.q"), Fc::Mx, Quality::GOOD);
                        tx.set_timestamp_now(format!("{ld}/GGIO1.AnIn{i}.t"), Fc::Mx);
                    }
                    // Stagger the status points so reports arrive steadily
                    // rather than all at once.
                    let which = (tick % 4) + 1;
                    tx.toggle(format!("{ld}/GGIO1.Ind{which}.stVal"), Fc::St);
                    tx.set_timestamp_now(format!("{ld}/GGIO1.Ind{which}.t"), Fc::St);
                }
            });
        }
    });
}
