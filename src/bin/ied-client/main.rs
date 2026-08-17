//! A command-line ACSI client: browse, read, write, control, and a `test`
//! subcommand that exercises every feature a server exposes and prints a
//! PASS/FAIL/SKIP report.
//!
//! ```sh
//! ied-client --addr 127.0.0.1:10102 browse
//! ied-client --addr 127.0.0.1:10102 read simpleIOGenericIO/GGIO1.AnIn1.mag.f MX
//! ied-client --addr 127.0.0.1:10102 test
//! ```

mod sweep;

use std::time::Duration;

use iec61850::client::{AcsiClass, Client, ControlOptions, Options};
use iec61850::mms::Value;
use iec61850::model::{Fc, OrCat};

fn usage() -> ! {
    eprintln!(
        "usage: ied-client [--addr HOST:PORT] [--password PW] COMMAND

commands:
  identify                      report the server's vendor, model and revision
  browse                        list logical devices, nodes and control blocks
  model                         retrieve and print the whole data model
  read REF [FC]                 read one value (FC defaults to MX)
  write REF FC VALUE            write one value
  dataset REF                   read a dataset and its members
  control REF on|off            operate a controllable object
  report RCBREF                 subscribe to a report control block
  test                          exercise every feature and report PASS/FAIL/SKIP
"
    );
    std::process::exit(2)
}

/// Parses a value from the command line, guessing the type from its spelling.
///
/// A device rejects a write whose type does not match the attribute, so the
/// guess has to follow what the text looks like rather than a default.
fn parse_value(s: &str) -> Value {
    if let Ok(b) = s.parse::<bool>() {
        return Value::boolean(b);
    }
    if let Ok(i) = s.parse::<i32>() {
        return Value::int32(i);
    }
    if let Ok(f) = s.parse::<f32>() {
        return Value::float32(f);
    }
    Value::visible_string(s)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut addr = "127.0.0.1:10102".to_string();
    let mut password: Option<String> = None;
    let mut rest: Vec<String> = Vec::new();

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--addr" => addr = it.next().unwrap_or_else(|| usage()),
            "--password" => password = Some(it.next().unwrap_or_else(|| usage())),
            "--help" | "-h" => usage(),
            _ => {
                rest.push(a);
                rest.extend(it);
                break;
            }
        }
    }
    if rest.is_empty() {
        usage();
    }

    let mut opts = Options::new().with_timeout(Duration::from_secs(10));
    if let Some(pw) = password {
        opts = opts.with_password(pw);
    }
    let client = Client::dial_with(&addr, opts).await?;

    let code = run(&client, &rest).await;
    client.close().await.ok();
    std::process::exit(code);
}

async fn run(client: &Client, args: &[String]) -> i32 {
    let result = match args[0].as_str() {
        "identify" => identify(client).await,
        "browse" => browse(client).await,
        "model" => model(client).await,
        "read" => read(client, &args[1..]).await,
        "write" => write(client, &args[1..]).await,
        "dataset" => dataset(client, &args[1..]).await,
        "control" => control(client, &args[1..]).await,
        "report" => report(client, &args[1..]).await,
        "test" => return sweep::run(client).await,
        other => {
            eprintln!("unknown command {other}");
            usage()
        }
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

type Res = Result<(), Box<dyn std::error::Error>>;

async fn identify(client: &Client) -> Res {
    let (vendor, model, revision) = client.mms().identify().await?;
    println!("vendor:   {vendor}");
    println!("model:    {model}");
    println!("revision: {revision}");
    Ok(())
}

async fn browse(client: &Client) -> Res {
    for ld in client.logical_devices().await? {
        println!("LD {ld}");
        for ln in client.logical_nodes(&ld).await? {
            let reference = format!("{ld}/{ln}");
            println!("  LN {ln}");
            for class in [
                AcsiClass::DataObject,
                AcsiClass::DataSet,
                AcsiClass::Urcb,
                AcsiClass::Brcb,
                AcsiClass::Lcb,
                AcsiClass::Sgcb,
                AcsiClass::GoCb,
                AcsiClass::Msvcb,
            ] {
                let found = client
                    .logical_node_directory(reference.clone(), class)
                    .await
                    .unwrap_or_default();
                if !found.is_empty() {
                    println!("    {class:<9} {}", found.join(", "));
                }
            }
        }
    }
    Ok(())
}

async fn model(client: &Client) -> Res {
    print!("{}", client.retrieve_model().await?);
    Ok(())
}

async fn read(client: &Client, args: &[String]) -> Res {
    let reference = args.first().ok_or("read needs a reference")?;
    let fc: Fc = args.get(1).map_or(Ok(Fc::Mx), |s| s.parse())?;
    println!("{}", client.read(reference.clone(), fc).await?);
    Ok(())
}

async fn write(client: &Client, args: &[String]) -> Res {
    if args.len() < 3 {
        return Err("write needs REF FC VALUE".into());
    }
    let fc: Fc = args[1].parse()?;
    client
        .write(args[0].clone(), fc, parse_value(&args[2]))
        .await?;
    println!("ok");
    Ok(())
}

async fn dataset(client: &Client, args: &[String]) -> Res {
    let reference = args.first().ok_or("dataset needs a reference")?;
    let ds = client.read_data_set(reference.clone()).await?;
    for m in &ds.members {
        println!(
            "{} [{}] = {}",
            m.reference,
            m.fc,
            m.value.as_ref().map_or("<none>".into(), |v| v.to_string())
        );
    }
    Ok(())
}

async fn control(client: &Client, args: &[String]) -> Res {
    if args.len() < 2 {
        return Err("control needs REF on|off".into());
    }
    let on = matches!(args[1].as_str(), "on" | "true" | "1");
    let co = client.control_for(args[0].clone()).await?;
    println!("{}: {}", args[0], co.model());
    co.operate(
        Value::boolean(on),
        &ControlOptions::new().with_originator(OrCat::StationControl, "ied-client"),
    )
    .await?;
    println!("operate {on} accepted (ctlNum {})", co.ctl_num());
    Ok(())
}

async fn report(client: &Client, args: &[String]) -> Res {
    let reference = args.first().ok_or("report needs an RCB reference")?;
    let rcb = client.get_rcb(reference.clone()).await?;
    println!("rptID={:?} dataset={:?}", rcb.rpt_id, rcb.data_set);

    let sub = client
        .enable_reporting(&rcb, |r| {
            println!("report seq={} entries={}", r.seq_num, r.entries.len());
            for e in &r.entries {
                println!("  {} ({}) = {}", e.reference, e.reason, e.value);
            }
        })
        .await?;
    client.trigger_gi(&rcb).await.ok();
    println!("subscribed; press ctrl-c to stop");
    tokio::signal::ctrl_c().await?;
    sub.disable().await?;
    Ok(())
}
