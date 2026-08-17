//! Prints every GOOSE message seen on an interface.
//!
//! Needs CAP_NET_RAW (or root) and is Linux-only:
//!
//! ```sh
//! sudo goose-sniff --iface eth0 --appid 0x1000
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use iec61850::{ethernet, goose};

fn usage() -> ! {
    eprintln!(
        "usage: goose-sniff [options]

  --iface NAME   interface to listen on (default eth0)
  --appid HEX    only show this APPID (for example 0x1000)
  --gocbref REF  only show this control block
  --quiet        one line per message, without the values
  --help"
    );
    std::process::exit(2)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut ifname, mut filter, mut quiet) =
        ("eth0".to_string(), goose::Filter::any(), false);

    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--iface" => ifname = it.next().unwrap_or_else(|| usage()),
            "--appid" => {
                let v = it.next().unwrap_or_else(|| usage());
                let s = v.trim_start_matches("0x");
                filter.app_id = u16::from_str_radix(s, 16).unwrap_or_else(|_| usage());
            }
            "--gocbref" => filter.go_cb_ref = it.next().unwrap_or_else(|| usage()),
            "--quiet" => quiet = true,
            "--help" | "-h" => usage(),
            other => {
                eprintln!("unknown option {other}");
                usage()
            }
        }
    }

    let iface: Arc<dyn ethernet::Interface> =
        ethernet::open(&ifname, &[ethernet::ETHER_TYPE_GOOSE])?.into();
    eprintln!("goose-sniff: listening on {ifname}");

    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);

    let subscription = goose::Subscriber::new(iface).subscribe(filter, move |m| {
        let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
        let mut line = format!(
            "#{n} appid=0x{:04x} {} stNum={} sqNum={} confRev={} ttl={}ms entries={}",
            m.app_id,
            m.go_cb_ref,
            m.st_num,
            m.sq_num,
            m.conf_rev,
            m.time_allowed_to_live,
            m.values.len()
        );
        if m.test {
            line.push_str(" TEST");
        }
        if m.nds_com {
            line.push_str(" NDSCOM");
        }
        let a = m.anomalies;
        if a.any() {
            line.push_str(" ANOMALY:");
            if a.st_num_regressed {
                line.push_str(" stNum-regressed");
            }
            if a.sq_num_gap {
                line.push_str(" sqNum-gap");
            }
            if a.stale {
                line.push_str(" stale");
            }
        }
        println!("{line}");
        if !quiet {
            for (i, v) in m.values.iter().enumerate() {
                println!("    [{i}] {v}");
            }
        }
    });

    std::thread::park();
    drop(subscription);
    Ok(())
}
