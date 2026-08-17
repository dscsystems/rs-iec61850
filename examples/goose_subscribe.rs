//! Subscribes to GOOSE on a network interface and prints every message.
//!
//! Needs CAP_NET_RAW (or root) and is Linux-only:
//!
//! ```sh
//! sudo -E cargo run --example goose_subscribe -- eth0
//! ```

use std::sync::Arc;

use iec61850::{ethernet, goose};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ifname = std::env::args().nth(1).unwrap_or_else(|| "eth0".into());

    let iface: Arc<dyn ethernet::Interface> =
        ethernet::open(&ifname, &[ethernet::ETHER_TYPE_GOOSE])?.into();
    println!("listening for GOOSE on {ifname}; press ctrl-c to stop");

    let subscription = goose::Subscriber::new(iface).subscribe(goose::Filter::any(), |m| {
        print!(
            "{} stNum={} sqNum={} confRev={} ttl={}ms values={}",
            m.go_cb_ref,
            m.st_num,
            m.sq_num,
            m.conf_rev,
            m.time_allowed_to_live,
            m.values.len()
        );
        if m.test {
            print!(" TEST");
        }
        // The anomalies are how a lost frame or a restarted publisher becomes
        // visible; a clean stream reports none.
        let a = m.anomalies;
        if a.any() {
            print!(" ANOMALY:");
            if a.st_num_regressed {
                print!(" stNum-regressed");
            }
            if a.sq_num_gap {
                print!(" sqNum-gap");
            }
            if a.stale {
                print!(" stale");
            }
        }
        println!();
        for (i, v) in m.values.iter().enumerate() {
            println!("    [{i}] {v}");
        }
    });

    // Block until interrupted; the subscription stops when it is dropped.
    std::thread::park();
    drop(subscription);
    Ok(())
}
