//! Subscribes to a report control block and prints every report.
//!
//! ```sh
//! cargo run --example report_monitor -- 127.0.0.1:10102 simpleIOGenericIO/LLN0.RP.EventsRCB01
//! ```

use iec61850::client::Client;
use iec61850::model::{OptFlds, TrgOps};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:10102".into());
    let rcb_ref = args
        .next()
        .unwrap_or_else(|| "simpleIOGenericIO/LLN0.RP.EventsRCB01".into());

    let client = Client::dial(&addr).await?;

    let mut rcb = client.get_rcb(rcb_ref.clone()).await?;
    println!(
        "{rcb_ref}: rptID={:?} dataset={:?} confRev={}",
        rcb.rpt_id, rcb.data_set, rcb.conf_rev
    );
    rcb.opt_flds = OptFlds::DEFAULT;
    rcb.trg_ops = TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE | TrgOps::GI;

    // The callback runs on the connection's reader task and must not block.
    let subscription = client
        .enable_reporting(&rcb, |report| {
            println!(
                "\nreport seq={} confRev={} entries={}",
                report.seq_num,
                report.conf_rev,
                report.entries.len()
            );
            for e in &report.entries {
                println!("  [{}] {} ({}) = {}", e.index, e.reference, e.reason, e.value);
            }
        })
        .await?;

    // A general interrogation fills the cache before the live stream starts.
    client.trigger_gi(&rcb).await?;
    println!("subscribed; press ctrl-c to stop");

    tokio::signal::ctrl_c().await?;
    subscription.disable().await?;
    client.close().await?;
    Ok(())
}
