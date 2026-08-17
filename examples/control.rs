//! Operates a controllable object, handling whichever control model the
//! device is configured for.
//!
//! ```sh
//! cargo run --example control -- 127.0.0.1:10102 simpleIOGenericIO/GGIO1.SPCSO1 true
//! ```

use iec61850::client::{Client, ControlOptions};
use iec61850::mms::Value;
use iec61850::model::OrCat;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:10102".into());
    let object = args
        .next()
        .unwrap_or_else(|| "simpleIOGenericIO/GGIO1.SPCSO1".into());
    let on: bool = args.next().unwrap_or_else(|| "true".into()).parse()?;

    let client = Client::dial(&addr).await?;

    // The control model is read from ctlModel, and operate() runs whichever
    // sequence it calls for: a select first for the SBO models.
    let control = client.control_for(object.clone()).await?;
    println!("{object}: {}", control.model());

    let options = ControlOptions::new()
        .with_originator(OrCat::StationControl, "rs-iec61850-example")
        .with_interlock_check(true);

    match control.operate(Value::boolean(on), &options).await {
        Ok(()) => println!("operate {on} accepted (ctlNum {})", control.ctl_num()),
        Err(e) => {
            // A control error carries the device's own diagnosis.
            eprintln!("operate {on} refused: {e}");
            std::process::exit(1);
        }
    }

    client.close().await?;
    Ok(())
}
