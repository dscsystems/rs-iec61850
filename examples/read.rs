//! Reads a value from an IED.
//!
//! ```sh
//! cargo run --example read -- 127.0.0.1:10102 simpleIOGenericIO/GGIO1.AnIn1.mag.f MX
//! ```

use std::time::Duration;

use iec61850::client::{Client, Options};
use iec61850::model::Fc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:10102".into());
    let reference = args
        .next()
        .unwrap_or_else(|| "simpleIOGenericIO/GGIO1.AnIn1.mag.f".into());
    let fc: Fc = args.next().unwrap_or_else(|| "MX".into()).parse()?;

    let client = Client::dial_with(
        &addr,
        Options::new().with_timeout(Duration::from_secs(5)),
    )
    .await?;

    let value = client.read(reference.clone(), fc).await?;
    println!("{reference} [{fc}] = {value}");

    client.close().await?;
    Ok(())
}
