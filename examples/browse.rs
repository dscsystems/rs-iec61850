//! Browses an IED: its logical devices, nodes and data objects.
//!
//! ```sh
//! cargo run --example browse -- 127.0.0.1:10102
//! ```

use iec61850::client::{AcsiClass, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:10102".into());
    let client = Client::dial(&addr).await?;

    let (vendor, model, revision) = client.mms().identify().await?;
    println!("{vendor} {model} {revision}\n");

    for ld in client.logical_devices().await? {
        println!("LD {ld}");
        for ln in client.logical_nodes(&ld).await? {
            let reference = format!("{ld}/{ln}");
            let data = client
                .logical_node_directory(reference.clone(), AcsiClass::DataObject)
                .await?;
            println!("  LN {ln}  ({} data objects)", data.len());

            for class in [
                AcsiClass::DataSet,
                AcsiClass::Urcb,
                AcsiClass::Brcb,
                AcsiClass::GoCb,
            ] {
                let found = client
                    .logical_node_directory(reference.clone(), class)
                    .await
                    .unwrap_or_default();
                if !found.is_empty() {
                    println!("    {class}: {}", found.join(", "));
                }
            }
        }
    }

    client.close().await?;
    Ok(())
}
