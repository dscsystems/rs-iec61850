//! Serves an SCL model over MMS, with simulated live data.
//!
//! ```sh
//! cargo run --example server -- testdata/simpleIO_direct_control.cid 0.0.0.0:10102
//! ```

use std::time::Duration;

use iec61850::model::{AddCause, Fc, Quality};
use iec61850::scl;
use iec61850::server::{Identity, Options, Server};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "testdata/simpleIO_direct_control.cid".into());
    let addr = args.next().unwrap_or_else(|| "0.0.0.0:10102".into());

    let model = scl::load_model(&path, &scl::BuildOptions::new())?;
    let ld = model.devices[0].name.clone();
    println!("serving {} from {path} on {addr}", model.name);

    let server = Server::new(
        model,
        Options::new().with_identity(Identity {
            vendor: "DSC Systems".into(),
            model: "rs-iec61850 example".into(),
            revision: env!("CARGO_PKG_VERSION").into(),
        }),
    );

    server.on_connection(|ev| {
        println!("connection {} from {:?} ({} open)", ev.state, ev.peer, ev.open);
    });

    // Accept every control and log it. Returning any other cause refuses the
    // command with that diagnosis.
    for i in 1..=4 {
        server.on_control(format!("{ld}/GGIO1.SPCSO{i}"), move |ctx| {
            println!(
                "control {} = {} by {:?} (test={}, from {:?})",
                ctx.reference, ctx.value, ctx.or_ident, ctx.test, ctx.peer
            );
            AddCause::NONE
        });
    }

    // Drive the process image: measurands drift, status points toggle.
    let updating = server.clone();
    let device = ld.clone();
    tokio::spawn(async move {
        let mut tick = 0u32;
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            tick += 1;
            updating.update(|tx| {
                for i in 1..=4u32 {
                    let phase = f32::from(tick as u16) * 0.1 + i as f32;
                    tx.set_float32(
                        format!("{device}/GGIO1.AnIn{i}.mag.f"),
                        230.0 + 10.0 * phase.sin(),
                    );
                    tx.set_quality(format!("{device}/GGIO1.AnIn{i}.q"), Fc::Mx, Quality::GOOD);
                    tx.set_timestamp_now(format!("{device}/GGIO1.AnIn{i}.t"), Fc::Mx);
                }
                // One status point toggles every few seconds so configured
                // reports have something to fire on.
                if tick % 5 == 0 {
                    tx.toggle(format!("{device}/GGIO1.Ind1.stVal"), Fc::St);
                    tx.set_timestamp_now(format!("{device}/GGIO1.Ind1.t"), Fc::St);
                }
            });
        }
    });

    server.listen_and_serve(&addr).await?;
    Ok(())
}
