//! Compile check for the code in [`SKILL.md`](../SKILL.md).
//!
//! The snippets there are what an agent will paste into a new application, so
//! a signature change that invalidates them has to fail the build rather than
//! wait to be discovered by whoever follows the guide. Nothing here runs: the
//! addresses and files it names do not exist.
#![allow(dead_code, unused_variables)]

use std::sync::Arc;
use std::time::Duration;

use iec61850::client::{Client, ControlOptions, Options};
use iec61850::mms::{BoxTransport, Value};
use iec61850::model::{AddCause, Cdc, CdcOptions, Fc, OptFlds, OrCat, Quality, TrgOps};
use iec61850::server::{Identity, Server};
use iec61850::{ethernet, goose, model, scl, server};

async fn client_recipes(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::dial("192.168.10.5:102").await?;
    let client = Client::dial_with(
        addr,
        Options::new()
            .with_timeout(Duration::from_secs(5))
            .with_password("secret"),
    )
    .await?;

    client.read("ied1LD0/GGIO1.AnIn1.mag.f", Fc::Mx).await?;
    client.read("ied1LD0/GGIO1.Ind1.stVal", Fc::St).await?;
    client
        .write("ied1LD0/GGIO1.SPCSO1.ctlModel", Fc::Cf, Value::int32(1))
        .await?;

    let _model = client.retrieve_model().await?;
    let refs = vec![model::ObjectReference::new("ied1LD0/GGIO1.AnIn1.mag.f")];
    let _ = client.read_values(Fc::Mx, &refs).await?;
    let _ = client.read_many(Fc::Mx, &refs).await;

    let mut rcb = client.get_rcb("ied1LD0/LLN0.RP.EventsRCB01").await?;
    rcb.opt_flds = OptFlds::DEFAULT;
    rcb.trg_ops = TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE | TrgOps::GI;

    let subscription = client
        .enable_reporting(&rcb, |report| {
            for e in &report.entries {
                println!("{} ({}) = {}", e.reference, e.reason, e.value);
            }
        })
        .await?;

    client.trigger_gi(&rcb).await?;
    subscription.disable().await?;

    let control = client.control_for("ied1LD0/GGIO1.SPCSO1").await?;
    control
        .operate(
            Value::boolean(true),
            &ControlOptions::new()
                .with_originator(OrCat::StationControl, "scada-1")
                .with_interlock_check(true),
        )
        .await?;

    client.closed().await;
    Ok(())
}

fn interlocked() -> bool {
    false
}

async fn server_recipes() -> Result<(), Box<dyn std::error::Error>> {
    let model = scl::load_model("ied.cid", &scl::BuildOptions::new().for_ied("IED1"))?;
    let server = Server::new(
        model,
        server::Options::new()
            .with_identity(Identity {
                vendor: "ACME".into(),
                model: "GW".into(),
                revision: "1.0".into(),
            })
            .with_file_store("/var/comtrade")
            .with_setting_groups(4),
    );

    server.on_connection(|ev| println!("{} from {:?} ({} open)", ev.state, ev.peer, ev.open));

    server.on_control("IED1LD0/GGIO1.SPCSO1", |_ctx| {
        if interlocked() {
            return AddCause::BLOCKED_BY_INTERLOCKING;
        }
        AddCause::NONE
    });

    server.on_write(|da, _value| {
        if da.name == "ctlModel" {
            return Err(iec61850::server::ERR_ACCESS_DENIED);
        }
        Ok(())
    });

    server.update(|tx| {
        tx.set_float32("IED1LD0/GGIO1.AnIn1.mag.f", 230.4);
        tx.set_quality("IED1LD0/GGIO1.AnIn1.q", Fc::Mx, Quality::GOOD);
        tx.set_timestamp_now("IED1LD0/GGIO1.AnIn1.t", Fc::Mx);
    });

    let _spc = model::new_data_object("SPCSO1", Cdc::Spc, &CdcOptions::new());

    server.listen_and_serve("0.0.0.0:102").await?;
    Ok(())
}

fn process_bus() -> Result<(), Box<dyn std::error::Error>> {
    let eth: Arc<dyn ethernet::Interface> =
        ethernet::open("eth0", &[ethernet::ETHER_TYPE_GOOSE])?.into();

    let _subscription = goose::Subscriber::new(eth).subscribe(goose::Filter::app_id(0x1000), |m| {
        let _ = (m.st_num, m.sq_num, &m.values, m.anomalies);
    });
    Ok(())
}

async fn in_process_harness() -> Result<(), Box<dyn std::error::Error>> {
    let model = scl::load_model("ied.cid", &scl::BuildOptions::new())?;
    let srv = Server::new(model, server::Options::new());
    let (client_side, server_side) = tokio::io::duplex(256 * 1024);
    let serving = srv.clone();
    tokio::spawn(async move {
        serving
            .serve_stream(Box::new(server_side) as BoxTransport, None)
            .await
    });
    let _client = Client::from_stream(
        Box::new(client_side) as BoxTransport,
        iec61850::client::Options::new(),
    )
    .await?;
    Ok(())
}

/// The guide claims the package and the library have different names, which is
/// the first thing a new application gets wrong.
#[test]
fn the_library_is_imported_under_its_own_name() {
    assert!(!iec61850::VERSION.is_empty());
}
