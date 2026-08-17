---
name: rs-iec61850
description: Build IEC 61850 applications with the rs-iec61850 crate - MMS client and server, GOOSE and Sampled Values publish/subscribe, SCL loading. Use when writing, reviewing or debugging Rust that talks to an IED, simulates one, subscribes to reports, operates controls, or handles process-bus traffic.
---

# Building applications with rs-iec61850

A pure-Rust IEC 61850 stack: ACSI client and server over MMS, GOOSE and
Sampled Values over raw Ethernet, and SCL configuration loading. Async on
tokio, no C bindings.

This file is the working guide. [`docs/api.md`](docs/api.md) is the full API
tour, [`docs/developer-guide.md`](docs/developer-guide.md) is for working on
the stack itself rather than with it, and `cargo doc --open` is authoritative
for signatures.

## Setup

**The package and the library have different names.** The dependency is
`rs-iec61850`; every `use` says `iec61850`.

```toml
[dependencies]
rs-iec61850 = { path = "../rs-iec61850" }   # not on crates.io: path or git
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust
use iec61850::client::Client;
```

- Rust 1.82 or newer, edition 2021.
- Features: `tls` (IEC 62351-3 over rustls, default MMS-over-TLS port 3782),
  `tui` (builds the `iedx` terminal client). Neither is on by default.
- MMS works on Linux, Windows and macOS. GOOSE and SV raw sockets are Linux
  only (AF_PACKET, needs `CAP_NET_RAW`); use `ethernet::pipe()` elsewhere.
- The licence is source-available and non-commercial. Do not add it to a
  product without checking [LICENSE](LICENSE).

## The one thing to understand first

Everything is addressed by an **object reference plus a functional
constraint**. The reference is `"LD/LN.DO.DA"` where `LD` is the full MMS
domain (IED name plus logical-device instance). The same object exposes
different data under different constraints, so the `Fc` is not decoration: the
wrong one is an access error, not a fallback.

```rust
use iec61850::model::Fc;

client.read("ied1LD0/GGIO1.AnIn1.mag.f", Fc::Mx).await?;   // measurand
client.read("ied1LD0/GGIO1.Ind1.stVal", Fc::St).await?;    // status
client.write("ied1LD0/GGIO1.SPCSO1.ctlModel", Fc::Cf, Value::int32(1)).await?;
```

Common constraints: `St` status, `Mx` measurands, `Co` control, `Sp`/`Sg`/`Se`
setpoints and setting groups, `Cf` configuration, `Dc` description, `Rp`/`Br`
report control, `Lg` logs. `Fc::All` is a lookup wildcard only.

Most APIs take `impl Into<ObjectReference>`, so `&str` works directly. Use
`ObjectReference::parse` for untrusted input; `new` skips validation.

## Client recipes

```rust
use iec61850::client::{Client, Options};

let client = Client::dial("192.168.10.5:102").await?;
let client = Client::dial_with(addr, Options::new()
    .with_timeout(Duration::from_secs(5))
    .with_password("secret")).await?;   // ACSE authentication
```

`Client` is safe for concurrent use; several tasks may issue requests at once.
`client.closed().await` resolves when the association ends, which is how a
supervisor reconnects without polling.

**Discovering the model.** `client.retrieve_model().await?` returns the whole
typed tree from the device, no SCL needed. For one level at a time use
`logical_devices`, `logical_nodes`, `browse(ld, &[])` or
`logical_node_directory(ln, AcsiClass::Urcb)`.

**Reading several values.** `read_values(fc, &refs)` is one request and needs
all references in one logical device. `read_many(fc, &refs)` issues them
concurrently, may span devices, and returns one `Result` per reference so a
single failure does not lose the rest.

**Reporting.** Configure the block, then subscribe:

```rust
use iec61850::model::{OptFlds, TrgOps};

let mut rcb = client.get_rcb("ied1LD0/LLN0.RP.EventsRCB01").await?;
rcb.opt_flds = OptFlds::DEFAULT;
rcb.trg_ops = TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE | TrgOps::GI;

let subscription = client.enable_reporting(&rcb, |report| {
    for e in &report.entries {
        println!("{} ({}) = {}", e.reference, e.reason, e.value);
    }
}).await?;

client.trigger_gi(&rcb).await?;    // fills the cache before the live stream
subscription.disable().await?;
```

Buffered blocks resume gap-free: set `rcb.resync_entry_id = Some(last_seen)`
from a previous `Report::entry_id` before enabling. If the server has discarded
that point it flushes the buffer and sets `buf_ovfl`, which is the only signal
that entries were lost.

**Control.** Never hand-roll the select/operate sequence. `control_for` reads
`ctlModel` and `operate` runs whichever sequence it calls for, carrying one
control number throughout:

```rust
use iec61850::client::ControlOptions;
use iec61850::model::OrCat;

let control = client.control_for("ied1LD0/GGIO1.SPCSO1").await?;
control.operate(Value::boolean(true), &ControlOptions::new()
    .with_originator(OrCat::StationControl, "scada-1")
    .with_interlock_check(true)).await?;
```

A refusal arrives as `client::Error::Control(e)` carrying the device's own
diagnosis in `e.stage` and `e.add_cause`; report those rather than a generic
failure.

Datasets, setting groups, file transfer and log queries follow the same shape;
see [`docs/api.md`](docs/api.md). `client.mms()` is the escape hatch to the raw
MMS connection for anything the ACSI layer does not wrap.

## Server recipes

```rust
use iec61850::scl;
use iec61850::server::{Identity, Options, Server};

let model = scl::load_model("ied.cid", &scl::BuildOptions::new().for_ied("IED1"))?;
let server = Server::new(model, Options::new()
    .with_identity(Identity { vendor: "ACME".into(), model: "GW".into(), revision: "1.0".into() })
    .with_file_store("/var/comtrade")
    .with_setting_groups(4));

server.on_connection(|ev| println!("{} from {:?} ({} open)", ev.state, ev.peer, ev.open));

server.on_control("IED1LD0/GGIO1.SPCSO1", |ctx| {
    if interlocked() {
        return AddCause::BLOCKED_BY_INTERLOCKING;
    }
    AddCause::NONE           // accept; stVal is set for you
});

server.on_write(|da, _value| {
    if da.name == "ctlModel" { return Err(iec61850::server::ERR_ACCESS_DENIED) }
    Ok(())
});

server.listen_and_serve("0.0.0.0:102").await?;
```

The process side pushes values through `update`, which applies the batch
atomically with respect to client reads and fires any report whose dataset the
batch touched:

```rust
server.update(|tx| {
    tx.set_float32("IED1LD0/GGIO1.AnIn1.mag.f", 230.4);
    tx.set_quality("IED1LD0/GGIO1.AnIn1.q", Fc::Mx, Quality::GOOD);
    tx.set_timestamp_now("IED1LD0/GGIO1.AnIn1.t", Fc::Mx);
});
```

`Server` is cheap to clone and every handle shares one server, so spawn the
process loop with a clone and serve on the original.

In a control handler, `ctx.origin` and `ctx.or_ident` are what the client
*claims*; `ctx.peer` and `ctx.conn` are what the server observed. An audit
trail wants the latter.

**Without SCL**, build the model by hand: `Model`, `LogicalDevice`,
`LogicalNode` and `DataObject` are plain structs implementing `Default`, and
`model::new_data_object(name, Cdc::Spc, &CdcOptions::new())` materialises any
of the 25 common data classes with the right attributes and constraints.

## Process bus

```rust
let eth: Arc<dyn ethernet::Interface> =
    ethernet::open("eth0", &[ethernet::ETHER_TYPE_GOOSE])?.into();

let subscription = goose::Subscriber::new(eth).subscribe(
    goose::Filter::app_id(0x1000),
    |m| { /* m.st_num, m.sq_num, m.values, m.anomalies */ },
);
```

Publishers run their own retransmission schedule in the background: each
`publish` increments `stNum`, resets `sqNum` and supersedes the previous
schedule, so a stale frame never follows a new state onto the wire. `m.anomalies`
(`st_num_regressed`, `sq_num_gap`, `stale`) is how a lost frame or a restarted
publisher becomes visible; a clean stream reports none.

Sampled Values has a generic path (`sv::Subscriber::subscribe`, raw `Asdu`) and
a 9-2LE fast path (`subscribe_le`, `LePublisher`). In the LE subscriber the
sample buffer is reused between calls, so copy anything you keep.

## Traps that cause real bugs

- **Subscriptions live only as long as their handle.** Dropping the value
  returned by `enable_reporting`, `subscribe` or `subscribe_le` cancels the
  subscription. Bind it, do not `let _ =` it.
- **Report and GOOSE callbacks must not block.** A report callback runs on the
  connection's reader task; blocking there stalls every other response on that
  association. Post to a channel and do the work elsewhere.
- **Do not call `Server::read` inside `update`.** The update already holds the
  model lock and `read` takes it again. Use `Tx::get` inside the callback.
- **Value accessors are lenient by design.** `as_f64` on a boolean yields zero
  rather than failing, because reports mix types freely. Check `type_of()` when
  the type matters, and check `value.as_access_error()` on entries inside a
  multi-value read: a per-element failure arrives inline, not as an `Err`.
- **Reports carry no block identity beyond `RptID`.** Two blocks configured
  with the same `RptID` (which the standard permits, and the reference simpleIO
  model does) cannot be told apart by a subscriber.
- **`intg_pd` is always written to the server**, because zero means "no
  integrity period" and so cannot also mean "leave it alone". `opt_flds` and
  `trg_ops` are written only when non-zero.
- **A control-block reference keeps its constraint** (`ied1LD0/LLN0.RP.urcb01`)
  and goes straight to `get_rcb`. A data object does not; there the constraint
  is a separate argument.
- **Filestore directory listings vary between servers.** This crate marks
  directories with a trailing `/`; some servers omit it, and some report names
  relative to the directory asked for rather than openable as given.
- **GOOSE and SV need `CAP_NET_RAW`** and are Linux only. `ethernet::open`
  returns `Error::Unsupported` elsewhere.

## Testing an application

Prefer these in order: they get faster and more deterministic as you go up.

**In-process, no sockets.** Join a client and server with a duplex stream, the
pattern `tests/acsi_loopback.rs` uses:

```rust
use iec61850::mms::BoxTransport;

let srv = Server::new(model, server::Options::new());
let (client_side, server_side) = tokio::io::duplex(256 * 1024);
let serving = srv.clone();
tokio::spawn(async move { serving.serve_stream(Box::new(server_side) as BoxTransport, None).await });
let client = Client::from_stream(Box::new(client_side) as BoxTransport,
                                 iec61850::client::Options::new()).await?;
```

`ethernet::pipe()` does the same for GOOSE and SV: two connected in-memory
interfaces, no NIC and no privileges.

**Against the bundled server**, which serves the model in `testdata` with
simulated live data:

```sh
cargo run --bin ied-server -- --scl testdata/simpleIO_direct_control.cid --addr :10102
cargo run --bin ied-client -- --addr 127.0.0.1:10102 test    # 27-check sweep
cargo run --features tui --bin iedx -- 127.0.0.1:10102       # interactive
```

`ied-server` also takes `--files DIR`, `--setting-groups N` and `--ied NAME`.
`iedx` is the fastest way to see what a device actually exposes before writing
code against it.

**Against other stacks.** `interop/run.sh` drives this crate's client and
server against reference implementations in both directions. Use it before
claiming interoperability.

## Before calling the work done

```sh
cargo test                                  # and --features tui if iedx is touched
cargo clippy --all-targets                  # expected to be clean
```

Then run the thing against `ied-server` and read the output. Protocol code
compiles and passes unit tests while still putting the wrong bytes on the wire;
a live round trip is what settles it.
