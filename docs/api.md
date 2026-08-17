# API reference

An example-driven tour of the public API. Every symbol also carries rustdoc;
`cargo doc --open` is the authoritative signature reference.

Contents:

- [Core concepts](#core-concepts) — object references, functional constraints, values
- [`client`](#client) — the ACSI client
- [`server`](#server) — the ACSI server
- [`model`](#model) — the object model and common data types
- [`scl`](#scl) — SCL parsing
- [`mms`](#mms) — the low-level MMS layer
- [`goose`](#goose) — GOOSE publish/subscribe
- [`sv`](#sv) — Sampled Values publish/subscribe
- [`ethernet`](#ethernet) — raw layer-2 access

---

## Core concepts

### Object references

An `ObjectReference` is the string `"LD/LN.DO[.DA...]"`, where `LD` is the full
MMS domain (the IED name plus the logical-device instance).

```rust
use iec61850::model::ObjectReference;

let r = ObjectReference::parse("ied1LD0/GGIO1.AnIn1.mag.f")?;
r.ld();                  // "ied1LD0"
r.ln();                  // "GGIO1"
r.path();                // ["GGIO1", "AnIn1", "mag", "f"]
r.parent();              // Some("ied1LD0/GGIO1.AnIn1.mag")
r.child("q");            // "ied1LD0/GGIO1.AnIn1.mag.q"
```

Most APIs take `impl Into<ObjectReference>`, so a `&str` or `String` works
directly. Use `parse` when the input is untrusted; `new` skips validation.

### Functional constraints

Data attributes are addressed by reference **and** functional constraint
(`Fc`): the same object exposes different views under different constraints.
Common values: `St` (status), `Mx` (measurands), `Co` (control), `Sp`/`Sg`/`Se`
(set points and setting groups), `Cf` (configuration), `Dc` (description),
`Rp`/`Br` (unbuffered and buffered report control). `Fc::All` is a wildcard for
lookups.

```rust
use iec61850::model::Fc;

let fc: Fc = "MX".parse()?;      // case-insensitive
assert_eq!(fc.to_string(), "MX");
```

### Values

`mms::Value` is a tagged union covering every MMS data type.

```rust
use iec61850::mms::{TimeQuality, Value};

Value::boolean(true);
Value::int32(-5);
Value::uint32(230);
Value::float32(230.4);
Value::visible_string("text");
Value::octet_string(vec![1, 2, 3]);
Value::utc_time(std::time::SystemTime::now(), TimeQuality::accuracy(10));
Value::structure(vec![a, b, c]);
Value::array(vec![a, b, c]);

v.type_of();                       // Type
v.as_bool(); v.as_i64(); v.as_i32(); v.as_u64(); v.as_f64(); v.as_f32();
v.text();                          // string content of the string types
v.bytes();                         // raw octets
v.bit(i); v.bit_len();             // bit strings
v.len(); v.index(i); v.children(); // arrays and structures
v.time();                          // UtcTime / BinaryTime -> Option<SystemTime>
v.as_access_error();               // Some(code) for a per-element failure
```

Accessors are lenient: reading the wrong family yields a zero rather than
panicking, because reports and read results mix types freely.

Quality and timestamp helpers live in `model`:

```rust
use iec61850::model::{Quality, Validity};

let q = Quality::GOOD.with_validity(Validity::Questionable) | Quality::OLD_DATA;
q.value();                    // -> mms::Value, a 13-bit bit string
Quality::from_value(&v);      // -> Quality
```

---

## client

The high-level ACSI client. It is safe for concurrent use: several tasks may
issue requests, matched to responses by invoke ID.

### Connecting

```rust
use iec61850::client::{Client, Options};

let client = Client::dial("192.168.10.5:102").await?;

let client = Client::dial_with(
    "192.168.10.5:102",
    Options::new()
        .with_timeout(Duration::from_secs(5))
        .with_password("secret"),        // ACSE authentication
)
.await?;
```

With the `tls` feature, `Options::with_tls` enables IEC 62351-3; the default
MMS-over-TLS port is 3782.

### Connection lifecycle

```rust
client.state();       // Connected, Closing, Closed
client.closed().await;                  // resolves when the association ends
client.err();                           // the cause, once it has
client.close().await?;
```

`closed()` replaces polling with a wait, so a supervisor can reconnect the
moment an IED drops the association.

### Browsing and reading

```rust
use iec61850::client::AcsiClass;
use iec61850::model::Fc;

let devices = client.logical_devices().await?;
let nodes = client.logical_nodes("ied1LD0").await?;
let model = client.retrieve_model().await?;   // full typed tree, no SCL needed

let v = client.read("ied1LD0/GGIO1.AnIn1.mag.f", Fc::Mx).await?;

// One request, several references, all in one logical device.
let vs = client.read_values(Fc::Mx, &refs).await?;

// One request each, concurrently, within the negotiated outstanding limit;
// references may span devices and one failing leaves the others alone.
let results = client.read_many(Fc::Mx, &refs).await;
```

The ACSI directory services are a filter over the MMS name lists:

```rust
// The objects of one class inside a logical node.
client.logical_node_directory("ied1LD0/LLN0", AcsiClass::Urcb).await?;

// Every class in a device, in one pass over the name list.
let entries = client.browse("ied1LD0", &[]).await?;

// One level of the tree below a data object.
client.data_directory("ied1LD0/GGIO1.AnIn1", Fc::Mx).await?;  // ["mag","q","t"]
```

A control-block reference keeps its constraint (`ied1LD0/LLN0.RP.urcb01`) so it
can be passed straight to `get_rcb`; a data object does not, the constraint
being a separate argument there.

### Writing

```rust
client
    .write("ied1LD0/GGIO1.SPCSO1.ctlModel", Fc::Cf, Value::int32(1))
    .await?;
```

### Datasets

```rust
use iec61850::client::DataSetEntry;

let ds = client.read_data_set("ied1LD0/LLN0.Measurements").await?;
for m in &ds.members {
    println!("{} [{}] = {:?}", m.reference, m.fc, m.value);
}

client
    .create_data_set(
        "ied1LD0/LLN0.MyDS",
        &[DataSetEntry::new("ied1LD0/GGIO1.AnIn1", Fc::Mx)],
    )
    .await?;
client.delete_data_set("ied1LD0/LLN0.MyDS").await?;
```

Members are labelled with the references the *server* holds, not with what the
caller assumed.

### Reporting

```rust
use iec61850::model::{OptFlds, TrgOps};

let mut rcb = client.get_rcb("ied1LD0/LLN0.RP.EventsRCB01").await?;  // BR works too
rcb.opt_flds = OptFlds::SEQ_NUM | OptFlds::REASON_CODE | OptFlds::DATA_SET_NAME;
rcb.trg_ops = TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE | TrgOps::GI;
rcb.intg_pd = Duration::from_secs(60);

let sub = client
    .enable_reporting(&rcb, |report| {
        for e in &report.entries {          // decoded per the inclusion bitstring
            println!("{} ({}) = {}", e.reference, e.reason, e.value);
        }
    })
    .await?;

client.trigger_gi(&rcb).await?;             // general interrogation
sub.disable().await?;
```

`opt_flds` and `trg_ops` are written to the server when non-zero; `intg_pd` is
written always, because zero is a meaningful integrity period (none at all) and
so cannot also mean "leave it alone".

A buffered block resumes gap-free after a disconnect: set
`rcb.resync_entry_id = Some(last_seen)` (from `Report::entry_id`) before
enabling. If the server has discarded that point, it flushes the whole buffer
and sets `buf_ovfl` so you know entries were lost.

Each subscription filters on its own `RptID`. A report carries no other
identification, so blocks configured with the same `RptID` — which the standard
permits, and which the reference `simpleIO` model does — cannot be told apart.

**The callback runs on the connection's reader task and must not block.**

### Control

The control model is read from `ctlModel`; `operate` performs the correct
select/operate sequence automatically.

```rust
use iec61850::client::{ControlOptions, ControlError};
use iec61850::model::OrCat;

let control = client.control_for("ied1LD0/GGIO1.SPCSO1").await?;
println!("{}", control.model());        // e.g. sbo-with-enhanced-security

let result = control
    .operate(
        Value::boolean(true),
        &ControlOptions::new()
            .with_originator(OrCat::StationControl, "scada-1")
            .with_interlock_check(true),
    )
    .await;

if let Err(iec61850::client::Error::Control(e)) = result {
    println!("{} failed: {}", e.stage, e.add_cause);   // "operate", "blocked-by-interlocking"
}
```

The lower-level steps are exposed too: `select`, `select_with_value`, `cancel`,
`ctl_val_spec` (what type of `ctlVal` the device will accept), and
`ControlOptions::with_model` to override the model.

One control sequence carries one control number throughout, which
`ControlObject` allocates and reuses; a server that compares the operate's
`ctlNum` against the select's rejects a mismatch as inconsistent-parameters.

### Setting groups

```rust
let mut sg = client.setting_groups("DEMOPROT/LLN0.SP.SGCB").await?;
println!("{} {} {}", sg.num_of_sg, sg.act_sg, sg.edit_sg);

sg.select_active_sg(2).await?;
sg.select_edit_sg(1).await?;
sg.set_edit_value("DEMOPROT/PTOC1.OpDlTmms.setVal", Value::int32(4200)).await?;
sg.confirm_edit().await?;
```

### Files

```rust
let entries = client.file_directory("").await?;       // the filestore root
let data = client.read_file("COMTRADE/rec001.dat").await?;

// Or stream it, for a recording too large to hold in memory.
let mut reader = client.open_file("COMTRADE/rec001.dat").await?;
while let Some(chunk) = reader.next_chunk().await? {
    sink.write_all(&chunk)?;
}
reader.close().await?;
```

Directories are reported with a trailing `/`. Servers vary here: some omit the
marker, and some report names relative to the directory asked for rather than
openable as given.

### Logs

```rust
let entries = client
    .query_log_by_time("ied1LD0/LLN0.LG.EventLog", an_hour_ago, now)
    .await?;
let more = client
    .query_log_after("ied1LD0/LLN0.LG.EventLog", t, &last_entry_id)
    .await?;
```

### Escape hatch

`client.mms()` returns the underlying `mms::Conn` for services the ACSI layer
does not wrap (`identify`, raw `get_name_list`, and anything reached through
`call`).

---

## server

The high-level ACSI server, driven by a `model::Model`.

```rust
use iec61850::server::{Identity, Options, Server};

let model = scl::load_model("substation.cid", &scl::BuildOptions::new().for_ied("IED1"))?;

let server = Server::new(
    model,
    Options::new()
        .with_identity(Identity { vendor: "ACME".into(), model: "GW".into(), revision: "1.0".into() })
        .with_file_store("/var/comtrade")
        .with_setting_groups(4)
        .with_max_connections(16),
);

server.listen_and_serve("0.0.0.0:102").await?;
```

Report control blocks are materialised into the model at construction, so they
read and write through the ordinary variable path. A `LastApplError` object is
materialised into each `LLN0` that lacks one, so a refused control's diagnosis
can always reach a client.

### Pushing values

`update` applies a batch atomically with respect to client reads, and drives
any reports whose dataset includes the changed attributes.

```rust
server.update(|tx| {
    tx.set_float32("IED1LD0/GGIO1.AnIn1.mag.f", 230.4);
    tx.set_quality("IED1LD0/GGIO1.AnIn1.q", Fc::Mx, Quality::GOOD);
    tx.set_timestamp_now("IED1LD0/GGIO1.AnIn1.t", Fc::Mx);
    tx.set_bool("IED1LD0/GGIO1.Ind1.stVal", true);
});

let v = server.read("IED1LD0/GGIO1.AnIn1.mag.f", Fc::Mx);   // local snapshot
```

Use `Tx::get` inside the callback rather than `Server::read`, which would take
a lock the update already holds.

### Write access control

```rust
server.on_write(|da, _value| {
    if da.name == "ctlModel" {
        return Err(iec61850::server::ERR_ACCESS_DENIED);
    }
    Ok(())                       // allow; the value is then applied
});
```

### Control handlers

```rust
use iec61850::model::AddCause;

server.on_control("IED1LD0/GGIO1.SPCSO1", |ctx| {
    if ctx.select { /* the select phase */ }
    println!("{} = {} by {:?} from {:?}", ctx.reference, ctx.value, ctx.or_ident, ctx.peer);
    if interlocked() {
        return AddCause::BLOCKED_BY_INTERLOCKING;
    }
    AddCause::NONE               // accept; stVal is set automatically
});
```

`ctx.origin` and `ctx.or_ident` are what the client *claims*; `ctx.peer` and
`ctx.conn` are what the server observed, which is what an audit trail needs.

Reporting, SBO select reservations and CommandTermination for the enhanced
control models are handled internally.

### Connection events

```rust
server.on_connection(|ev| {
    println!("{} from {:?} ({} open)", ev.state, ev.peer, ev.open);
});
```

Opened, Closed and Refused are all reported; a connection refused for exceeding
`max_connections` is dropped at the transport, before any association.

---

## model

The object model plus the IEC 61850-7-3 common data types.

- `Model` → `LogicalDevice` → `LogicalNode` → `DataObject` → `DataAttribute`
- Lookups: `m.device(name)`, `ld.node(name)`, `ln.object(name)`,
  `m.attribute(ref, fc)`, `m.lookup(ref, fc)`
- `Fc`, `ObjectReference`, `from_mms`
- `Quality`, `Validity`, `Dbpos`, `TrgOps`, `OptFlds`, `ReasonCode` — each with
  `value()` and `from_value()`
- `CtlModel`, `OrCat`, `AddCause` for control

Data objects can be built from their common data class:

```rust
use iec61850::model::{Cdc, CdcOptions, CtlModel, new_data_object};

let spc = new_data_object(
    "SPCSO1",
    Cdc::Spc,
    &CdcOptions::new().with_control_model(CtlModel::SboEnhanced),
);

let mv = new_data_object("AnIn1", Cdc::Mv, &CdcOptions::new().with_optional(["units", "db"]));
```

All 25 classes are covered. Optional attributes appear only when asked for, and
an `AnalogueValue` carries exactly one of `i` or `f` — never both.

---

## scl

```rust
let doc = scl::parse_file("substation.scd")?;         // the typed document

let model = scl::load_model(
    "ied.cid",
    &scl::BuildOptions::new().for_ied("IED1").with_access_point("S1"),
)?;
```

`load_model` and `build_model` expand the DataTypeTemplates into the runtime
model, apply DOI/SDI/DAI initial values (resolving enum literals to their
ordinals), and resolve datasets and control blocks, including the GSE/SMV MAC,
APPID and VLAN from the Communication section.

Elements are matched by local name, so any SCL namespace revision is accepted.

---

## mms

The low-level layer. Most applications only touch `Value` and reach the rest
through `client` and `server`.

```rust
let conn = mms::Conn::dial("host:102", mms::Options::default()).await?;
let (vendor, model, revision) = conn.identify().await?;
let names = conn.get_name_list(mms::ObjectClass::Domain, "").await?;
let values = conn.read("domain", &["LN$MX$AnIn1$mag$f"]).await?;
```

Errors are typed: `mms::ServiceError` (a confirmed error or reject) and
`mms::DataAccessError` (per-item, also returned inline inside read results —
check `value.as_access_error()`).

The server transport primitive is `mms::accept_conn(stream, peer)` with a
`Handler`; `server` builds on it.

---

## goose

Layer-2 GOOSE over an `ethernet::Interface`.

```rust
use std::sync::Arc;
use iec61850::{ethernet, goose};

let eth: Arc<dyn ethernet::Interface> =
    ethernet::open("eth0", &[ethernet::ETHER_TYPE_GOOSE])?.into();

// The retransmission state machine runs in the background.
let publisher = goose::Publisher::new(
    Arc::clone(&eth),
    goose::PublisherConfig {
        dst_mac: goose::default_mac(1),
        app_id: 0x1000,
        go_cb_ref: "IED1LD0/LLN0$GO$gcb01".into(),
        dat_set: "IED1LD0/LLN0$Events".into(),
        go_id: "events".into(),
        conf_rev: 1,
        vlan: Some(ethernet::VlanTag::priority(4)),
        retrans: goose::DEFAULT_RETRANS.to_vec(),
        ..Default::default()
    },
)?;

publisher.publish(vec![Value::boolean(true), Quality::GOOD.value()])?;  // stNum++

let subscription = goose::Subscriber::new(eth).subscribe(
    goose::Filter::app_id(0x1000),
    |m| {
        // m.st_num, m.sq_num, m.values, m.anomalies
    },
);
```

Each `publish` increments `stNum`, restarts the schedule and resets `sqNum`; a
background task retransmits with increasing `sqNum` until the next publish. A
newer publish supersedes the previous retransmissions, so a stale frame never
follows a new state onto the wire.

Anomalies (`st_num_regressed`, `sq_num_gap`, `stale`) come from per-control-block
sequence tracking and are what turn a lost frame or a restarted publisher into
something visible. `SequenceTracker` is public if you want the rules without the
socket.

Use `ethernet::pipe()` for an in-memory segment in tests.

---

## sv

Sampled Values, generic and the 9-2LE fast path.

```rust
use iec61850::sv;

// 80 samples/cycle at 50 Hz = 4000 samples/s.
let publisher = sv::LePublisher::new(
    Arc::clone(&eth),
    sv::LeConfig {
        app_id: 0x4000,
        sv_id: "MU01".into(),
        conf_rev: 1,
        dst_mac: sv::default_mac(1),
        samples_per_cycle: 80,
        nominal_hz: 50,
        ..Default::default()
    },
)?;

publisher
    .run(
        |smp_cnt, out| {
            out.i[0] = current;
            out.v[0] = voltage;
        },
        cancel_future,
    )
    .await?;

// The typed subscriber: the sample is reused between calls, so copy to retain.
let subscription = sv::Subscriber::new(eth).subscribe_le(
    sv::Filter::app_id(0x4000),
    |s| { let _ = (s.smp_cnt, s.i, s.v, s.quality(0)); },
);
```

`subscribe` (rather than `subscribe_le`) delivers generic `sv::Asdu` with the
raw `sample` payload, for datasets that are not 9-2LE.

The sample count wraps once per second, which is what lets a subscriber align
streams within the second.

---

## ethernet

```rust
let eth = ethernet::open("eth0", &[ethernet::ETHER_TYPE_GOOSE, ethernet::ETHER_TYPE_SV])?;
```

Linux AF_PACKET; needs `CAP_NET_RAW` or root. On other platforms `open` returns
`Error::Unsupported`. `ethernet::pipe()` returns two connected in-memory
interfaces for tests and simulation.

`Frame` marshalling is a pure function, so the GOOSE and SV codecs are testable
without a socket.

---

## Runnable examples

See [`examples/`](../examples): `read`, `browse`, `report_monitor`, `control`,
`server`, `goose_subscribe`.

```sh
cargo run --example read -- 127.0.0.1:10102 simpleIOGenericIO/GGIO1.AnIn1.mag.f MX
```
