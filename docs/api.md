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
[`iec62351`](#iec62351-tls-profile) builds that configuration under the
profile.

A server that accepts only the IEC 61850 ACSE application context, rather than
the MMS one most expect, is reached with
`Options::with_application_context(mms::ApplicationContext::Acsi)`.

### Connection lifecycle

```rust
client.state();       // Connected, Closing, Closed
client.closed().await;                  // resolves when the association ends
client.err();                           // the cause, once it has
client.close().await?;
```

`closed()` replaces polling with a wait, so a supervisor can reconnect the
moment an IED drops the association.

`client.abort().await?` ends the association with an ACSE A-ABORT instead of
releasing it; requests still outstanding fail with `mms::Error::Aborted`.
`client.server_status(extended).await?` is the MMS Status service: the VMD's
logical and physical state (`mms::logical`, `mms::physical`).

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

Only the triggers in `TrgOps` produce reports, so ask for the ones you want: a
block configured with the integrity period alone reports no data changes.

A buffered block resumes gap-free after a disconnect: set
`rcb.resync_entry_id = Some(last_seen)` (from `Report::entry_id`) before
enabling. If the server has discarded that point, it flushes the whole buffer
and sets `buf_ovfl` so you know entries were lost.

Each subscription filters on its own `RptID` (`Rcb::report_id`: the block's
reference when its `RptID` is empty, as the server substitutes it). A report
carries no other identification, so blocks configured with the same `RptID`,
which the standard permits and the reference `simpleIO` model does, cannot be
told apart.

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

On an enhanced-security model `operate` returns once the CommandTermination
arrives, failing with stage `termination` and its cause if the termination is
negative; `ControlOptions::with_termination_timeout` bounds the wait (30 s by
default). A refusal's `add_cause` is the LastApplError the server reported
ahead of the negative response; `Client::last_appl_error` returns the most
recent one, for control structures written directly.

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

Writing to the server's file store: SetFile, which IEC 61850-8-1 maps to MMS
obtainFile (the server reads the file back from this client), DeleteFile and
fileRename. A server refuses a SetFile or rename onto a name that exists.

```rust
client.set_file("COMTRADE/rec002.cfg", data).await?;
client.set_file_from("/tmp/rec002.dat", "COMTRADE/rec002.dat").await?;
client.rename_file("COMTRADE/rec002.cfg", "COMTRADE/old.cfg").await?;
client.delete_file("COMTRADE/old.cfg").await?;
```

A refusal is a file-class service error, `err.as_service_error()`: 7
file-non-existent, 8 duplicate-filename, 6 access-denied.

### Logs

```rust
let entries = client
    .query_log_by_time("ied1LD0/LLN0.LG.EventLog", an_hour_ago, now)
    .await?;
let more = client
    .query_log_after("ied1LD0/LLN0.LG.EventLog", t, &last_entry_id)
    .await?;
```

The log's state, and clearing it (MMS ReportJournalStatus and
InitializeJournal); a server allows the latter only when configured to:

```rust
let st = client.log_status("ied1LD0/LLN0.EventLog").await?;   // st.current_entries, st.deletable
let removed = client.clear_log("ied1LD0/LLN0.EventLog", None, &[]).await?;   // all of them
let removed = client.clear_log("ied1LD0/LLN0.EventLog", Some(until), &entry_id).await?;
```

### Sampled-value control blocks

```rust
let cb = client.get_svcb("MU01LD0/LLN0.msvcb01").await?;   // MSVCB or USVCB, told by FC
println!("{} {} {} {:?}", cb.sv_id, cb.smp_rate, cb.smp_mod, cb.dst_address);

// A unicast block is reserved first, then enabled; the server releases and
// disables it when this association ends.
client.reserve_usvcb("MU01LD0/LLN0.usvcb01", true).await?;
client.enable_svcb("MU01LD0/LLN0.usvcb01", true, true).await?;
```

### Clock quality

The operate timestamp `T` states how far the client's clock can be trusted.
Until told otherwise it is `TimeQuality::DEFAULT` (leap seconds known, accuracy
10 bits); a client that knows better says so, for all commands or one:

```rust
client.set_time_quality(TimeQuality(TimeQuality::CLOCK_NOT_SYNCHRONIZED.0 | 3));
co.operate(Value::boolean(true), &ControlOptions::default().with_time_quality(TimeQuality::accuracy(20))).await?;
```

A Cancel carries the operate's fields except `Check`, as IEC 61850-7-2 defines
it.

### Errors

`client::Error::as_access_error()` and `as_service_error()` return the data
access error or the confirmed error the server answered with, whichever layer
it came through.

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
read and write through the ordinary variable path.

The server answers the MMS Initiate with the services it actually implements
and negotiates the parameter CBB down to what both ends support. Every response
is bounded by the association's negotiated PDU size: name lists, directory
listings and file reads are paged to fit, reports are segmented, and a response
that still cannot fit is refused with a resource error.

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

Clients may write SP, SV and SE by default, and SE only while a setting group
is being edited. CF, DC and BL are writable in IEC 61850-7-2 but change
configuration, descriptions and blocking, so a server opts in to them. ST, MX,
OR, EX and SG are never writable, whatever is listed.

```rust
let server = Server::new(model, Options::new().with_writable_fcs(&[Fc::Sp, Fc::Sv, Fc::Se, Fc::Cf]));
```

A value is stored only when it has the attribute's type, bit-string width and,
for a sized integer, range; anything else is refused as type-inconsistent.
Report and setting-group control blocks follow their own rules, checked before
anything is stored. The hook then sees every write the policy admitted:

```rust
server.on_write(|da, _value| {
    if da.name == "ctlModel" {
        return Err(iec61850::server::ERR_ACCESS_DENIED);
    }
    Ok(())                       // allow; the value is then applied
});
```

A client write and an operate report like a process change: a member of an
enabled block's dataset is reported for the triggers its attribute raised.

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

A refused command is answered negatively and, ahead of that answer, with a
LastApplError report naming the cause (IEC 61850-8-1). A status-only object
refuses control, SBOw is accepted only for SBO with enhanced security, and the
members of a control structure are not writable on their own. A selection lasts
the object's `sboTimeout`.

An enhanced-security operate is concluded by a CommandTermination, sent after
the operate's response. The server sends it as soon as the handler accepts,
unless the handler takes it over to report the outcome of a longer execution:

```rust
server.on_control("IED1LD0/XCBR1.Pos", |ctx| {
    let done = ctx.defer_termination();
    tokio::spawn(async move {
        let reached = drive_breaker().await;
        done(if reached { AddCause::NONE } else { AddCause::BLOCKED_BY_PROCESS });
    });
    AddCause::NONE               // accepted; terminated when `done` is called
});
```

If `done` is not called within the object's `operTimeout`, the server
terminates the operate negatively with time-limit-over.

Report control blocks follow IEC 61850-7-2 clause 17: the first client to write
a block reserves it, settings are locked while it is enabled, only the triggers
in `TrgOps` produce reports (with their own reason codes), `BufTm` collects
events into one report, and a buffered block delivers each entry once.

### Connection events

```rust
server.on_connection(|ev| {
    println!("{} from {:?} ({} open)", ev.state, ev.peer, ev.open);
});
```

Opened, Closed and Refused are all reported; a connection refused for exceeding
`max_connections` is dropped at the transport, before any association.

`server.abort(conn).await` ends an association abruptly, by the id its events
carry.

### Authentication

```rust
let server = Server::new(model, Options::new().with_password("s3cret"));

// Or decide per association: the password, the peer, the ACSE titles, and the
// certificate chain of a TLS connection.
let server = Server::new(model, Options::new().with_authenticator(|req| {
    if allowed(req.peer, &req.peer_certificates) { Ok(()) } else { Err(mms::Error::AuthenticationRequired) }
}));
```

A refused association is answered with an ACSE rejection the client can read:
authentication-failure for a wrong password, authentication-required for none.

### Status

`server.set_status(logical, physical)` sets what the MMS Status service reports
(`mms::logical`, `mms::physical`).

### Files

`with_file_store(dir)` serves `dir` for reading and for SetFile (obtainFile),
DeleteFile and fileRename, which are advertised only then;
`with_read_only_file_store(dir)` serves it for reading only. Names are confined
to the store, symbolic links included, and nothing is ever overwritten.

### Logs

The log control blocks of the model (SCL `LogControl`) are served with their
IEC 61850-8-1 components, and each logs its dataset's changes, with reasons,
into the journal it names (`LogRef`). Clients query the journals with
ReadJournal (paged with moreFollows to the negotiated PDU size), read their
state with ReportJournalStatus and, given `with_deletable_logs()`, clear them
with InitializeJournal. A journal keeps `with_log_capacity(n)` entries
(`DEFAULT_LOG_CAPACITY`, 1024), dropping the oldest. A client enables and
configures a block through `LogEna`, `DatSet`, `TrgOps` and `IntgPd`, the
configuration only while logging is off.

### Service tracking

When the model has an LTRK node (IEC 61850-7-4 Ed2.1), the server records each
tracked service in it: controls in the tracking object of their CDC
(`SpcTrk`, `DpcTrk`, ...), report, log, GOOSE and sampled-value control block
writes in `BrcbTrk`, `UrcbTrk`, `LocbTrk`, `GocbTrk`, `MsvcbTrk`, `UsvcbTrk`,
and setting group selection in `SgcbTrk`, each with the service, its outcome
(`ServiceErrorCode`) and the parameters. A data set over them reports each
service as it happens. The values agree with libiec61850's for the same
services (`interop/libiec.sh`).

### Sampled-value control blocks

The model's `SampledValueControl`s are served as MSVCB (FC MS) and USVCB (FC
US). Clients write `SvEna`, and reserve a USVCB with `Resv`; the rest is
configuration. The server does not publish the samples: it tells the
application, which runs a publisher (`sv::LePublisher::from_model`) while the
block is enabled:

```rust
server.on_sv_control(|ev| {
    println!("{}/{}.{} enabled={} reserved={} by {:?}", ev.device, ev.node, ev.block.name,
             ev.enabled, ev.reserved, ev.conn);
});
```

GOOSE control blocks are served too (FC GO, or GS for GSSE), read-only.

### Clock quality

Every timestamp the server sets (`set_timestamp_now`, `LActTm`, log entries)
carries the quality of its clock: `with_time_quality(q)` at construction,
`server.set_time_quality(q)` when synchronisation is lost or regained.

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

All 52 classes of IEC 61850-7-3 Ed2.1 are covered, the Edition 2 and 2.1
additions (HST, BAC, ORG, TSG, CUG, VSG, CSG, the service tracking classes)
included. Optional attributes appear only when asked for, and an
`AnalogueValue` carries exactly one of `i` or `f` — never both.

Logical nodes are built from the IEC 61850-7-4 tables, and a model can be
checked against them:

```rust
use iec61850::model::{new_logical_node, LnOptions};

let ltrk = new_logical_node("", "LTRK", "1", &LnOptions::new().with_objects(["SpcTrk", "UrcbTrk"]));
for d in model.check_ln_classes() {
    eprintln!("{}: {}", d.path, d.message);
}
```

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

The loader reads Edition 1, 2 and 2.1 documents (`doc.edition()`: 2003, 2007A,
2007B, 2007B4). What it cannot place — an unknown CDC or functional
constraint, a value of the wrong type — is kept where it can be and reported in
`model.diagnostics`; `BuildOptions::strict(true)` turns those into an error,
and `on_warn` sees each as it happens. Setting groups (`Val@sGroup`), array
instances, ClientLN reservations of report blocks, and the GSE/SMV
addressing, `smvOpts` and log targets of the control blocks reach the model.

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

Anomalies (`st_num_regressed`, `sq_num_gap`, `stale`, `entries_mismatch`) come
from per-control-block sequence tracking and are what turn a lost frame or a
restarted publisher into something visible. `SequenceTracker` is public if you
want the rules without the socket.

`stale` is only noticed when the next message arrives. A subscriber has to
treat a control block's data as invalid as soon as `timeAllowedToLive` passes
(IEC 61850-8-1), which `subscribe_supervised` reports as it happens, once per
silence:

```rust
let subscription = goose::Subscriber::new(eth).subscribe_supervised(
    goose::Filter::app_id(0x1000),
    |m| { /* ... */ },
    |go_cb_ref| eprintln!("{go_cb_ref}: publisher silent, data invalid"),
);
```

Use `ethernet::pipe()` for an in-memory segment in tests.

`publish` announces a state change; `refresh` repeats the current state
without one (stNum unchanged, the timestamp of the change it repeats). stNum
starts at 1 and skips 0 on wrap, as sqNum does. `set_test` and `set_nds_com`
take effect from the next publish or refresh, and `PublisherConfig::time_quality`
states the clock's quality. A message that does not fit an Ethernet frame is
refused with `Error::FrameTooLarge`, and the state being advertised carries on.

A publisher can be built from a model's control block, taking its addressing,
VLAN, identity and the retransmission schedule its MinTime and MaxTime ask for
(`retrans_from_scl`):

```rust
let publisher = goose::Publisher::from_model(eth, &ld, &lln0, &ld_lln0_gcb01, src_mac)?;
```

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

The ASDU carries the Edition 2 `smp_mod` and the Amendment 1 `gm_identity` when
set. A publisher emits only the optional fields `LeConfig::opts` asks for
(`AsduOpts`: smpRate, refrTm, datSet, smpMod, gmIdentity), with smpRate in the
unit smpMod names, sends `no_asdu` samples per frame, and can be built from a
model's control block:

```rust
let publisher = sv::LePublisher::from_model(eth, &ld, &lln0, &msvcb, src_mac, 50)?;
publisher.set_gm_identity(ptp_grandmaster);
```

`LeSample::quality(i)` reads the 13-bit quality from the 9-2LE quality word as
IEC 61850-9-2:2011 lays it out (invalid is 0x0002, as Wireshark and
libiec61850 read it); 0x0001, invalid under the first 9-2LE guideline, still
reads as invalid.

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

## rsession (R-GOOSE, R-SV)

The IEC 61850-90-5 session protocol carries GOOSE and SV over UDP, signed
(HMAC-SHA256 or -SHA3) or encrypted (AES-GCM) under keys named in each SPDU. A
`Session` is an `ethernet::Interface`, so the publishers and subscribers above
run over it unchanged:

```rust
use iec61850::rsession::{Config, Key, KeyStore, SecAlgorithm, Session};

let keys = Arc::new(KeyStore::with_keys([Key {
    id: 1,
    material: key_bytes,
    sec: SecAlgorithm::AES_128_GCM,
    ..Default::default()
}])?);
let session: Arc<dyn ethernet::Interface> = Arc::new(Session::open(Config {
    remote: "239.192.0.1:102".into(),      // or listen / groups to receive
    keys: Some(keys),
    ..Default::default()
})?);
let publisher = goose::Publisher::from_model(session, &ld, &lln0, &gcb, [0; 6])?;
```

A receiver refuses an SPDU it cannot verify, an unsecured one unless
`allow_unsecured`, and a replay (a window per sender and key); each refusal is
counted in `stats()` and reported to `on_reject`. A key change is: add the new
key everywhere, make it active at the publisher, remove the old one; or let
[`gdoi`](#gdoi-key-distribution) do it. `marshal` and `unmarshal` are the codec
on their own.

---

## iec62351 (TLS profile)

Behind the `tls` feature: rustls configurations under IEC 62351-3.

```rust
use iec61850::iec62351::{self, Options};

let cfg = iec62351::client_config(Options {
    certificates: vec![my_cert],
    key: Some(my_key),
    roots: vec![ca],
    crls: vec![crl_der],
    server_name: "ied1".into(),         // SAN, or the CN of a certificate without SANs
    ..Default::default()
})?;
let client = Client::dial_with("ied1:3782", client::Options::new().with_tls(cfg)).await?;

let cfg = iec62351::server_config(Options { /* the same, without server_name */ ..options })?;
let server = Server::new(model, server::Options::new().with_tls(cfg));
```

Both ends authenticate; TLS 1.2 or 1.3 with ECDHE and AES-GCM only; keys
weaker than 2048-bit RSA or P-256 refused anywhere in the chain; revocation
from the CRLs, a CRL past its next update failing closed unless
`allow_stale_crl`; `allowed_peers` pins peers; no session resumption. X.509 v1
certificates, which many IEDs carry, are accepted when a configured root issued
them directly. `on_event` hears of every refused peer.

---

## gdoi (key distribution)

Behind the `gdoi` feature: IEC 62351-9 group key management (GDOI, RFC 6407,
with the IEC 61850 payloads of RFC 8052) over IKEv1 main mode, authenticated by
certificates (RSA, ECDSA P-256/P-384) or a pre-shared key.

```rust
use iec61850::gdoi::*;

// The key server.
let group = Arc::new(Group::new());
group.add(Tek::new(stream_oid.clone(), Vec::new(), AuthAlg::NONE, EncAlg::AES_GCM_128, Duration::from_secs(86400))?)?;
let ks = Server::new(ServerConfig {
    credentials,
    authorize: Some(Arc::new(|member: &Peer, _: &GroupId| member.common_name.is_some())),
    ..Default::default()
})?;
ks.add_group(GroupId::oid(stream_oid.clone()), group.clone());
tokio::spawn(async move { ks.listen_and_serve("0.0.0.0:848").await });

// A member keeping a session's key store current.
let keys = Arc::new(rsession::KeyStore::new());
let member = Member::new(MemberConfig {
    server: "ks.substation:848".into(),
    credentials,
    authorize_server: Some(Arc::new(|ks: &Peer| ok_if_ours(ks))),
    ..Default::default()
}, GroupId::oid(stream_oid), keys.clone());
tokio::spawn(async move { member.run(std::future::pending()).await });
```

A rotation adds the next TEK with an `activation_delay` longer than the
members' `refresh`, then removes the old one; members install each key when it
activates, send with the newest, and drop keys that expire or are withdrawn.
`register` runs one registration on its own.

---

## Runnable examples

See [`examples/`](../examples): `read`, `browse`, `report_monitor`, `control`,
`server`, `goose_subscribe`.

```sh
cargo run --example read -- 127.0.0.1:10102 simpleIOGenericIO/GGIO1.AnIn1.mag.f MX
```
