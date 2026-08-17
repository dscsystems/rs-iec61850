# Developer's guide

For people working **on** rs-iec61850: extending the stack, fixing protocol
bugs, adding services. For using the library see [api.md](api.md).

## Architecture

The stack is layered strictly, dependencies pointing downward only:

```text
client   server            <- ACSI: object references, FCs, reports, control
   \       /
    v     v
      mms                   <- ISO 9506 values, PDUs, Conn/ServerConn
       |
      osi                   <- acse -> presentation -> session -> cotp -> tpkt
       |
     asn1                   <- BER runtime (tag/length/value)

goose  sv  -> ethernet + asn1 + mms(values)   <- process bus, independent of MMS
scl        -> model                            <- configuration -> runtime model
model      -> mms(values)                      <- object model + 7-3 data types
```

Rules:

- `asn1` has no internal dependencies; `model` imports only `mms` for `Value`.
- Nothing depends on `src/bin/` or `examples/`.
- `osi` is an implementation detail of `mms`, exported only for tooling.
- The GOOSE/SV side never touches the MMS/OSI stack. It shares only the BER
  runtime and the `mms::Value` model.

### Why these boundaries

MMS needs a full OSI upper stack (TPKT/COTP/Session/Presentation/ACSE); that
complexity is quarantined under `osi` so `mms` reads as a clean ISO 9506
implementation. GOOSE and SV are layer 2 and share nothing with MMS except
value encoding, so they live in sibling modules over a small raw-Ethernet
abstraction.

## Async design

The MMS layer is async on tokio. The layer-2 side is not: a raw socket read is
a blocking syscall, and parking a runtime worker on it would stall every other
task sharing that worker, so GOOSE and SV subscribers run on their own threads.

`cotp::Conn` splits into independent reading and writing halves after the
handshake, which is what lets a client demultiplex responses on a reader task
while other tasks issue requests. The class-0 state that matters afterwards is
only the negotiated TPDU size, which the writer alone needs.

The server holds its model behind a `std::sync::RwLock`. Nothing awaits while
that lock is held; the report engine's send path is `try_send` onto a bounded
queue drained by a per-association writer task, so pushing a report never
blocks the process side.

## The BER runtime (`asn1`)

Everything is TLV. Two encoding styles:

- **Builders** (`Element`, `cons`/`prim`/`int_elem`/…) for control-plane PDUs,
  where clarity beats allocation counts. `raw_content(tag, bytes)` wraps
  pre-encoded octets as an element's body; `raw_tlv(bytes)` splices a complete
  pre-encoded element in as a child. These let one layer embed another's
  already-encoded PDU without re-parsing it — an ACSE APDU inside a
  presentation single-ASN1-type, say.
- **Append helpers** (`append_tag`, `append_length`, `append_int`, …) for the
  GOOSE and SV hot paths.

Decoding is via `Decoder`: `read_tlv`, `expect(tag)`, `optional(tag)`, `peek`,
`more`, `skip`. It borrows from the input rather than copying, is
bounds-checked and depth-limited, and must never panic on hostile input.

Context tags: `context_primitive(n)`, `context_constructed(n)`,
`application_constructed(n)`. High tag numbers (≥ 31, such as the MMS file
services at [72]) are handled automatically.

## Protocol details that bite

These are the things most likely to trip up a new service. Several were found
by interop testing.

- **`variableAccessSpecification` tagging is asymmetric.** In `ReadRequest` it
  is `[1] EXPLICIT`; in `WriteRequest` it is untagged, so the CHOICE tags show
  through. See `mms/services.rs`.
- **`GetVariableAccessAttributes-Response` puts the type specification at
  `[2] EXPLICIT`** (with an optional `address` at `[1]`), not at `[1]`. Reading
  `[1]` finds the address and every model retrieval fails.
- **Floating-point type specifications are a constructed SEQUENCE of two
  INTEGERs** (format width, exponent width) — unlike float *values*, which are
  the primitive MMS FloatingPoint octet string. See `mms/typespec.rs`.
- **`identify` is a primitive `[2] NULL`** (`0x82`), not a constructed element.
- **Confirmed responses carry the invokeID as a universal INTEGER, but
  ConfirmedErrorPDU and RejectPDU carry it context-tagged `[0]`.**
  `split_invoke` accepts either; accepting only one loses every error reply.
- **ISO session GIVE-TOKENS and DATA-TRANSFER share SI `0x01`** and cannot be
  told apart by value, so the data-phase prefix is stripped by count.
- **A CPA is not a CP with a different name.** ISO 8823 gives its normal-mode
  parameters their own tags: the responder states one
  responding-presentation-selector `[3]`, and there is no place for the calling
  `[1]` or called `[2]` selectors a CP carries. The result list has one entry
  per proposed context, matched by position.
- **`smpCnt` in a sampled-value ASDU is a two-octet OCTET STRING, not an
  INTEGER.** Encoded as an integer, a count of 7 is one octet and a subscriber
  expecting two reads the wrong sample number.
- **The report `OptFlds` value is echoed as the report's second field** and
  tells the client which optional fields follow. A bit set there without its
  field shifts every value after it, so the flags must describe the report as
  built, not as requested. `effective_opt_flds` reduces them.
- **`Dbpos` transmits its two bits most-significant first**, unlike `Quality`
  and the other bit strings, so a uniform mapping swaps "on" and "off".
- **An SCL enum literal is a name, not an ordinal.** Resolving it needs the
  declaring `type` attribute, which `DataAttribute::enum_type` carries.

When adding a service, the reliable method is: read the observable wire
behaviour of a reference stack, encode to match, then verify against a live
peer with `interop/run.sh`. **Never copy code** — see [licensing](#licensing).

## Reporting engine (`server`)

Report control blocks are **materialised into the model** at construction
(`server/rcb.rs`): each SCL `ReportControl` becomes a `DataObject` under `RP`
or `BR` with the standard attributes, so they read and write through the normal
path. Indexed instances (`Name01`…`NameNN`) follow IEC 61850-6.

The engine (`server/reporting.rs`) reacts to writes of `RptEna`, `GI`,
`EntryID` and `PurgeBuf`, and to update transactions. An update records the set
of changed references; afterwards the engine emits data-change reports for
enabled blocks whose dataset intersects that set. `member_changed` matches in
both directions, since a dataset member may name any level of the tree — a
member naming a data object is touched by a change to any attribute below it,
and the trailing separator keeps `Pos` from matching `PosSomething`.

Buffered blocks also buffer every event (a ring with a monotonic EntryID) so
they can be flushed on a later enable, honouring a resync EntryID. A resync
point the buffer has discarded raises `BufOvfl`, which is how the client learns
it lost entries.

The wire format is the IEC 61850-8-1 layout: a `variableListName` of `"RPT"`
plus a flat `listOfAccessResult` whose fields are driven by the `OptFlds` bit
string. The decoder (`client/report.rs`) walks the same layout, driven by the
flags present in the report itself.

## Control (`server`)

Writes to `…$CO$…$Oper`, `$SBOw` and `$Cancel`, and reads of `…$SBO`, are
intercepted in the handler and routed to `server/control.rs` and
`server/select.rs`. SBO models require a reservation, held per connection with
a 30 s timeout; enhanced models send a positive CommandTermination as an
unconfirmed InformationReport after the operate.

One control sequence carries one control number throughout. A server that
compares the operate's `ctlNum` against the select's rejects a mismatch as
inconsistent-parameters, so `Selections` checks both the owning connection and
the number.

## Adding a new MMS service

1. Add the confirmed-service CHOICE tag as a constant in `mms/pdu.rs` (client)
   and/or `server/handler.rs` (server).
2. Client: add a method on `mms::Conn` that builds the request element and
   calls `call_inner`, then decodes the response after
   `dec.expect(context_constructed(tag))`.
3. Server: add an arm to `Handler::handle` returning the response element, or
   an error (`mms::ServiceError` / `mms::DataAccessError`).
4. Add the high-level wrapper in `client`/`server` mapping object references
   and constraints to MMS names via `ObjectReference::to_mms`.
5. Add a codec round-trip test, and an end-to-end test in
   `tests/acsi_loopback.rs`.
6. Add an assertion to the `ied-client test` sweep so interop covers it.

## Testing

- `cargo test` runs everything with no external dependencies: unit and codec
  tests, plus `tests/mms_loopback.rs` and `tests/acsi_loopback.rs`, which drive
  a real client against a real server over an in-memory duplex stream.
- The terminal UI is behind a feature, so its tests only run with it on:
  `cargo test --features tui`.
- `cargo clippy --all-targets --features tui` is expected to be clean.
- **Interop is the primary correctness oracle.** `interop/run.sh` runs both
  directions against an independent implementation, plus the reference against
  itself as a control. See [interop/README.md](../interop/README.md).

Layer-2 codecs are tested over `ethernet::pipe()`, an in-memory segment, so no
NIC is needed. Network-facing decoders are tested against truncated and
bit-flipped input to confirm they fail rather than panic.

The `testdata/simpleIO_direct_control.cid` model is loaded and served by the
tests, so the SCL loader, the name list and every type specification are
exercised against a real configuration rather than a hand-written fixture.

## Concurrency model

- **Client**: one reader task demultiplexes responses by invoke ID to
  per-call oneshot channels, and routes unconfirmed InformationReports to the
  registered handlers. `Conn` is safe for concurrent use.
- **Server**: one task per association. The model is guarded by an `RwLock`;
  `update` is the only writer entry point and holds the write lock for the
  whole batch, so a client never sees a half-applied change.
- **GOOSE publisher**: a task owns the retransmission state machine. A
  generation counter makes a superseded task stop rather than interleave.
- **Subscribers**: a dedicated thread per subscription, because the read is a
  blocking syscall.
- Callbacks (reports, GOOSE/SV subscribers) run on an internal task or thread
  and **must not block**.

## Platform notes

- Pure Rust. The only `unsafe` is the AF_PACKET socket calls in
  `ethernet/afpacket.rs`, each with a safety comment.
- GOOSE and SV raw sockets are Linux-only. Other platforms return
  `ethernet::Error::Unsupported`; a capture backend is the intended extension
  point.
- TLS (IEC 62351-3) is behind the `tls` feature, on rustls.

## Releases

A release is a tag. `.github/workflows/release.yml` runs the suite, builds the
four binaries for every target in its matrix, and attaches the archives and
their `SHA256SUMS.txt` to a GitHub release of the same name.

```sh
# The tag has to agree with Cargo.toml, or the workflow stops before building.
cargo test --features tui
git tag -a v0.2.0 -m 'v0.2.0'
git push origin v0.2.0
```

Points worth knowing before changing it:

- **The matrix is a table, one line per target.** Targets under `required` must
  build or no release is published; those marked `optional: true` are allowed
  to fail and simply contribute no archive, so a tier-2 architecture cannot
  hold up a release.
- **Release binaries are built with `tui` and without `tls`.** None of the
  tools speaks TLS, and rustls would pull in aws-lc-rs, whose C build needs a
  working cross toolchain for every target in the matrix. Leaving it off keeps
  the build pure Rust, which is what makes cross-compiling to a dozen targets a
  matter of naming a linker.
- **Cross-compiling uses the Ubuntu cross gcc packages**, not a container. Each
  one needs its `libc6-dev-<arch>-cross` named alongside it: that package is
  only a *Recommends* of the compiler, so with `--no-install-recommends` the
  crate compiles and then fails to link for want of `crt1.o`.
- **musl targets have no cross gcc in the archive**, so they link with rustc's
  bundled `rust-lld` against the self-contained startup objects that ship with
  the target's std.
- **The 32-bit targets are the ones that catch portability bugs.** `libc`
  widths differ there (`timeval` is the usual offender), and a host-only clippy
  run will not see it, so armv7 is in the required set deliberately.
- A manual run (`workflow_dispatch`) rebuilds an existing tag; with `dry_run`
  it builds everything and publishes nothing, which is how to test a change to
  the workflow without spending a tag.

## Code style

British English in comments; no em-dashes. Doc comments on every public item,
in complete sentences, saying what the thing is for rather than restating its
name. Comments explain why, not what. Test names are sentences describing the
property under test.

## Licensing

The crate is source-available and non-commercial; see [LICENSE](../LICENSE).

**Never copy or mechanically translate code** from other IEC 61850
implementations, whatever their licence. They may be run as interop peers and
read to understand *observable protocol behaviour* only. IEC standard text must
not be reproduced beyond short factual references.

## Repository map

| Path | Contents |
|---|---|
| `src/asn1/` | BER runtime |
| `src/osi/` | TPKT, COTP, session, presentation, ACSE |
| `src/mms/` | MMS values, PDUs, client `Conn`, `ServerConn` |
| `src/model/` | Object model, FCs, Quality/Timestamp, control enums, CDCs |
| `src/scl/` | SCL parser and model instantiation |
| `src/client/` | ACSI client |
| `src/server/` | ACSI server (reporting, control, setting groups, files) |
| `src/ethernet/` | Raw layer 2, AF_PACKET and `pipe` |
| `src/goose/`, `src/sv/` | Process-bus publish/subscribe |
| `src/bin/` | `ied-server`, `ied-client`, `goose-sniff`, `iedx` (the `tui` feature) |
| `examples/` | Runnable snippets |
| `interop/` | Bidirectional interop harness |
| `testdata/` | SCL files and fixtures |
| `.github/workflows/` | `release.yml`: tag-driven binary builds and the GitHub release |
| `SKILL.md` | Guide for building applications on the crate; its code is compile-checked by `tests/skill_snippets.rs`, so keep the two in step |
