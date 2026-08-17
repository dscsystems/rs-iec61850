# rs-iec61850

A pure-Rust implementation of the IEC 61850 protocol family:

- **MMS client and server** (IEC 61850-8-1 over TPKT/COTP/Session/Presentation/ACSE)
- **GOOSE** publisher and subscriber (raw Ethernet, Linux AF_PACKET)
- **Sampled Values** (IEC 61850-9-2 / 9-2LE) publisher and subscriber
- **SCL** (ICD/CID/SCD) parsing and runtime model instantiation

No C bindings, no `unsafe` outside the AF_PACKET socket calls, async on tokio.
Source-available under a non-commercial licence; see [LICENSE](LICENSE).

## Quick start

Run the test server and drive it with the bundled client:

```sh
cargo run --bin ied-server -- --scl testdata/simpleIO_direct_control.cid --addr :10102
cargo run --bin ied-client -- --addr 127.0.0.1:10102 test
```

`ied-client test` exercises every feature the server exposes and prints a
PASS/FAIL/SKIP report. Against the bundled server it reports 27 passing checks.

Read a value programmatically:

```rust
use iec61850::{client::Client, model::Fc};

let client = Client::dial("192.168.10.5:102").await?;
let value = client
    .read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx)
    .await?;
```

Serve a model:

```rust
use iec61850::{scl, server::{Server, Options}};

let model = scl::load_model("substation.cid", &scl::BuildOptions::new())?;
let server = Server::new(model, Options::new());

// The process side pushes values atomically; reports fire from the same batch.
server.update(|tx| {
    tx.set_float32("IED1LD0/GGIO1.AnIn1.mag.f", 230.4);
    tx.set_timestamp_now("IED1LD0/GGIO1.AnIn1.t", Fc::Mx);
});

server.listen_and_serve("0.0.0.0:102").await?;
```

## Modules

| Module | Purpose |
|---|---|
| `client` | High-level ACSI client: browse, read/write, datasets, reporting, control, files, logs |
| `server` | High-level ACSI server driven by an SCL or programmatic model |
| `goose`, `sv` | GOOSE and Sampled Values publish/subscribe over `ethernet` |
| `scl` | SCL parsing and model instantiation |
| `model` | The IEC 61850 object model, functional constraints, `Quality`/`Timestamp`, the 7-3 common data classes |
| `mms` | Low-level MMS (ISO 9506) values, codecs, and the client and server connections |
| `ethernet` | Raw layer-2 access, AF_PACKET and an in-memory `pipe()` |
| `asn1` | The minimal BER runtime every codec is built on |

## Documentation

- [SKILL.md](SKILL.md) — a task-oriented guide for building applications on the
  crate, written for AI coding agents: recipes, the traps that cause real bugs,
  and how to test against a live server
- [docs/api.md](docs/api.md) — an example for every part of the public API
- [docs/developer-guide.md](docs/developer-guide.md) — architecture, and the
  protocol details that bite when adding a service
- [examples/](examples) — `read`, `browse`, `report_monitor`, `control`,
  `server`, `goose_subscribe`
- [interop/](interop) — the bidirectional interoperability harness

## Tools

| Binary | What it does |
|---|---|
| `ied-server` | Serves an SCL model with simulated live data, controls and optional file services |
| `ied-client` | Browse, read, write, control, subscribe, and the `test` conformance sweep |
| `goose-sniff` | Prints every GOOSE message on an interface, with sequence anomalies |
| `iedx` | Terminal UI: the whole client in one screen, behind the `tui` feature |

```sh
cargo run --features tui --bin iedx -- 127.0.0.1:10102
```

`iedx` opens on a tab per service — Browse, Reports, Datasets, Controls,
SetGroups, Files, Logs — switched with `tab` or `1`-`7`. The tree reads and
writes values (`r`, `w`), operates controls behind a confirmation (`o`),
enables reporting with a general interrogation (`e`), downloads files (`d`)
and queries logs. With no address on the command line it opens a connect
form. `?` lists the keys; the mouse works for tabs, rows and the wheel.

## Interoperability

`interop/run.sh` runs this crate's client and server against an independent
implementation in both directions, plus the reference against itself as a
control:

```sh
GO_IEC61850=/path/to/go-iec61850 interop/run.sh
```

The control run is what makes the result readable: a failure the reference
also has against its own server is reported as `KNOWN` and does not fail the
harness, because it is a property of the reference rather than a defect here.

Current status against `go-iec61850`:

```
PASS   rust client -> rust server   27 passed, 0 failed, 2 skipped
PASS   rust client -> go server     27 passed, 0 failed, 2 skipped
KNOWN  go client   -> rust server   (File directory)
KNOWN  go client   -> go server     (File directory)
```

The `File directory` failure is the reference client reading the first
directory listing entry without checking whether it is a directory; it fails
identically against its own server. This crate's server marks directories with
a trailing `/`, which the reference server omits, and answers an attempt to
open one with `object-access-unsupported` rather than `object-non-existent`, so
a client can tell the two mistakes apart.

A peer that is not present is skipped, so the harness stays useful without a Go
toolchain.

## Status

Implemented: MMS client/server, browse, read/write, datasets (configured and
dynamic), reporting (URCB and buffered BRCB with EntryID resync, general
interrogation, integrity and data-change), control (all four models:
direct/SBO, normal/enhanced), setting groups, file services (directory and
streamed read), log queries, GOOSE and SV publish/subscribe, SCL parsing, and
TLS transport behind the `tls` feature.

The API may change before 1.0.

GOOSE and SV raw-socket transport is Linux-only (AF_PACKET, needs
`CAP_NET_RAW`); everything else builds on Linux, Windows and macOS. Use
`ethernet::pipe()` to exercise the process-bus protocols without a NIC.

Not yet implemented: report segmentation, and GOOSE/SV capture backends for
non-Linux platforms. The `iedx` terminal UI connects in the clear only; a TLS
session needs a trust configuration it has no way to ask for, so use the
library API for that.

## Testing

```sh
cargo test                          # unit, codec and in-process end-to-end tests
cargo test --features tui           # and the terminal UI
cargo clippy --all-targets --features tui
interop/run.sh                      # against an independent implementation
```

The suite covers the codecs by round trip, the protocol layers against
captured bytes from real devices, and the client against the server in-process
over a duplex stream. The `simpleIO_direct_control.cid` model in `testdata` is
loaded and served in the tests, so the model, the name list and every type
specification are checked against a real configuration file.

## Licence

Copyright © 2026 Ricardo Olsen / DSC Systems.

Source-available and free for non-commercial use. Commercial use requires a
separate licence; see [LICENSE](LICENSE) for the terms and
<https://www.linkedin.com/in/ricardo-olsen/> to obtain one.

This is an independent implementation of the publicly documented protocol. It
contains no code copied or mechanically translated from any other IEC 61850
implementation, and no normative text from the IEC standards.
