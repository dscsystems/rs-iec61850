# Interoperability testing

Interop is the primary correctness oracle for a protocol implementation. A
round-trip test only proves this crate agrees with itself; talking to an
independent implementation is what proves the bytes on the wire are right.

`run.sh` drives four directions, skipping the ones whose peer is not present:

| # | Direction | What it proves |
|---|---|---|
| 1 | rust client → rust server | The baseline: the whole feature set works |
| 2 | rust client → go server | Our encoder against an independent decoder |
| 3 | go client → rust server | An independent encoder against our decoder |
| 4 | go client → go server | **Control**: the reference against itself |

Direction 4 is what makes the results interpretable. Without a control run, a
failure in direction 3 is ambiguous: it could be our decoder, their encoder, or
a bug in their test client. With one, a failure that also occurs
reference-against-reference is attributable to the reference, and the harness
reports it as `KNOWN` rather than failing.

## Running it

```sh
# Just the baseline.
interop/run.sh

# With go-iec61850 (needs a Go toolchain).
GO_IEC61850=/path/to/go-iec61850 interop/run.sh
```

Options: `BASE_PORT` (default 10401) moves the port range, `SCL` selects a
different model.

The harness exits non-zero only when a direction fails that the reference
control run does not.

## What it exercises

The `ied-client test` sweep covers association and identify, the name lists,
online model retrieval, functionally-constrained reads and writes, batch
reads, configured and dynamic datasets, reporting (get, enable, general
interrogation, disable) for both unbuffered and buffered control blocks,
control (model discovery, `ctlVal` type, operate, and that `stVal` follows),
setting groups, file directory and streamed file read, and log queries.

Each step reports PASS, FAIL or SKIP. A feature the peer does not implement is
a SKIP: no device implements everything, and a sweep that failed on absent
optional services would drown the ones that matter.

## Building the peer

```sh
git clone https://github.com/dscsystems/go-iec61850
GO_IEC61850=$PWD/go-iec61850 interop/run.sh
```

## Known reference behaviour

**File directory listings.** The reference Go client reads the first entry of
a filestore listing without checking whether it is a directory, so it fails
against any server whose filestore has a subdirectory first, including its
own. The harness reports this as `KNOWN`.

The two servers also differ in how they name entries:

| | This crate | go-iec61850 |
|---|---|---|
| Directory marker | trailing `/` | none |
| Entry name | path-prefixed, openable as reported | bare name, needs rejoining |
| Opening a directory | `object-access-unsupported` | `object-non-existent` |

This crate marks directories and reports openable names, which is the more
useful of the two conventions: marking directories is what lets a client skip
them, and reporting names that are openable as given is what lets a client act
on a listing without reconstructing paths. Our client copes with either
convention: it tries candidates until one opens, rather than committing to the
first entry.

## Hygiene

Two failure modes made earlier versions of this harness lie, and both are
guarded against now:

- **Orphaned servers.** `kill $!` reaches only the subshell that started the
  server, leaving it holding its port and still answering. A later run then
  binds nothing and silently reports results for a stale process whose
  filestore has since been deleted. Servers now run under `setsid` and record
  their own process-group id, and the whole group is killed.
- **Busy ports.** If a port is already in use the harness refuses to run that
  direction rather than testing whatever is listening.

If a direction reports `SKIP (port N busy)`, something from an earlier run is
still alive:

```sh
pkill -f 'target/debug/ied-server'
```

## libiec61850 (`libiec.sh`)

`tests/interop_libiec.rs` runs this crate against libiec61850, the C
implementation most IEDs and test tools build on. Every test is gated on an
environment variable naming the C program it drives, so `cargo test` without
them skips the lot; `libiec.sh` supplies them. The C side (libiec61850 1.6,
plain, with mbedtls 3.6 for R-GOOSE/R-SV and TLS, and with MMS fileRename
compiled in, plus the `mms_peer` and `rsession_peer` drivers) is built by the
go-iec61850 harness, whose cache this reuses:

```sh
GO_IEC61850=/path/to/go-iec61850 interop/libiec.sh
```

| Test | Direction | What it checks |
|---|---|---|
| `client_against_libiec_basic_io` | client → C server | Identify, name lists, read, type specs, model retrieval, data sets, reporting with GI |
| `client_controls_against_libiec` | client → C server | direct- and SBO-enhanced operate with CommandTermination, LastApplError on a refused operate, CommandTermination− |
| `client_logs_against_libiec` | client → C server | log and LCB browsing, ReadJournal by time and after an entry, the LCB's nine components |
| `client_files_against_libiec`, `client_rename_against_libiec` | client → C server | Status, SetFile (obtainFile), GetFile, DeleteFile and its refusal, fileRename, abort |
| `libiec_client_example1` | C client → server | association, read, data set, reports |
| `libiec_log_client` | C client → server | log listing, enabling the LCB, journal query with values and reason codes |
| `libiec_mms_utility_ed2_classes` | C client → server | the Edition 2/2.1 classes of `ed21_diverse.cid` in the directory and read |
| `libiec_mms_peer_services` | C client → server | password authentication and refusal, Status, SetFile, fileRename, directory, DeleteFile, release, abort |
| `libiec_mms_peer_svcb` | C client → server | ClientSVControlBlock: MSVCB/USVCB, reservation, exclusivity, release on departure |
| `rsession_interop::*` | both ways | R-GOOSE and R-SV, unsecured, HMAC-SHA256-128/256 and AES-128/256-GCM |
| `tls_interop::*` | both ways | MMS over TLS under the IEC 62351-3 profile, port 3782 |
| `port102_svcb_against_libiec_9_2le` | client → C server | the 9-2LE example's block read, reserved, enabled, and its stream received |
| `port102_ltrk_against_libiec` | both servers | the same services against libiec61850's service tracking server and this one: LTRK values and tracking reports compared |

The two `port102_*` tests need port 102 and a raw socket; the script runs them
in an unprivileged user and network namespace (`unshare -rn`), on its loopback.

libiec61850's own HMAC-SHA256-256 SPDUs carry a length octet of 16 before a
32-octet MAC, which no receiver can parse, so that mode is tested towards it
only. Its example TLS certificates are X.509 v1; the profile accepts those when
a configured root issued them, as libiec61850 and Go do.

## go-iec61850 security layers (`go-security.sh`)

`tests/interop_go.rs` checks R-GOOSE/R-SV in every key mode both ways, GDOI
registrations (pre-shared key and certificates) of each implementation's member
with the other's key server, and MMS over TLS both ways. The Go side is
`interop/go/peer`, a small program over go-iec61850 whose R-GOOSE/R-SV modes
share the command line of libiec61850's `rsession_peer`, so the same Rust
driver runs against both.

```sh
GO_IEC61850=/path/to/go-iec61850 interop/go-security.sh
```

## mms-interop adapter images (`mms-interop.sh`)

`tests/interop_mms_interop.rs` runs this crate against the Docker adapter
images of [otfabric/mms-interop](https://github.com/otfabric/mms-interop):
libiec61850, iec61850bean, dscsystems/go-iec61850 and csp0924/iec61850-rust,
each packaged as one program per role, reading one shared fixture and
reporting in JSON Lines. The fixture is vendored in `testdata/mms-interop/`.
The tests are skipped unless `MMS_INTEROP_STACKS` names the stacks to run, and
the script sets it to `all`:

```sh
interop/mms-interop.sh                                  # every stack
MMS_INTEROP_STACKS=dscsystems interop/mms-interop.sh    # one stack
LIBIEC61850_IMAGE=mms-interop-libiec61850:local interop/mms-interop.sh
```

The images default to the digests mms-interop v0.4.0 published, and the
variables that override them are the ones the Go suites use. Containers run
on the host network, so no ports are mapped. Each test removes its containers
by name; the script also clears any left behind by an interrupted run.

| Test (per stack) | Direction | What it checks |
|---|---|---|
| `client_ied_services` | client → `ied-server` | Identify, server/LD directory, every value of `values.json`, a setting write read back, the dataset's values and directory |
| `client_reports` | client → `ied-server` | `urcb01` and `brcb01`: RptID, enable, a GI report with both members, disable |
| `client_controls` | client → `ied-server` | SPCSO1 direct, SPCSO2 SBO, SPCSO3 SBO-enhanced, and `stVal` follows each |
| `client_mms_services` | MMS client → `mms-server` | Identify, Status, domain and variable name lists, every fixture type read, scalar writes read back, a structure's type description (not iec61850bean, which has no MMS server) |
| `server_ied_client` | `ied-client` → server | the adapter's fixed browse, read, write and dataset sequence |
| `server_controller` | `ied-controller` → server | each control model, then `stVal` read back by the adapter and on the server |
| `server_reporter` | `ied-reporter` → server | `urcb01` read and enabled, a data-change report received, disabled |

The client adapters were written against go-iec61850, which names a logical
device by its `inst` alone and gives a report control block exactly its
configured name. The server direction therefore serves the fixture with the
IED name blanked, so the device is `InteropLD`, and with the report blocks
marked `indexed="false"`, so the block is `urcb01` and not the `urcb0101` that
IEC 61850-6 gives an indexed block (libiec61850's own server uses the latter).

Two of the adapters' steps fail against this server on purpose: the
`ied-client` writes `LLN0.Mod.stVal` and the `ied-reporter` writes
`GGIO1.SPS1.stVal`, both under ST. IEC 61850-7-2 makes status read-only, so
the server refuses both, as iec61850-rust's does. The test asserts that
refusal, and for the reporter it changes the value on the process side, as a
device would.

Limitations of the peers are listed in `known()` in the test, with the
reason for each. A step that hits one is logged as `known:` and skipped
rather than failed:

| Stack | Limitation |
|---|---|
| libiec61850, iec61850bean | the server does not apply `DPS1.stVal` and `TotVAh.actVal` from `values.json` (mms-interop lists this too); the value's type is still checked |
| iec61850bean | the server cannot decode an Identify request and does not answer it |
| iec61850bean | the server reads a dataset only when `specificationWithResult` is set; the test reads it that way instead |
| iec61850bean | the server refuses SelectWithValue on SBOw (mms-interop lists this too) |
| iec61850bean, iec61850-rust | the server accepts RptEna and GI on `brcb01` and never sends a report |
