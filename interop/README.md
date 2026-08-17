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
