#!/usr/bin/env bash
# Runs this crate's security layers against go-iec61850's, both ways
# (tests/interop_go.rs): R-GOOSE and R-SV in every key mode, GDOI
# registrations with pre-shared keys and certificates, and MMS over TLS.
# The MMS services are interop/run.sh's.
#
# Environment:
#   GO_IEC61850  go-iec61850 checkout (default ../go-iec61850)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO_IEC61850="$(cd "${GO_IEC61850:-$ROOT/../go-iec61850}" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== building the Go peer against $GO_IEC61850 =="
cp -r "$ROOT/interop/go" "$WORK/go"
(cd "$WORK/go" &&
  go mod edit -replace "github.com/dscsystems/go-iec61850=$GO_IEC61850" &&
  GOFLAGS=-mod=mod go build -o "$WORK/peer" ./peer)

cd "$ROOT"
IEC61850_GO_PEER="$WORK/peer" \
  cargo test --features gdoi --test interop_go -- --test-threads=1 "$@"
echo "== go-iec61850 security interop OK =="
