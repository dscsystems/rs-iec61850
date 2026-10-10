#!/usr/bin/env bash
# Runs this crate against libiec61850, both ways (tests/interop_libiec.rs):
#   1. our client against the C basic I/O, control, logging and file servers
#   2. the C client_example1, client_example_log, mms_utility and
#      interop/c/mms_peer.c against our server
#   3. R-GOOSE and R-SV (IEC 61850-90-5) both ways through
#      interop/c/rsession_peer.c, a driver of libiec61850's session layer
#   4. MMS over TLS (IEC 62351-3) both ways through the C TLS examples
#
# The C side is built by the Go library's harness, whose build this reuses:
# point GO_IEC61850 at a go-iec61850 checkout. Its interop/run.sh builds
# libiec61850 (plain, with mbedtls 3.6, and with MMS fileRename) and the two
# peers under $GO_IEC61850/.interop-work; this script runs that build step
# first when the binaries are missing.
#
# Environment:
#   GO_IEC61850  go-iec61850 checkout (default ../go-iec61850)
#   WORK         its build directory (default $GO_IEC61850/.interop-work)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO_IEC61850="${GO_IEC61850:-$ROOT/../go-iec61850}"
WORK="${WORK:-$GO_IEC61850/.interop-work}"
LIB="$WORK/libiec61850"
SEC="$WORK/libiec61850-sec"
RENAME="$WORK/libiec61850-rename"

need=(
  "$LIB/examples/server_example_basic_io/server_example_basic_io"
  "$LIB/examples/server_example_control/server_example_control"
  "$LIB/examples/server_example_logging/server_example_logging"
  "$LIB/examples/server_example_files/server_example_files"
  "$LIB/examples/iec61850_client_example1/client_example1"
  "$LIB/examples/iec61850_client_example_log/client_example_log"
  "$LIB/examples/mms_utility/mms_utility"
  "$RENAME/examples/server_example_files/server_example_files"
  "$SEC/cbuild/examples/tls_server_example/tls_server_example"
  "$SEC/cbuild/examples/tls_client_example/tls_client_example"
  "$WORK/mms_peer"
  "$WORK/rsession_peer"
  "$LIB/examples/iec61850_9_2_LE_example/sv_9_2LE_example"
  "$SEC/cbuild/examples/server_example_service_tracking/server_example_service_tracking"
)
for b in "${need[@]}"; do
  if [ ! -x "$b" ]; then
    echo "== building libiec61850 with the go-iec61850 harness ($b missing) =="
    # The Go harness builds everything, then runs its own suite; only the
    # build is wanted here, and it is done once the peers exist.
    WORK="$WORK" bash "$GO_IEC61850/interop/run.sh" || true
    break
  fi
done
for b in "${need[@]}"; do
  [ -x "$b" ] || { echo "missing $b"; exit 1; }
done

BASIC_PORT="${BASIC_PORT:-10202}"
CTL_PORT="${CTL_PORT:-10203}"
LOG_PORT="${LOG_PORT:-10204}"

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

LOGDIR="$(mktemp -d)"
"$LIB/examples/server_example_basic_io/server_example_basic_io" "$BASIC_PORT" >"$LOGDIR/basic.log" 2>&1 &
PIDS+=($!)
"$LIB/examples/server_example_control/server_example_control" "$CTL_PORT" >"$LOGDIR/ctl.log" 2>&1 &
PIDS+=($!)
# The logging example keeps its log in SQLite in its working directory; a
# fresh database holds exactly the entry it writes at startup.
(cd "$LOGDIR" && exec "$LIB/examples/server_example_logging/server_example_logging" "$LOG_PORT") >"$LOGDIR/log.log" 2>&1 &
PIDS+=($!)
sleep 1

cd "$ROOT"
IEC61850_TEST_SERVER="127.0.0.1:$BASIC_PORT" \
IEC61850_TEST_CONTROL_SERVER="127.0.0.1:$CTL_PORT" \
IEC61850_TEST_LOG_SERVER="127.0.0.1:$LOG_PORT" \
IEC61850_C_FILE_SERVER="$LIB/examples/server_example_files/server_example_files" \
IEC61850_C_RENAME_FILE_SERVER="$RENAME/examples/server_example_files/server_example_files" \
IEC61850_C_FILE_SERVER_STORE="$LIB/examples/server_example_files/vmd-filestore" \
IEC61850_C_CLIENT="$LIB/examples/iec61850_client_example1/client_example1" \
IEC61850_C_LOG_CLIENT="$LIB/examples/iec61850_client_example_log/client_example_log" \
IEC61850_C_MMS_UTILITY="$LIB/examples/mms_utility/mms_utility" \
IEC61850_C_MMS_PEER="$WORK/mms_peer" \
IEC61850_C_RSESSION_PEER="$WORK/rsession_peer" \
IEC61850_C_TLS_SERVER="$SEC/cbuild/examples/tls_server_example/tls_server_example" \
IEC61850_C_TLS_CLIENT="$SEC/cbuild/examples/tls_client_example/tls_client_example" \
IEC61850_C_TLS_CERTS="$SEC/examples" \
  cargo test --features tls --test interop_libiec -- --test-threads=1 --nocapture --skip port102 "$@"

echo
echo "== port 102: SV control blocks and service tracking, in a network namespace =="
# libiec61850's 9-2LE and service tracking examples listen on port 102, and
# the 9-2LE one publishes on a raw socket. Unprivileged, both run in a user
# and network namespace of their own (unshare -rn), with the tests, on its
# loopback; as root they run as they are.
TEST_BIN="$(cargo test --features tls --test interop_libiec --no-run --message-format=json 2>/dev/null |
  sed -n 's/.*"executable":"\([^"]*interop_libiec[^"]*\)".*/\1/p' | tail -1)"
NS_RUN="IEC61850_C_SV_SERVER='$LIB/examples/iec61850_9_2_LE_example/sv_9_2LE_example' \
  IEC61850_C_LTRK_SERVER='$SEC/cbuild/examples/server_example_service_tracking/server_example_service_tracking' \
  IEC61850_C_LTRK_ICD='$SEC/examples/server_example_service_tracking/simpleIO_ltrk_tests.icd' \
  '$TEST_BIN' port102 --test-threads=1 --nocapture"
if [ "$(id -u)" = 0 ]; then
  sh -c "$NS_RUN"
else
  unshare -rn sh -c "ip link set lo up && $NS_RUN"
fi

echo "== libiec61850 interop OK =="
