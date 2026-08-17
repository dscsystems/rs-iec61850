#!/usr/bin/env bash
#
# Bidirectional interoperability harness.
#
# It runs this crate's client and server against an independent
# implementation in both directions, so a change to the wire format shows up
# as a difference between two runs rather than as a support call:
#
#   1. rust client  -> rust server    (baseline: the whole feature set)
#   2. rust client  -> go server      (our encoder against their decoder)
#   3. go client    -> rust server    (their encoder against our decoder)
#   4. go client    -> go server      (control: the reference against itself)
#
# Direction 4 is what makes the result interpretable: a failure that also
# happens in the reference-against-itself run is a property of the reference,
# not a defect here.
#
# A peer that is not present is skipped, so this stays useful without a Go
# toolchain.
#
# Usage:
#   interop/run.sh                       # everything available
#   GO_IEC61850=/path/to/go-iec61850 interop/run.sh

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCL="${SCL:-testdata/simpleIO_direct_control.cid}"
WORK="$(mktemp -d)"
FILESTORE="$WORK/filestore"
BASE_PORT="${BASE_PORT:-10401}"

# A nested filestore, which is what a COMTRADE store looks like, plus a file
# in the root so a client that does not descend still has something to read.
mkdir -p "$FILESTORE/COMTRADE"
printf 'station,1,2024\n' > "$FILESTORE/COMTRADE/rec001.cfg"
head -c 20000 /dev/urandom > "$FILESTORE/COMTRADE/rec001.dat" 2>/dev/null
printf 'readme\n' > "$FILESTORE/readme.txt"

PASSED=0
FAILED=0
SKIPPED=0
declare -a SUMMARY
# Maps a direction to the steps its client reported as failing, so a failure
# can be compared against the reference-against-itself control run.
declare -A FAILING_STEPS

# Stops a server and everything it spawned.
#
# The server runs under setsid so it leads its own process group: a bare
# "kill $!" reaches only the subshell eval created, leaving the server orphaned,
# still holding its port and still answering. A later run then binds nothing,
# talks to that stale process, and reports results for a server that no longer
# has the filestore it was given, which is worse than no harness at all.
stop_server() {
  local pid="$1" pgidfile="${2:-}"
  # setsid forks, so $! is not the new session leader; the group records its
  # own id from inside instead. Killing the group is what reaches the server,
  # which is a child of the shell setsid started.
  if [ -n "$pgidfile" ] && [ -s "$pgidfile" ]; then
    kill -- "-$(cat "$pgidfile")" 2>/dev/null
  fi
  [ -n "$pid" ] && kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
}

cleanup() {
  local i=0
  for pid in "${PIDS[@]:-}"; do
    stop_server "$pid" "${PGIDS[$i]:-}"
    i=$((i + 1))
  done
  rm -rf "$WORK"
}
PIDS=()
PGIDS=()
trap cleanup EXIT

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# Reports whether anything is already listening on a port.
port_in_use() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3<&- 3>&-; return 0; }
  return 1
}

# Waits for a listener to come up, so a slow start is not a failure.
wait_for_port() {
  local port="$1" tries=50
  while [ $tries -gt 0 ]; do
    port_in_use "$port" && return 0
    sleep 0.1
    tries=$((tries - 1))
  done
  return 1
}

# Waits for a port to be released, so the next direction can bind it.
wait_port_free() {
  local port="$1" tries=30
  while [ $tries -gt 0 ]; do
    port_in_use "$port" || return 0
    sleep 0.1
    tries=$((tries - 1))
  done
  return 1
}

# run_case NAME SERVER_CMD CLIENT_CMD PORT
run_case() {
  local name="$1" server_cmd="$2" client_cmd="$3" port="$4"
  say "== $name =="

  # A busy port means some earlier server is still running. Binding would
  # fail and the client would talk to that one instead, so refuse rather than
  # report a result for a process this run did not start.
  if port_in_use "$port"; then
    echo "  port $port is already in use; refusing to test an unknown server"
    SKIPPED=$((SKIPPED + 1))
    SUMMARY+=("SKIP  $name (port $port busy)")
    return
  fi

  local pgidfile="$WORK/$port.pgid"
  rm -f "$pgidfile"
  setsid bash -c "echo \$\$ > '$pgidfile'; $server_cmd" \
    > "$WORK/$port.server.log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  PGIDS+=("$pgidfile")

  if ! wait_for_port "$port"; then
    echo "  server did not start; log:"
    sed 's/^/    /' "$WORK/$port.server.log" | head -20
    SKIPPED=$((SKIPPED + 1))
    SUMMARY+=("SKIP  $name (server did not start)")
    stop_server "$pid" "$pgidfile"
    return
  fi

  eval "$client_cmd" 2>&1 | tee "$WORK/$port.client.log"
  local rc=${PIPESTATUS[0]}

  stop_server "$pid" "$pgidfile"
  wait_port_free "$port"

  # Record which steps failed, for the reference comparison in the report.
  # Both clients print one failing step per line; take the step name from it.
  FAILING_STEPS["$name"]="$(
    grep -E 'FAIL' "$WORK/$port.client.log" |
      sed -E 's/.*FAIL[[:space:]]+//; s/[[:space:]]{2,}.*//' |
      sort -u | tr '\n' ','
  )"

  local tail
  tail="$(grep -iE '^(Summary:|[0-9]+ passed)' "$WORK/$port.client.log" | tail -1)"
  if [ $rc -eq 0 ]; then
    PASSED=$((PASSED + 1))
    SUMMARY+=("PASS  $name  ${tail:-}")
  else
    FAILED=$((FAILED + 1))
    SUMMARY+=("FAIL  $name  ${tail:-}")
  fi
}

# --- build our own tools -----------------------------------------------------

say "building rs-iec61850"
cargo build --bins --quiet || { echo "build failed"; exit 1; }
RS_SERVER="$ROOT/target/debug/ied-server"
RS_CLIENT="$ROOT/target/debug/ied-client"

# --- locate the reference implementation -------------------------------------

GO_SERVER=""
GO_CLIENT=""
GO_SRC="${GO_IEC61850:-}"
if [ -n "$GO_SRC" ] && [ -d "$GO_SRC" ] && command -v go >/dev/null 2>&1; then
  say "building go-iec61850 from $GO_SRC"
  if (cd "$GO_SRC" && go build -o "$WORK/go-ied-server" ./cmd/ied-server &&
      go build -o "$WORK/go-ied-client" ./cmd/ied-client); then
    GO_SERVER="$WORK/go-ied-server"
    GO_CLIENT="$WORK/go-ied-client"
  else
    echo "  go build failed; skipping the Go directions"
  fi
fi

# --- 1. rust -> rust (the baseline) ------------------------------------------

P=$BASE_PORT
run_case "rust client -> rust server" \
  "$RS_SERVER --scl $SCL --addr :$P --files $FILESTORE --quiet" \
  "$RS_CLIENT --addr 127.0.0.1:$P test" \
  "$P"

# --- 2. rust client -> go server ---------------------------------------------

if [ -n "$GO_SERVER" ]; then
  P=$((BASE_PORT + 1))
  run_case "rust client -> go server" \
    "cd $GO_SRC && $GO_SERVER -scl testdata/simpleIO_direct_control.cid -addr :$P -files $FILESTORE" \
    "$RS_CLIENT --addr 127.0.0.1:$P test" \
    "$P"
else
  SKIPPED=$((SKIPPED + 1))
  SUMMARY+=("SKIP  rust client -> go server (set GO_IEC61850)")
fi

# --- 3. go client -> rust server ---------------------------------------------

if [ -n "$GO_CLIENT" ]; then
  P=$((BASE_PORT + 2))
  run_case "go client -> rust server" \
    "$RS_SERVER --scl $SCL --addr :$P --files $FILESTORE --quiet" \
    "$GO_CLIENT -addr 127.0.0.1:$P test" \
    "$P"
else
  SKIPPED=$((SKIPPED + 1))
  SUMMARY+=("SKIP  go client -> rust server (set GO_IEC61850)")
fi

# --- 4. go -> go, the control run --------------------------------------------

if [ -n "$GO_CLIENT" ] && [ -n "$GO_SERVER" ]; then
  P=$((BASE_PORT + 3))
  run_case "go client -> go server (reference control)" \
    "cd $GO_SRC && $GO_SERVER -scl testdata/simpleIO_direct_control.cid -addr :$P -files $FILESTORE" \
    "$GO_CLIENT -addr 127.0.0.1:$P test" \
    "$P"
fi

# --- report ------------------------------------------------------------------

# A failure the reference also has against its own server is a property of the
# reference, not a defect here. Reporting those as ours would train everyone to
# ignore the harness, so they are named and set aside instead.
CONTROL="go client -> go server (reference control)"
OURS="go client -> rust server"
KNOWN=""
if [ -n "${FAILING_STEPS[$CONTROL]:-}" ] &&
   [ "${FAILING_STEPS[$OURS]:-}" = "${FAILING_STEPS[$CONTROL]}" ]; then
  KNOWN="${FAILING_STEPS[$CONTROL]%,}"
  for i in "${!SUMMARY[@]}"; do
    case "${SUMMARY[$i]}" in
      FAIL*"$OURS"*|FAIL*"$CONTROL"*)
        SUMMARY[$i]="KNOWN ${SUMMARY[$i]#FAIL }"
        FAILED=$((FAILED - 1))
        ;;
    esac
  done
fi

say "== interop summary =="
for line in "${SUMMARY[@]}"; do
  printf '  %s\n' "$line"
done
if [ -n "$KNOWN" ]; then
  printf '\n  KNOWN: the reference client fails these same steps against its own\n'
  printf '  server, so they are defects in the reference, not in this crate:\n'
  printf '    %s\n' "$KNOWN"
fi
printf '\n  %d directions passed, %d failed, %d skipped\n\n' "$PASSED" "$FAILED" "$SKIPPED"

exit $((FAILED > 0))
