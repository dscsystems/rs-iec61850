#!/usr/bin/env bash
# Exercise the bundled tools over TLS and ACSE certificate authentication.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$ROOT"
cargo build --features tls --bin ied-server --bin ied-client --quiet
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out "$WORK/ca.pem" \
  -subj /CN=cli-test-ca -days 1 >/dev/null 2>&1
for role in server client; do
  openssl req -newkey rsa:2048 -nodes -keyout "$WORK/$role.key" -out "$WORK/$role.csr" \
    -subj "/CN=$role" >/dev/null 2>&1
  echo 'subjectAltName=IP:127.0.0.1' > "$WORK/ext"
  openssl x509 -req -in "$WORK/$role.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
    -CAcreateserial -out "$WORK/$role.pem" -days 1 -extfile "$WORK/ext" >/dev/null 2>&1
done
start_server() {
  target/debug/ied-server --addr 127.0.0.1:0 --quiet "$@" > "$WORK/server.log" 2>&1 &
  PID=$!
  for ((i=0; i<100; i++)); do
    if rg -q 'listening' "$WORK/server.log"; then break; fi
    if ! kill -0 "$PID" 2>/dev/null; then cat "$WORK/server.log"; exit 1; fi
    sleep 0.05
  done
  ADDR="$(sed -n 's/.*listening on \([^ ]*\).*/\1/p' "$WORK/server.log" | tail -1)"
  if [[ -z "$ADDR" || "$ADDR" == *:0 ]]; then cat "$WORK/server.log"; exit 1; fi
}
stop_server() {
  kill "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  PID=""
}
start_server --tls-cert "$WORK/server.pem" --tls-key "$WORK/server.key" --tls-ca "$WORK/ca.pem"
target/debug/ied-client --addr "$ADDR" --tls-cert "$WORK/client.pem" --tls-key "$WORK/client.key" --tls-ca "$WORK/ca.pem" read simpleIOGenericIO/GGIO1.AnIn1.mag.f MX
if target/debug/ied-client --addr "$ADDR" --tls-cert "$WORK/client.pem" --tls-key "$WORK/client.key" --tls-ca "$WORK/ca.pem" --tls-server-name wrong-name identify > "$WORK/wrong.log" 2>&1; then
  echo 'FAIL: mismatched TLS name accepted'; exit 1
fi
stop_server
start_server --mms-cert "$WORK/server.pem" --mms-key "$WORK/server.key" --mms-ca "$WORK/ca.pem" --mms-without-tls
target/debug/ied-client --addr "$ADDR" --mms-cert "$WORK/client.pem" --mms-key "$WORK/client.key" --mms-ca "$WORK/ca.pem" --mms-without-tls read simpleIOGenericIO/GGIO1.AnIn1.mag.f MX
if target/debug/ied-client --addr "$ADDR" identify > "$WORK/plain.log" 2>&1; then
  echo 'FAIL: required A-profile accepted a plain client'; exit 1
fi
stop_server
echo 'PASS: tool TLS, server naming, A-profile and required authentication'
