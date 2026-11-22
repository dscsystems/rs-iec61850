# Go implementation comparison

Reference: the local `go-iec61850` checkout at `a9329db` (10 November 2026).
This is a feature-level comparison, not a claim of IEC conformance or a
complete public-symbol equivalence audit. Rust's existing ACSI, process-bus,
SCL and group-security implementations already cover most of the Go library.

## Implemented in this update

- IEC 62351-4 A-profile (compatibility mode): RSA/SHA-256 signed timestamps,
  certificate path validation, replaceable trust anchors and CRLs, optional
  fail-closed revocation policy, required/optional server authentication,
  legacy mechanism-name tolerance, and peer certificates for authorization.
  One shared verifier protects all associations from replay. Future-dated
  values remain remembered through their entire acceptance window. Invalid
  signatures cannot consume a genuine peer's replay-cache entry.
- PEM/DER A-profile credential loading and `--mms-*` options on `ied-client`
  and `ied-server`; TLS remains required unless explicitly disabled for a lab.
- TLS credentials and trust options on `ied-client`, `ied-server` and `iedx`.
  Client certificate verification binds to the dialled server name by default;
  `--tls-server-name` overrides it and `--tls-no-server-name` explicitly
  disables that check for legacy deployments. Existing applications that
  intentionally checked only a chain must set `Options::no_server_name`.
- Server handshake and PDU write deadlines, responding ACSE identity options,
  and refusal of associations completing after server shutdown. A partial or
  failed PDU write makes the framing unusable instead of allowing later PDUs
  to follow corrupted bytes. Client request sends are bounded too.
- Per-association file handles, a 16-handle allowance, cleanup at association
  end, range checks on file IDs, streaming server reads, and exclusive
  creation of files downloaded by `iedx`.
- Bounded dynamic datasets (256 per server, 1024 members each), name-list,
  directory and journal continuations; malformed MMS requests receive rejects.
- Client reporting reads must establish that the RCB exists. Enabling writes
  `BufTm`, failed configuration releases URCB reservations, and disabling
  releases a URCB so another client can reserve it.
- Control discovery propagates errors other than a missing `ctlModel`;
  control writes check the configured `ctlVal` type before invoking a handler.
- COTP selector roles, class-0 size negotiation and reference checks; bounded
  TSDU reassembly; session Extended User Data for large authentication PDUs;
  the 16-bit TPKT length limit; overflow checks on BER tags and OID arcs;
  normalization of bit-string storage and padding; strict AARE results.
- R-session replay windows use the source IP independently of its UDP port,
  and refuse new senders when replay state is full. GOOSE retries transient
  initial and retransmission failures. GOOSE and SV preserve the simulation
  bit independently of the GOOSE `test` flag. Subscriber state is bounded.
  AF_PACKET receives multicast and VLAN traffic and retains its descriptor
  until in-flight calls can no longer use it.

## Native E2E follow-up

The native integrity-protected E2E stack is now implemented with feature
`e2e`: 2018/2020 codecs and corrections, Annex G identities, RSA/P-256
signatures, DH groups 14/23, HMAC/GMAC transfer, independent rekey epochs,
idle carriers, signed release/abort and OSI/MMS integration. The bundled
clients/server load E2E credentials. `interop/e2e.sh` checks 13 configurations
in each direction against Go. See [the E2E guide](e2e.md) for scope and
verification details. Encryption and IEC 62351-8 validation remain outside
both implementations' E2E scope.

## TLS versions and ML-KEM hybrid compatibility

The IEC 62351-3 TLS profile accepts TLS 1.2 and TLS 1.3 (or only TLS 1.3
when `tls13_only` is set). As in Go, the default key exchange groups are
P-256, P-384 and P-521 (`iec62351::DEFAULT_KX_GROUPS`, Go's
`iec62351.Curves`). A TLS 1.3 peer offering ML-KEM hybrids plus one of
those groups negotiates classical ECDHE; a hybrid-only peer cannot connect.

`Options::kx_groups` replaces the groups, as Go applications do by setting
`CurvePreferences` on the returned `tls.Config`. It accepts the same set Go
supports: `P256`, `P384`, `P521`, `X25519MlKem768`, `P256MlKem768` and
`P384MlKem1024`. rustls 0.23.45 has neither P-521 nor SecP384r1MLKEM1024,
so `src/iec62351/kx.rs` implements both with aws-lc-rs (the backend rustls
already uses), reusing rustls's P-384 and ML-KEM-1024 primitives for the
hybrid. The hybrids exist in TLS 1.3 only
([RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html)). Unlike Go, a
list of hybrids alone is refused unless `tls13_only` is set, because
TLS 1.2 would otherwise be offered with no group to run it on. Adding a
classical group keeps classical peers connecting. Hybrid key exchange does
not replace certificate authentication or the separate IEC 62351-4 E2E
algorithms.

Verification:

- `tls_versions_and_mlkem_hybrid_compatibility` (`tests/iec62351.rs`):
  TLS 1.2/1.3 with P-256/P-384 against plain rustls peers in both roles;
  classical fallback and hybrid-only rejection by the default profile; the
  profile opting into rustls's own X25519MLKEM768 and SecP256r1MLKEM768;
  profile-to-profile over all six groups; the TLS 1.2 guard. It asserts
  the negotiated protocol and group on both endpoints.
- `tls_key_exchange_groups` (`tests/interop_go.rs`, run by
  `interop/go-security.sh`): each group against Go's `crypto/tls`, at TLS
  1.2 and 1.3 for the classical groups and TLS 1.3 for the hybrids, in both
  directions, with each end limited to that one group. The Go server
  reports the negotiated version and group. This is the independent check
  of the P-521 and SecP384r1MLKEM1024 implementations: a deliberately
  reversed hybrid secret fails it.
- Unit tests in `src/iec62351/kx.rs` cover share lengths and layouts, and
  refuse truncated, compressed and off-curve shares.

```sh
cargo test --features tls --test iec62351 tls_versions_and_mlkem_hybrid_compatibility
bash interop/go-security.sh tls_key_exchange_groups
```

## Follow-up against Go `a1910ac`

The current Go comparison includes MMS robustness and connection events through
`a7f53e6` and `a1910ac` (21 November 2026). Rust now shares a setup deadline
across TLS and association negotiation, backs off on transient socket failures,
limits TPKT completion to 30 seconds by default, and offers an opt-in idle
timeout that counts both reads and writes. Shutdown also interrupts setup.

The optional [security event dispatcher](api.md#security-events) reports
connection, TLS and association lifecycle events with stable Go event codes,
session IDs, peer identity, and request and traffic totals. Its queue and
repeat aggregation are bounded. It exports JSON Lines and counts dropped
events, with no passwords, private keys or PDU bytes in its records.

GOOSE and SV subscribers now deliver each frame to all matching subscriptions.
Live and simulated traffic use separate filters, and GOOSE refresh continues
`sqNum` while retaining the state change timestamp. SV publishers require
`smpMod` when advertising a sample rate in samples per second. MMS report
disable retries failed writes, file cleanup has a bounded timeout, and
directory responses preserve multipart filenames.

The feature `e2e-pki` adds the `init`, `issue`, `csr` and `show` commands
for Annex G test credentials and CA signing requests. See the
[E2E guide](e2e.md#creating-credentials).

## Remaining Go features

**Full parity has not been reached.** These reference features require
separate implementation and independent validation:

1. **IEC 62351-4 native-mode TLS and OpenSSL engines:** Go's
   `Options.NativeMode` restricts TLS to 1.2 with session resumption and
   `NativeModeCipherSuites`, which include `TLS_RSA_WITH_AES_128_CBC_SHA256`.
   rustls implements neither RSA key transport nor CBC, so Rust has no
   native mode. Go's optional OpenSSL engines add DHE and legacy static-DH
   suites. The Rust TLS profile neither enables nor advertises these.
2. **Security event API:** Go's complete kind catalogue and generic sink
   adapter API have a wider scope than Rust's implemented MMS lifecycle
   events. The Go roadmap for other subsystems is still in progress.
3. A complete symbol-by-symbol comparison of the terminal tools and optional
   configuration helpers. The library's asynchronous API intentionally uses
   Rust futures rather than mirroring Go callback signatures.

Report segmentation and non-Linux Ethernet capture backends remain absent
from both implementations and are not Go parity gaps.

## Verification

```sh
cargo test
cargo test --all-features
cargo clippy --all-targets --all-features
GO_IEC61850=../go-iec61850 bash interop/run.sh
bash interop/go-security.sh
bash interop/cli-security.sh  # requires OpenSSL CLI for ephemeral test credentials
bash interop/e2e.sh
```

The security harness includes A-profile in both directions in addition to
R-GOOSE, R-SV, GDOI and TLS (11 tests). The MMS harness keeps the Go-against-Go
control run: its file-directory sweep currently chooses a directory as a
file and fails identically against the Go and Rust servers. That is reported
as `KNOWN`, not counted as evidence of missing Rust services.
