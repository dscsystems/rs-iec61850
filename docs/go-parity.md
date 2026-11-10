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

## Remaining Go features

**Full parity has not been reached.** These reference features require
separate implementation and independent validation:

1. Go's standalone E2E certificate issuance/CSR convenience tool is not
   bundled in Rust; E2E credentials can be issued externally and loaded as
   PEM or DER.
2. **Native-mode TLS cipher suites and OpenSSL engines:** Rust's current
   rustls transport supports ECDHE/AES-GCM and TLS 1.3. Go additionally offers
   optional OpenSSL engines for DHE and legacy static-DH suites. These are
   not enabled or advertised by the Rust TLS profile.
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
R-GOOSE, R-SV, GDOI and TLS (10 tests). The MMS harness keeps the Go-against-Go
control run: its file-directory sweep currently chooses a directory as a
file and fails identically against the Go and Rust servers. That is reported
as `KNOWN`, not counted as evidence of missing Rust services.
