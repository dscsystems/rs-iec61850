# IEC 62351-4 native E2E security

Build with `--features e2e`. This implements the native integrity-protected
profile supported by the Go reference: signed association setup, ephemeral
DH key agreement, HMAC/GMAC-protected MMS, rekey, signed release and aborts.
It is distinct from the compatibility-mode A-profile (`--mms-*`).

## Credentials and identities

Each endpoint needs an E2E leaf certificate, its private key, and trust
anchors for the peer. Certificates follow the implemented Annex G profile:

- X.509 v3, positive serial, RSA at least 2048 bits or ECDSA P-256;
- a SHA-256-or-stronger issuer signature;
- `digitalSignature` and `keyAgreement` key usages, without CA privileges
  or issuer/subject unique identifiers;
- one subject RDN containing one OID-valued `objectIdentifier` attribute
  (`2.5.4.106`). Its value concatenates the AP-title OID and AE-qualifier.

For example, AE `1.3.6.1.4.1.55555/2` has subject attribute value
`1.3.6.1.4.1.55555.2`. A common-name string containing those digits does not
satisfy this requirement. Certificate issuance remains the application's
PKI responsibility; `tests/e2e_common` creates ephemeral test credentials.
The path may contain up to four intermediate certificates, with each
certificate at most 8192 octets.

The peer's certificate identity must match its ACSE AE title. A client also
pins the expected server AE in its configuration. The server exposes the
validated E2E identity to its ordinary association authenticator.

TLS may additionally protect the transport. TLS and E2E must use separate
leaf certificates. The bundled tools reject local credential reuse, and the
MMS TLS dial/accept paths reject reuse by the peer. Applications supplying
already-secured streams directly must enforce that separation themselves.
Rustls's TLS cipher selection remains independent of this implementation:
the optional OpenSSL/DHE native-mode TLS engines are still a separate Go
parity gap. This E2E implementation is not a claim of complete native-mode
TLS or laboratory conformance.

## Library API

```rust
use std::sync::Arc;
use iec61850::{client, server, iec62351::{e2e, pki::UnavailablePolicy}};

let config = e2e::Files {
    certificate: "scada-e2e.pem".into(),
    key: "scada-e2e.key".into(),
    authorities: vec!["e2e-ca.pem".into()],
    crls: vec!["e2e-ca.crl".into()],
    ..Default::default()
}.load(UnavailablePolicy::Warn)?;
let peer: e2e::AeTitle = "1.3.6.1.4.1.55555/2".parse()?;
let options = client::Options::new().with_e2e(Arc::new(config), peer);
let connection = client::Client::dial_with("ied.example:102", options).await?;
let identity = connection.mms().peer_e2e_security();
connection.close().await?;
```

A server uses `server::Options::with_e2e(config, true)` to require E2E.
`false` permits ordinary associations during migration; native requests
still undergo full verification. `mms::AssociationRequest::e2e_peer` and
`mms::ServerConn::e2e_peer` expose the validated peer certificate and AE.
A password or A-profile cannot accompany a native client association.

Reuse an `Arc<e2e::Config>` across all associations of an endpoint. Its
handshake replay cache and live association identifier allocator must cover
all those associations. Its `Policy` is configured before sharing it.

The lower-level `e2e::Association` operates on complete SecPDU TLVs and
protected application TLVs; the MMS integration supplies the OSI mapping.
`e2e::osi` exposes the EXTERNAL/Virtual API wrappers for other environments.
`Policy::on_event` receives handshake acceptance, rekey and security-error
events. Debug output excludes key material.

## Policy and key management

Defaults:

- Amendment 2020 wire encoding with the published corrections in force;
- P-256 DH (group 23), with MODP-2048 (group 14) also accepted;
- HMAC-SHA-256, AES-128-GMAC and AES-256-GMAC, in that preference order;
- Annex B Authenticator encoding, ten-minute freshness window;
- one-hour client rekey interval and at most `2^30` messages per key.

`Policy::edition = Edition::First2018` selects the earlier, incompatible
ClearToken1/Virtual API encoding. `Corrections::None` selects the printed
2020 numbering and GMAC identifiers. Receivers recognize both GMAC OID
forms and preserve the negotiated identifier. Clause 13 Authenticator
tagging and alternative initial HKDF hash representations are selectable.

The client changes its transmit key immediately after sending a rekey;
its receive key changes after the old-key-protected `changedKey` response.
The server advances the corresponding directions separately. The MMS
client sends a Status carrier when an otherwise idle association needs a
rekey. An unacknowledged rekey ends the association after 30 seconds.
`Association::request_rekey`, `rekey_due`, `rekey_overdue` and `epoch`
are available to other environments.

Trust anchors and CRLs can be refreshed using the shared PKI objects.
`UnavailablePolicy::Warn` accepts unavailable revocation information;
`FailClosed` requires current issuer-signed information. A signed revocation
always refuses the certificate. Attribute certificates are ignored with an
event unless `require_authorization` is set, in which case they are refused:
IEC 62351-8 authorization validation is not implemented.

## Tools and verification

```sh
cargo run --features e2e --bin ied-server -- \
  --scl testdata/simpleIO_direct_control.cid --addr :10102 \
  --e2e-cert ied-e2e.pem --e2e-key ied-e2e.key --e2e-ca e2e-ca.pem

cargo run --features e2e --bin ied-client -- \
  --addr 127.0.0.1:10102 --e2e-peer 1.3.6.1.4.1.55555/2 \
  --e2e-cert scada-e2e.pem --e2e-key scada-e2e.key --e2e-ca e2e-ca.pem \
  read simpleIOGenericIO/GGIO1.AnIn1.mag.f MX
```

`--e2e-ca`, `--e2e-crl` and `--e2e-path` are repeatable. Optional
`--e2e-edition 2018|2020`, `--e2e-group 14|23` and
`--e2e-icv hmac-sha256|aes128-gmac|aes256-gmac` select interoperability
parameters. Add the ordinary `--tls-*` flags for transport confidentiality.
`iedx` uses the same credential options across reconnects.

```sh
cargo test --features e2e --test e2e
bash interop/e2e.sh
cargo test --all-features
cargo clippy --all-targets --all-features
```

The Rust tests exercise both editions, both DH groups, both signature
families and all three ICV algorithms, repeated rekey, signed release,
certificate identity and trust, replay, truncation, stale time, malformed
certificates, individual handshake faults, indefinite BER signed spans,
TLS credential separation and abrupt disconnect. Known-answer tests cover
HMAC and GMAC.

The Go harness runs 13 configurations in each MMS direction, including the
earlier edition and identifiers, clause-13 tagging, RSA and P-256, multiple
rekeys and orderly release. It also tests the bundled tools. These are
interoperability tests against one independent implementation, not external
certification or standard-supplied cryptographic vectors for the entire
key schedule.

Encryption/AEAD transfer, brainpool keys and IEC 62351-8 attribute-certificate
validation remain unsupported, matching the Go reference's implemented
E2E scope. Unsupported encryption proposals are explicitly refused.
