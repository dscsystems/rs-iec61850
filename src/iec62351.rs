//! The TLS profile of IEC 62351-3 for MMS: the transport security of the
//! client and server. (The IEC 61850-90-5 session security of R-GOOSE and
//! R-SV is in [`crate::rsession`].)
//!
//! [`client_config`] and [`server_config`] build rustls configurations under
//! the profile:
//!
//! - TLS 1.2 or 1.3 ([`Options::tls13_only`] refuses 1.2), with ephemeral
//!   elliptic-curve key exchange (P-256, P-384) and AES-GCM only.
//! - Both ends authenticate with certificates, which must chain to
//!   [`Options::roots`]. A certificate with an extended key usage must allow
//!   TLS server or client authentication as its role requires; IED
//!   certificates without one are accepted.
//! - Every certificate of the chain is checked against the configured CRLs,
//!   and refused when revoked; a CRL past its next update fails the
//!   connection unless [`Options::allow_stale_crl`].
//! - Keys weaker than 2048-bit RSA or 256-bit ECDSA are refused anywhere in
//!   the chain.
//! - [`Options::allowed_peers`] pins the peers to exact certificates.
//! - A client checks the server's name in its subject alternative names, or,
//!   for a certificate without any (usual for IEDs), its common name.
//! - Neither end resumes sessions, so every association is fully
//!   authenticated.
//!
//! Each refused peer is reported to [`Options::on_event`] for the security
//! event log (IEC 62351-14).

use std::sync::Arc;
use std::time::SystemTime;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{self, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, TrustAnchor, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::x509;

/// The port of MMS over TLS (IEC 62351-3, ISO-TSAP over TLS).
pub const MMS_TLS_PORT: u16 = 3782;

/// The smallest RSA key accepted from a peer.
pub const MIN_RSA_BITS: usize = 2048;

/// Receives every peer refused.
pub type EventHandler = Arc<dyn Fn(&Event) + Send + Sync>;

/// A refused peer.
#[derive(Debug)]
pub struct Event {
    /// The leaf the peer presented, `None` if none.
    pub peer: Option<CertificateDer<'static>>,
    pub err: Error,
}

/// Errors of configuration and peer verification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error("iec62351: {0} is required")]
    Required(&'static str),
    #[error("iec62351: {0}")]
    Config(String),
    #[error("iec62351: peer presented no certificate")]
    NoPeerCertificate,
    #[error("iec62351: certificate chain: {0}")]
    Chain(String),
    #[error("iec62351: certificate revoked")]
    Revoked,
    #[error("iec62351: CRL past its next update")]
    StaleCrl,
    #[error("iec62351: key too weak: {0}")]
    WeakKey(String),
    #[error("iec62351: peer certificate not in the allowed set")]
    NotAllowed,
    #[error("iec62351: server certificate does not name the server: want {0:?}")]
    ServerName(String),
}

/// Configures one end of a TLS connection under the profile.
#[derive(Default)]
pub struct Options {
    /// This end's certificate chain, leaf first. Required: the profile
    /// authenticates both ends.
    pub certificates: Vec<CertificateDer<'static>>,
    /// The private key of the leaf. Required.
    pub key: Option<PrivateKeyDer<'static>>,
    /// The certificate authorities a peer's chain must lead to. Required.
    pub roots: Vec<CertificateDer<'static>>,
    /// DER CRLs, checked against every certificate of the peer's chain.
    pub crls: Vec<Vec<u8>>,
    pub allow_stale_crl: bool,
    /// When not empty, restricts the peers to these certificates exactly
    /// (pinning), after the chain checks.
    pub allowed_peers: Vec<CertificateDer<'static>>,
    /// On a client, the identity the server's certificate must carry: in a
    /// subject alternative name, or, for a certificate that has none, as its
    /// common name. Empty checks the chain only.
    pub server_name: String,
    /// Refuses TLS 1.2.
    pub tls13_only: bool,
    pub on_event: Option<EventHandler>,
    /// Overrides the clock the certificates and CRLs are checked against
    /// (tests).
    pub now: Option<fn() -> SystemTime>,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("certificates", &self.certificates.len())
            .field("roots", &self.roots.len())
            .field("crls", &self.crls.len())
            .field("allow_stale_crl", &self.allow_stale_crl)
            .field("allowed_peers", &self.allowed_peers.len())
            .field("server_name", &self.server_name)
            .field("tls13_only", &self.tls13_only)
            .finish_non_exhaustive()
    }
}

/// The provider of the profile: AES-GCM suites with ECDHE, P-256 and P-384.
fn provider() -> CryptoProvider {
    use crypto::aws_lc_rs as p;
    CryptoProvider {
        cipher_suites: vec![
            p::cipher_suite::TLS13_AES_128_GCM_SHA256,
            p::cipher_suite::TLS13_AES_256_GCM_SHA384,
            p::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            p::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            p::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            p::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![p::kx_group::SECP256R1, p::kx_group::SECP384R1],
        ..p::default_provider()
    }
}

/// Returns the TLS configuration of an MMS client under the profile, for
/// [`client::Options::with_tls`](crate::client::Options::with_tls).
pub fn client_config(o: Options) -> Result<Arc<rustls::ClientConfig>, Error> {
    let key = o.key.as_ref().ok_or(Error::Required("Options::key"))?.clone_key();
    let (provider, versions, verifier) = base(o)?;
    let own = Arc::new(OwnCert(certified_key(&provider, &verifier.own, key)?));
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| Error::Config(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_client_cert_resolver(own);
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(cfg))
}

/// Returns the TLS configuration of an MMS server under the profile, for
/// [`server::Options::with_tls`](crate::server::Options::with_tls): clients
/// must present a certificate, which is checked as a client checks a server's.
pub fn server_config(o: Options) -> Result<Arc<rustls::ServerConfig>, Error> {
    let key = o.key.as_ref().ok_or(Error::Required("Options::key"))?.clone_key();
    let (provider, versions, verifier) = base(o)?;
    let own = Arc::new(OwnCert(certified_key(&provider, &verifier.own, key)?));
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| Error::Config(e.to_string()))?
        .with_client_cert_verifier(verifier.clone())
        .with_cert_resolver(own);
    // Resumption skips the certificate checks for the lifetime of a ticket;
    // MMS associations are long-lived, so a full handshake each time costs
    // nothing that matters.
    cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    cfg.send_tls13_tickets = 0;
    Ok(Arc::new(cfg))
}

/// This end's certificate and key, presented as they are. rustls would parse
/// the certificate to check it against the key, and its parser refuses an
/// X.509 v1 certificate, which is what many IEDs (and libiec61850's examples)
/// carry; the peer is the one to judge it.
fn certified_key(
    provider: &CryptoProvider,
    chain: &[CertificateDer<'static>],
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::sign::CertifiedKey>, Error> {
    let signer = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| Error::Config(format!("private key: {e}")))?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(chain.to_vec(), signer)))
}

#[derive(Debug)]
struct OwnCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for OwnCert {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

impl rustls::client::ResolvesClientCert for OwnCert {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

type Base = (
    Arc<CryptoProvider>,
    &'static [&'static rustls::SupportedProtocolVersion],
    Arc<Verifier>,
);

fn base(o: Options) -> Result<Base, Error> {
    if o.certificates.is_empty() {
        return Err(Error::Required("Options::certificates"));
    }
    if o.roots.is_empty() {
        return Err(Error::Required("Options::roots"));
    }
    let anchors = o
        .roots
        .iter()
        .map(|c| {
            webpki::anchor_from_trusted_cert(c)
                .map(|a| a.to_owned())
                .map_err(|e| Error::Config(format!("root certificate: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let crls = o
        .crls
        .iter()
        .map(|der| {
            webpki::OwnedCertRevocationList::from_der(der)
                .map_err(|e| Error::Config(format!("CRL: {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    // The names a server advertises as the authorities it accepts: each a
    // whole DER Name, which a webpki anchor holds without its SEQUENCE. A
    // client choosing a certificate by them (Go's does) finds none otherwise.
    let hints = anchors
        .iter()
        .map(|a| DistinguishedName::in_sequence(a.subject.as_ref()))
        .collect();
    let provider = Arc::new(provider());
    static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    static TLS12_AND_13: &[&rustls::SupportedProtocolVersion] =
        &[&rustls::version::TLS13, &rustls::version::TLS12];
    let versions = if o.tls13_only { TLS13_ONLY } else { TLS12_AND_13 };
    let roots = o
        .roots
        .iter()
        .map(|c| x509::parse(c.as_ref()).map_err(|e| Error::Config(format!("root certificate: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let crl_list = o
        .crls
        .iter()
        .map(|c| x509::parse_crl(c).map_err(|e| Error::Config(format!("CRL: {e}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let verifier = Arc::new(Verifier {
        algs: provider.signature_verification_algorithms,
        anchors,
        crls,
        roots,
        crl_list,
        hints,
        own: o.certificates,
        allow_stale_crl: o.allow_stale_crl,
        allowed_peers: o.allowed_peers,
        server_name: o.server_name,
        on_event: o.on_event,
        now: o.now,
    });
    Ok((provider, versions, verifier))
}

/// Verifies a peer under the profile, in either role.
struct Verifier {
    algs: WebPkiSupportedAlgorithms,
    anchors: Vec<TrustAnchor<'static>>,
    crls: Vec<webpki::OwnedCertRevocationList>,
    /// The roots and CRLs as this crate reads them, for X.509 v1 leaves,
    /// which webpki does not take.
    roots: Vec<x509::Certificate>,
    crl_list: Vec<x509::Crl>,
    hints: Vec<DistinguishedName>,
    own: Vec<CertificateDer<'static>>,
    allow_stale_crl: bool,
    allowed_peers: Vec<CertificateDer<'static>>,
    server_name: String,
    on_event: Option<EventHandler>,
    now: Option<fn() -> SystemTime>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier").finish_non_exhaustive()
    }
}

impl Verifier {
    fn now(&self, given: UnixTime) -> UnixTime {
        match self.now {
            Some(f) => UnixTime::since_unix_epoch(
                f().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default(),
            ),
            None => given,
        }
    }

    /// Checks a peer and reports a refusal.
    fn check(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        server: bool,
    ) -> Result<(), rustls::Error> {
        self.verify(leaf, intermediates, now, server).map_err(|err| {
            if let Some(h) = &self.on_event {
                h(&Event {
                    peer: Some(leaf.clone().into_owned()),
                    err: err.clone(),
                });
            }
            rustls::Error::General(err.to_string())
        })
    }

    fn verify(
        &self,
        leaf: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        server: bool,
    ) -> Result<(), Error> {
        let parsed = x509::parse(leaf.as_ref()).map_err(|e| Error::Chain(e.to_string()))?;
        if parsed.version == 1 {
            self.verify_v1(&parsed, now)?;
            // A v1 certificate has no extensions, so no alternative names: it
            // is named by its common name.
            if server && !self.server_name.is_empty() && parsed.common_name.as_deref() != Some(&self.server_name) {
                return Err(Error::ServerName(self.server_name.clone()));
            }
            return self.check_pinned(leaf);
        }
        let ee = webpki::EndEntityCert::try_from(leaf).map_err(|e| Error::Chain(e.to_string()))?;
        let crl_refs: Vec<webpki::CertRevocationList<'_>> =
            self.crls.iter().map(|c| webpki::CertRevocationList::Owned(c.clone())).collect();
        let crl_ptrs: Vec<&webpki::CertRevocationList<'_>> = crl_refs.iter().collect();
        let revocation = webpki::RevocationOptionsBuilder::new(&crl_ptrs).ok().map(|b| {
            b.with_depth(webpki::RevocationCheckDepth::Chain)
                .with_status_policy(webpki::UnknownStatusPolicy::Allow)
                .with_expiration_policy(if self.allow_stale_crl {
                    webpki::ExpirationPolicy::Ignore
                } else {
                    webpki::ExpirationPolicy::Enforce
                })
                .build()
        });
        let usage = if server {
            webpki::KeyUsage::server_auth()
        } else {
            webpki::KeyUsage::client_auth()
        };
        let path = ee
            .verify_for_usage(
                self.algs.all,
                &self.anchors,
                intermediates,
                self.now(now),
                usage,
                revocation,
                None,
            )
            .map_err(|e| match e {
                webpki::Error::CertRevoked => Error::Revoked,
                webpki::Error::CrlExpired { .. } => Error::StaleCrl,
                other => Error::Chain(format!("{other:?}")),
            })?;

        // Key strength, from the leaf to the root.
        check_key(&parsed.public_key)?;
        for c in path.intermediate_certificates() {
            let parsed = x509::parse(c.der().as_ref()).map_err(|e| Error::Chain(e.to_string()))?;
            check_key(&parsed.public_key)?;
        }
        let anchor = x509::parse_spki(path.anchor().subject_public_key_info.as_ref())
            .map_err(|e| Error::Chain(e.to_string()))?;
        check_key(&anchor)?;

        if server && !self.server_name.is_empty() && !names_server(&ee, &parsed, &self.server_name) {
            return Err(Error::ServerName(self.server_name.clone()));
        }
        self.check_pinned(leaf)
    }

    fn check_pinned(&self, leaf: &CertificateDer<'_>) -> Result<(), Error> {
        if !self.allowed_peers.is_empty() && !self.allowed_peers.iter().any(|a| a.as_ref() == leaf.as_ref()) {
            return Err(Error::NotAllowed);
        }
        Ok(())
    }

    /// Verifies an X.509 v1 leaf, which webpki refuses: it must be issued
    /// directly by a configured root, within its validity, with a key of the
    /// profile's strength, and not revoked by a CRL its root signed.
    fn verify_v1(&self, leaf: &x509::Certificate, now: UnixTime) -> Result<(), Error> {
        let now = self.now(now).as_secs() as i64;
        if now < leaf.not_before || now > leaf.not_after {
            return Err(Error::Chain("certificate expired or not yet valid".into()));
        }
        let root = self
            .roots
            .iter()
            .find(|r| r.subject == leaf.issuer)
            .ok_or_else(|| Error::Chain("an X.509 v1 certificate not issued by a configured root".into()))?;
        if !self.signed_by(&leaf.signed, root) {
            return Err(Error::Chain("certificate signature does not verify".into()));
        }
        check_key(&leaf.public_key)?;
        check_key(&root.public_key)?;
        for crl in self.crl_list.iter().filter(|c| c.issuer == leaf.issuer) {
            if !self.signed_by(&crl.signed, root) {
                continue;
            }
            if !self.allow_stale_crl && crl.next_update.is_some_and(|n| now > n) {
                return Err(Error::StaleCrl);
            }
            if crl.revoked.iter().any(|s| s == &leaf.serial) {
                return Err(Error::Revoked);
            }
        }
        Ok(())
    }

    /// Verifies a handshake signature with the key of an X.509 v1
    /// certificate, which rustls's own check refuses to parse; `None` when the
    /// certificate is not v1 or the signature does not verify.
    fn verify_v1_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Option<HandshakeSignatureValid> {
        let c = x509::parse(cert.as_ref()).ok().filter(|c| c.version == 1)?;
        let (_, algs) = self.algs.mapping.iter().find(|(scheme, _)| *scheme == dss.scheme)?;
        algs.iter()
            .any(|alg| {
                alg.public_key_alg_id().as_ref() == c.spki_alg.as_slice()
                    && alg.verify_signature(&c.spki_key, message, dss.signature()).is_ok()
            })
            .then(HandshakeSignatureValid::assertion)
    }

    /// Reports whether `issuer`'s key verifies a signed structure, with the
    /// provider's algorithm for its signature and key types.
    fn signed_by(&self, signed: &x509::Signed, issuer: &x509::Certificate) -> bool {
        self.algs.all.iter().any(|alg| {
            alg.signature_alg_id().as_ref() == signed.algorithm.as_slice()
                && alg.public_key_alg_id().as_ref() == issuer.spki_alg.as_slice()
                && alg.verify_signature(&issuer.spki_key, &signed.tbs, &signed.signature).is_ok()
        })
    }
}

fn check_key(k: &x509::PublicKey) -> Result<(), Error> {
    match k {
        x509::PublicKey::Rsa { .. } => {
            let bits = k.rsa_bits().unwrap_or(0);
            if bits < MIN_RSA_BITS {
                return Err(Error::WeakKey(format!("{bits}-bit RSA")));
            }
        }
        x509::PublicKey::Ec { curve, .. } => {
            if curve.bits() < 256 {
                return Err(Error::WeakKey(format!("{curve:?}")));
            }
        }
        x509::PublicKey::Ed25519(_) => {}
        x509::PublicKey::Other(oid) => return Err(Error::WeakKey(format!("algorithm {oid:?}"))),
    }
    Ok(())
}

/// Reports whether the certificate names the server: in its subject
/// alternative names when it has any, else in its common name.
fn names_server(ee: &webpki::EndEntityCert<'_>, c: &x509::Certificate, name: &str) -> bool {
    if c.has_alt_names {
        return ServerName::try_from(name).is_ok_and(|sn| ee.verify_is_valid_for_subject_name(&sn).is_ok());
    }
    c.common_name.as_deref() == Some(name)
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The name the connection was dialled by is an address more often
        // than not; the profile names the server by Options::server_name.
        self.check(end_entity, intermediates, now, true)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls12_signature(message, cert, dss, &self.algs)
            .or_else(|e| self.verify_v1_signature(message, cert, dss).ok_or(e))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.algs)
            .or_else(|e| self.verify_v1_signature(message, cert, dss).ok_or(e))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity, intermediates, now, false)?;
        Ok(ClientCertVerified::assertion())
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls12_signature(message, cert, dss, &self.algs)
            .or_else(|e| self.verify_v1_signature(message, cert, dss).ok_or(e))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.algs)
            .or_else(|e| self.verify_v1_signature(message, cert, dss).ok_or(e))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}
