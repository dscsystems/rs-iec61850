//! IEC 62351-4 compatibility-mode ACSE certificate authentication.
//! The value authenticates association setup; TLS protects subsequent MMS data.
use super::pki::{RevocationChecker, TrustStore};
use crate::{
    asn1::{
        self, cons, context_constructed as cc, context_primitive as cp, prim, Decoder, Oid,
        TAG_INTEGER,
    },
    time_util, x509,
};
use rustls::{pki_types::PrivateKeyDer, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(600);
pub fn mechanism() -> Oid {
    Oid::from([1, 0, 62351, 4, 3, 1])
}
pub fn legacy_mechanism() -> Oid {
    Oid::from([1, 0, 840, 0, 1, 0, 1, 1])
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("A-profile: malformed authentication value")]
    Malformed,
    #[error("A-profile: certificate: {0}")]
    Certificate(String),
    #[error("A-profile: peer time differs by more than ten minutes")]
    Time,
    #[error("A-profile: replayed authentication value")]
    Replay,
    #[error("A-profile: invalid signature")]
    Signature,
    #[error("A-profile: configuration: {0}")]
    Config(String),
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub certificate: Vec<u8>,
    pub time: Vec<u8>,
    pub signature: Vec<u8>,
    pub indirect_reference: Option<i64>,
}
impl Value {
    pub fn encode(&self) -> Vec<u8> {
        let mut external = cons(cc(2), []);
        if let Some(id) = self.indirect_reference {
            external.push(asn1::int_elem(TAG_INTEGER, id));
        }
        external.push(cons(
            cc(0),
            [cons(
                cc(0),
                [
                    prim(cp(0), self.certificate.clone()),
                    prim(cp(1), self.time.clone()),
                    prim(cp(2), self.signature.clone()),
                ],
            )],
        ));
        external.encode()
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let decode = || -> asn1::Result<Self> {
            let mut outer = Decoder::new(bytes);
            let ext = outer.expect(cc(2))?;
            if outer.more() {
                return Err(asn1::Error::bad_value("trailing authentication data"));
            }
            let mut d = Decoder::new(ext);
            let indirect_reference = d.optional(TAG_INTEGER)?.map(asn1::decode_int).transpose()?;
            let mut body = d.expect(cc(0))?;
            if d.more() {
                return Err(asn1::Error::bad_value("trailing EXTERNAL data"));
            }
            let mut inner = Decoder::new(body);
            if inner.peek_is(cc(0)) {
                body = inner.expect(cc(0))?;
                if inner.more() {
                    return Err(asn1::Error::bad_value("trailing certificate data"));
                }
            }
            let mut fields = Decoder::new(body);
            let certificate = fields.expect(cp(0))?.to_vec();
            let time = fields.expect(cp(1))?.to_vec();
            let signature = fields.expect(cp(2))?.to_vec();
            if fields.more() || certificate.is_empty() || signature.is_empty() {
                return Err(asn1::Error::bad_value("invalid certificate value"));
            }
            Ok(Self {
                certificate,
                time,
                signature,
                indirect_reference,
            })
        };
        decode().map_err(|_| Error::Malformed)
    }
}

pub struct Credential {
    pub certificate: Vec<u8>,
    key: Arc<dyn rustls::sign::SigningKey>,
}
impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential").finish_non_exhaustive()
    }
}
impl Credential {
    pub fn new(certificate: Vec<u8>, key: PrivateKeyDer<'static>) -> Result<Self> {
        let parsed = x509::parse(&certificate).map_err(|e| Error::Config(e.to_string()))?;
        if parsed.public_key.rsa_bits().unwrap_or(0) < 2048 {
            return Err(Error::Config(
                "RSA of at least 2048 bits is required".into(),
            ));
        }
        let key = super::provider()
            .key_provider
            .load_private_key(key)
            .map_err(|e| Error::Config(e.to_string()))?;
        let credential = Self { certificate, key };
        // Check key/certificate agreement before an association can be attempted.
        let probe = credential.sign(SystemTime::UNIX_EPOCH)?;
        verify_signature(&parsed, &probe.time, &probe.signature)
            .map_err(|_| Error::Config("private key does not match certificate".into()))?;
        Ok(credential)
    }
    pub fn sign(&self, now: SystemTime) -> Result<Value> {
        let (y, m, d, h, mi, s) = time_util::civil_from_unix(time_util::unix_parts(now).0);
        let time = format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}Z").into_bytes();
        let signer = self
            .key
            .choose_scheme(&[SignatureScheme::RSA_PKCS1_SHA256])
            .ok_or_else(|| Error::Config("RSA PKCS#1 SHA-256 signing is required".into()))?;
        let signature = signer
            .sign(&time)
            .map_err(|e| Error::Config(e.to_string()))?;
        Ok(Value {
            certificate: self.certificate.clone(),
            time,
            signature,
            indirect_reference: None,
        })
    }
}

type ReplayKey = ([u8; 32], Vec<u8>);
#[derive(Debug)]
pub struct Verifier {
    pub trust: Arc<TrustStore>,
    pub revocation: Option<Arc<RevocationChecker>>,
    pub intermediates: Vec<Vec<u8>>,
    pub now: fn() -> SystemTime,
    seen: Mutex<HashMap<ReplayKey, SystemTime>>,
}
impl Verifier {
    pub fn new(trust: Arc<TrustStore>) -> Self {
        Self {
            trust,
            revocation: None,
            intermediates: Vec::new(),
            now: SystemTime::now,
            seen: Mutex::new(HashMap::new()),
        }
    }
    pub fn verify(&self, value: &Value) -> Result<x509::Certificate> {
        let now = (self.now)();
        let cert = self
            .trust
            .verify(
                &value.certificate,
                &self.intermediates,
                self.revocation.as_deref(),
                now,
            )
            .map_err(|e| Error::Certificate(e.to_string()))?;
        if cert.public_key.rsa_bits().unwrap_or(0) < 2048 {
            return Err(Error::Certificate("RSA key smaller than 2048 bits".into()));
        }
        let stamp = parse_time(&value.time)?;
        let difference = now
            .duration_since(stamp)
            .or_else(|_| stamp.duration_since(now))
            .map_err(|_| Error::Time)?;
        if difference > MAX_CLOCK_SKEW {
            return Err(Error::Time);
        }
        verify_signature(&cert, &value.time, &value.signature)?;
        // A future-dated value remains valid until timestamp+skew, so retain it
        // for that entire period rather than merely skew after reception.
        let expires = stamp.checked_add(MAX_CLOCK_SKEW).ok_or(Error::Time)?;
        let key = (
            Sha256::digest(&value.certificate).into(),
            value.time.clone(),
        );
        let mut seen = self.seen.lock().unwrap();
        seen.retain(|_, expires| *expires >= now);
        if seen.contains_key(&key) {
            return Err(Error::Replay);
        }
        if seen.len() >= 65536 {
            return Err(Error::Config("authentication replay cache is full".into()));
        }
        seen.insert(key, expires);
        Ok(cert)
    }
}
fn verify_signature(cert: &x509::Certificate, time: &[u8], signature: &[u8]) -> Result<()> {
    let provider = super::provider();
    let valid = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .filter(|(scheme, _)| *scheme == SignatureScheme::RSA_PKCS1_SHA256)
        .flat_map(|(_, algorithms)| algorithms.iter())
        .any(|alg| {
            alg.public_key_alg_id().as_ref() == cert.spki_alg.as_slice()
                && alg
                    .verify_signature(&cert.spki_key, time, signature)
                    .is_ok()
        });
    if valid {
        Ok(())
    } else {
        Err(Error::Signature)
    }
}
fn parse_time(bytes: &[u8]) -> Result<SystemTime> {
    let s = std::str::from_utf8(bytes).map_err(|_| Error::Malformed)?;
    if s.len() < 15 || !s.ends_with('Z') || !s.as_bytes()[..14].iter().all(u8::is_ascii_digit) {
        return Err(Error::Malformed);
    }
    let fraction = &s[14..s.len() - 1];
    if !fraction.is_empty()
        && (!fraction.starts_with('.')
            || fraction.len() < 2
            || fraction.len() > 10
            || !fraction.as_bytes()[1..].iter().all(u8::is_ascii_digit))
    {
        return Err(Error::Malformed);
    }
    let n = |start, end| s[start..end].parse::<u32>().map_err(|_| Error::Malformed);
    let (y, m, d, h, mi, sec) = (
        n(0, 4)?,
        n(4, 6)?,
        n(6, 8)?,
        n(8, 10)?,
        n(10, 12)?,
        n(12, 14)?,
    );
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return Err(Error::Malformed);
    }
    let days = time_util::days_from_civil(i64::from(y), m, d);
    if time_util::civil_from_days(days) != (i64::from(y), m, d) {
        return Err(Error::Malformed);
    }
    let nanos = if fraction.is_empty() {
        0
    } else {
        fraction[1..].parse::<u32>().map_err(|_| Error::Malformed)?
            * 10u32.pow(10 - fraction.len() as u32)
    };
    Ok(time_util::from_unix(
        days * 86400 + i64::from(h * 3600 + mi * 60 + sec),
        nanos,
    ))
}

#[derive(Debug)]
pub struct Config {
    pub credential: Credential,
    pub verifier: Arc<Verifier>,
    pub mechanism: Option<Oid>,
    pub indirect_reference: Option<i64>,
    pub allow_without_tls: bool,
}
impl Config {
    pub fn new(credential: Credential, verifier: Arc<Verifier>) -> Self {
        Self {
            credential,
            verifier,
            mechanism: None,
            indirect_reference: None,
            allow_without_tls: false,
        }
    }
    pub fn value(&self) -> Result<Value> {
        let mut value = self.credential.sign((self.verifier.now)())?;
        value.indirect_reference = self.indirect_reference;
        Ok(value)
    }
}

/// Credential, trust and CRL files, each PEM or DER.
#[derive(Debug, Default)]
pub struct Files {
    pub certificate: std::path::PathBuf,
    pub key: std::path::PathBuf,
    pub authorities: Vec<std::path::PathBuf>,
    pub crls: Vec<std::path::PathBuf>,
    pub intermediates: Vec<std::path::PathBuf>,
}

impl Files {
    pub fn load(&self, policy: super::pki::UnavailablePolicy) -> Result<Config> {
        use rustls::pki_types::{pem::PemObject, CertificateDer, CertificateRevocationListDer};
        let read = |path: &std::path::Path| {
            std::fs::read(path).map_err(|e| Error::Config(format!("{}: {e}", path.display())))
        };
        let certificates = |path: &std::path::Path| -> Result<Vec<CertificateDer<'static>>> {
            let bytes = read(path)?;
            if bytes.starts_with(b"-----BEGIN") {
                CertificateDer::pem_slice_iter(&bytes)
                    .map(|c| c.map_err(|e| Error::Config(e.to_string())))
                    .collect()
            } else {
                Ok(vec![CertificateDer::from(bytes)])
            }
        };
        let certs = certificates(&self.certificate)?;
        let certificate = certs
            .first()
            .ok_or_else(|| Error::Config("no certificate in file".into()))?
            .to_vec();
        let key = read(&self.key)?;
        let key = if key.starts_with(b"-----BEGIN") {
            PrivateKeyDer::from_pem_slice(&key).map_err(|e| Error::Config(e.to_string()))?
        } else {
            PrivateKeyDer::try_from(key).map_err(|e| Error::Config(e.into()))?
        };
        let credential = Credential::new(certificate, key)?;
        let mut roots = Vec::new();
        for file in &self.authorities {
            roots.extend(certificates(file)?);
        }
        let trust = Arc::new(TrustStore::new(roots).map_err(|e| Error::Config(e.to_string()))?);
        let mut verifier = Verifier::new(trust);
        for file in &self.intermediates {
            verifier
                .intermediates
                .extend(certificates(file)?.into_iter().map(|c| c.to_vec()));
        }
        if !self.crls.is_empty() {
            let mut crls = Vec::new();
            for file in &self.crls {
                let bytes = read(file)?;
                if bytes.starts_with(b"-----BEGIN") {
                    for crl in CertificateRevocationListDer::pem_slice_iter(&bytes) {
                        crls.push(crl.map_err(|e| Error::Config(e.to_string()))?.to_vec());
                    }
                } else {
                    crls.push(bytes);
                }
            }
            verifier.revocation = Some(Arc::new(
                RevocationChecker::new(&crls, policy).map_err(|e| Error::Config(e.to_string()))?,
            ));
        }
        Ok(Config::new(credential, Arc::new(verifier)))
    }
}
