//! Certificate path validation shared by IEC 62351 application security.
use super::Error;
use crate::x509;
use rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use std::sync::RwLock;
use std::time::SystemTime;

/// A replaceable set of trust anchors. Refreshes apply to new verifications.
#[derive(Debug)]
pub struct TrustStore {
    roots: RwLock<Vec<CertificateDer<'static>>>,
}

impl TrustStore {
    pub fn new(roots: Vec<CertificateDer<'static>>) -> Result<Self, Error> {
        validate_roots(&roots)?;
        Ok(Self {
            roots: RwLock::new(roots),
        })
    }

    pub fn replace(&self, roots: Vec<CertificateDer<'static>>) -> Result<(), Error> {
        validate_roots(&roots)?;
        *self.roots.write().unwrap() = roots;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.roots.read().unwrap().is_empty()
    }

    /// Validates a certificate path without imposing a TLS extended key usage.
    /// Application profiles enforce their own key usage after this check.
    pub fn verify(
        &self,
        leaf: &[u8],
        intermediates: &[Vec<u8>],
        revocation: Option<&RevocationChecker>,
        now: SystemTime,
    ) -> Result<x509::Certificate, Error> {
        if intermediates.len() > 4 {
            return Err(Error::Chain(
                "more than four intermediate certificates".into(),
            ));
        }
        let roots = self.roots.read().unwrap().clone();
        let anchors: Vec<TrustAnchor<'_>> = roots
            .iter()
            .map(webpki::anchor_from_trusted_cert)
            .collect::<Result<_, _>>()
            .map_err(|e| Error::Chain(e.to_string()))?;
        let leaf_der = CertificateDer::from(leaf);
        let ee =
            webpki::EndEntityCert::try_from(&leaf_der).map_err(|e| Error::Chain(e.to_string()))?;
        let inter: Vec<_> = intermediates
            .iter()
            .map(|v| CertificateDer::from(v.as_slice()))
            .collect();
        let provider = super::provider();
        let time = UnixTime::since_unix_epoch(
            now.duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|e| Error::Chain(e.to_string()))?,
        );
        let path = ee
            .verify_for_usage(
                provider.signature_verification_algorithms.all,
                &anchors,
                &inter,
                time,
                AnyUsage,
                None,
                None,
            )
            .map_err(|e| Error::Chain(e.to_string()))?;
        let parsed = x509::parse(leaf).map_err(|e| Error::Chain(e.to_string()))?;
        let mut chain = vec![parsed.clone()];
        for cert in path.intermediate_certificates() {
            chain.push(x509::parse(cert.der().as_ref()).map_err(|e| Error::Chain(e.to_string()))?);
        }
        // Match the actual verified anchor, not just an issuer with the same name.
        let anchor = roots
            .iter()
            .find(|r| {
                webpki::anchor_from_trusted_cert(r).is_ok_and(|a| {
                    a.subject == path.anchor().subject
                        && a.subject_public_key_info == path.anchor().subject_public_key_info
                })
            })
            .ok_or_else(|| Error::Chain("verified anchor missing".into()))?;
        chain.push(x509::parse(anchor.as_ref()).map_err(|e| Error::Chain(e.to_string()))?);
        for cert in &chain {
            super::check_key(&cert.public_key)?;
        }
        if let Some(revocation) = revocation {
            for pair in chain.windows(2) {
                revocation.check(&pair[0], &pair[1], now)?;
            }
        }
        Ok(parsed)
    }
}

fn validate_roots(roots: &[CertificateDer<'_>]) -> Result<(), Error> {
    if roots.is_empty() {
        return Err(Error::Required("trust anchors"));
    }
    for cert in roots {
        webpki::anchor_from_trusted_cert(cert).map_err(|e| Error::Config(e.to_string()))?;
    }
    Ok(())
}

struct AnyUsage;
impl webpki::ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for oid in iter {
            oid?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum UnavailablePolicy {
    #[default]
    Warn,
    FailClosed,
}

/// CRLs supplied by the application; never fetched during a handshake.
#[derive(Debug)]
pub struct RevocationChecker {
    crls: RwLock<Vec<x509::Crl>>,
    pub policy: UnavailablePolicy,
}

impl RevocationChecker {
    pub fn new(crls: &[Vec<u8>], policy: UnavailablePolicy) -> Result<Self, Error> {
        let checker = Self {
            crls: RwLock::new(Vec::new()),
            policy,
        };
        checker.replace(crls)?;
        Ok(checker)
    }
    pub fn replace(&self, crls: &[Vec<u8>]) -> Result<(), Error> {
        let parsed = crls
            .iter()
            .map(|v| x509::parse_crl(v).map_err(|e| Error::Config(e.to_string())))
            .collect::<Result<_, _>>()?;
        *self.crls.write().unwrap() = parsed;
        Ok(())
    }
    fn check(
        &self,
        cert: &x509::Certificate,
        issuer: &x509::Certificate,
        now: SystemTime,
    ) -> Result<(), Error> {
        let provider = super::provider();
        let now = crate::time_util::unix_parts(now).0;
        let mut current = false;
        for crl in self
            .crls
            .read()
            .unwrap()
            .iter()
            .filter(|c| c.issuer == cert.issuer)
        {
            let valid_signature = provider
                .signature_verification_algorithms
                .all
                .iter()
                .any(|a| {
                    a.signature_alg_id().as_ref() == crl.signed.algorithm.as_slice()
                        && a.public_key_alg_id().as_ref() == issuer.spki_alg.as_slice()
                        && a.verify_signature(
                            &issuer.spki_key,
                            &crl.signed.tbs,
                            &crl.signed.signature,
                        )
                        .is_ok()
                });
            if !valid_signature {
                continue;
            }
            if crl.revoked.contains(&cert.serial) {
                return Err(Error::Revoked);
            }
            current |= now >= crl.this_update && crl.next_update.is_some_and(|end| now <= end);
        }
        if !current && self.policy == UnavailablePolicy::FailClosed {
            return Err(Error::StaleCrl);
        }
        Ok(())
    }
}
