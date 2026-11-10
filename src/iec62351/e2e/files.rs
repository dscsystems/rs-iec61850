//! PEM/DER credential loading for native-mode endpoints.
use super::*;
use rustls::pki_types::{
    pem::PemObject, CertificateDer, CertificateRevocationListDer, PrivateKeyDer,
};
use std::path::{Path, PathBuf};
#[derive(Debug, Default)]
pub struct Files {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub path: Vec<PathBuf>,
    pub authorities: Vec<PathBuf>,
    pub crls: Vec<PathBuf>,
}
fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| Error::hs(8, format!("{}: {e}", path.display())))
}
fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = read(path)?;
    if data.starts_with(b"-----BEGIN") {
        CertificateDer::pem_slice_iter(&data)
            .map(|c| c.map_err(|e| Error::hs(8, e.to_string())))
            .collect()
    } else {
        Ok(vec![CertificateDer::from(data)])
    }
}
impl Files {
    pub fn load(&self, revocation_policy: super::super::pki::UnavailablePolicy) -> Result<Config> {
        let chain = certificates(&self.certificate)?;
        if chain.len() != 1 {
            return Err(Error::hs(
                8,
                "credential file must contain one leaf; use path files for CA certificates",
            ));
        }
        let certificate = chain[0].to_vec();
        let data = read(&self.key)?;
        let key = if data.starts_with(b"-----BEGIN") {
            PrivateKeyDer::from_pem_slice(&data).map_err(|e| Error::hs(8, e.to_string()))?
        } else {
            PrivateKeyDer::try_from(data).map_err(|e| Error::hs(8, e))?
        };
        let mut path = Vec::new();
        for file in &self.path {
            path.extend(certificates(file)?.into_iter().map(|c| c.to_vec()));
        }
        if path.len() > 4 {
            return Err(Error::hs(9, "certificate path exceeds four intermediates"));
        }
        let identity = Identity::new(certificate, key, path)?;
        let mut roots = Vec::new();
        for file in &self.authorities {
            roots.extend(certificates(file)?);
        }
        let trust = Arc::new(TrustStore::new(roots).map_err(|e| Error::hs(9, e.to_string()))?);
        let mut policy = Policy::new(trust);
        if !self.crls.is_empty() {
            let mut crls = Vec::new();
            for file in &self.crls {
                let data = read(file)?;
                if data.starts_with(b"-----BEGIN") {
                    for crl in CertificateRevocationListDer::pem_slice_iter(&data) {
                        crls.push(crl.map_err(|e| Error::hs(9, e.to_string()))?.to_vec());
                    }
                } else {
                    crls.push(data);
                }
            }
            policy.revocation = Some(Arc::new(
                RevocationChecker::new(&crls, revocation_policy)
                    .map_err(|e| Error::hs(9, e.to_string()))?,
            ));
        }
        Config::new(identity, policy)
    }
}
impl std::str::FromStr for AeTitle {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (oid, qualifier) = s
            .rsplit_once('/')
            .ok_or_else(|| Error::hs(1, "AE title must be AP-title-OID/AE-qualifier"))?;
        let arcs = oid
            .split('.')
            .map(|v| {
                v.parse::<u32>()
                    .map_err(|_| Error::hs(1, "invalid AP-title OID"))
            })
            .collect::<Result<Vec<_>>>()?;
        let qualifier = qualifier
            .parse::<u32>()
            .map_err(|_| Error::hs(1, "invalid AE qualifier"))?;
        if arcs.len() < 2
            || arcs[0] > 2
            || (arcs[0] < 2 && arcs[1] > 39)
            || qualifier > i32::MAX as u32
        {
            return Err(Error::hs(1, "invalid AE title"));
        }
        Ok(Self {
            ap_title: Oid(arcs),
            ae_qualifier: qualifier,
        })
    }
}
