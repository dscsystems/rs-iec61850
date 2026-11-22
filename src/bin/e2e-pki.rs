//! Create IEC 62351-4 Annex G CSRs and local test credentials.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use iec61850::asn1::{
    cons, oid_elem, prim, raw_tlv, Decoder, Oid, TAG_BIT_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET,
};
use iec61850::iec62351::e2e::{certificate_ae, AeTitle, Identity};
use iec61850::iec62351::pki::TrustStore;
use iec61850::x509;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::SignatureScheme;
use time::{Duration, OffsetDateTime};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USAGE: &str = "e2e-pki init  [-dir DIR] [-name COMMON_NAME] [-rsa]
e2e-pki issue -ae AP_TITLE/QUALIFIER [-dir DIR] [-name NAME] [-rsa]
e2e-pki csr   -ae AP_TITLE/QUALIFIER [-key KEY] [-out CSR] [-rsa]
e2e-pki show  CERTIFICATE";

fn new_key(rsa: bool) -> Result<KeyPair> {
    Ok(KeyPair::generate_for(if rsa {
        &rcgen::PKCS_RSA_SHA256
    } else {
        &rcgen::PKCS_ECDSA_P256_SHA256
    })?)
}

fn subject(ae: &AeTitle) -> Vec<u8> {
    cons(
        TAG_SEQUENCE,
        [cons(
            TAG_SET,
            [cons(
                TAG_SEQUENCE,
                [
                    oid_elem(TAG_OID, &Oid::from([2, 5, 4, 106])),
                    oid_elem(TAG_OID, &ae.oid()),
                ],
            )],
        )],
    )
    .encode()
}

fn full_tlv<'a>(decoder: &mut Decoder<'a>) -> Result<&'a [u8]> {
    let before = decoder.rest();
    decoder.skip()?;
    Ok(&before[..before.len() - decoder.rest().len()])
}

/// rcgen generates the other fields and extensions. Replace its placeholder
/// directory-string subject with the OID-valued Name and sign the new DER.
fn sign_with_names(
    der: &[u8],
    key: &KeyPair,
    subject_index: usize,
    ae: &AeTitle,
    issuer: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let envelope = Decoder::new(der).expect(TAG_SEQUENCE)?;
    let mut envelope = Decoder::new(envelope);
    let body = envelope.expect(TAG_SEQUENCE)?;
    let algorithm = full_tlv(&mut envelope)?;
    let mut entries = Decoder::new(body);
    let subject = subject(ae);
    let mut fields = Vec::new();
    while entries.more() {
        let original = full_tlv(&mut entries)?;
        fields.push(raw_tlv(
            match (fields.len(), issuer) {
                (3, Some(name)) => name,
                (index, _) if index == subject_index => &subject,
                _ => original,
            }
            .to_vec(),
        ));
    }
    if fields.len() <= subject_index {
        return Err("missing subject in generated DER".into());
    }
    let data = cons(TAG_SEQUENCE, fields).encode();
    let key = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            key.serialize_der(),
        )))?;
    let signer = key
        .choose_scheme(&[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ])
        .ok_or("unsupported signing algorithm")?;
    let mut signature = vec![0]; // No unused bits in the DER BIT STRING.
    signature.extend(signer.sign(&data)?);
    Ok(cons(
        TAG_SEQUENCE,
        [
            raw_tlv(data),
            raw_tlv(algorithm.to_vec()),
            prim(TAG_BIT_STRING, signature),
        ],
    )
    .encode())
}

fn pem(label: &str, der: &[u8]) -> String {
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in STANDARD.encode(der).as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn read_certificate(path: &Path) -> Result<Vec<u8>> {
    let data = fs::read(path)?;
    if data.starts_with(b"-----BEGIN") {
        Ok(CertificateDer::from_pem_slice(&data)?.to_vec())
    } else {
        Ok(data)
    }
}

fn write_new(path: &Path, data: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if let Err(e) = file.write_all(data) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("{}: {e}", path.display()).into());
    }
    Ok(())
}

fn write_pair(key: &KeyPair, key_path: &Path, public: &str, public_path: &Path) -> Result<()> {
    write_new(key_path, key.serialize_pem().as_bytes(), true)?;
    if let Err(error) = write_new(public_path, public.as_bytes(), false) {
        let _ = fs::remove_file(key_path);
        return Err(error);
    }
    println!("wrote {}", key_path.display());
    println!("wrote {}", public_path.display());
    Ok(())
}

fn ca_params(name: &str, now: OffsetDateTime) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(3650);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

fn init(dir: &Path, name: &str, rsa: bool) -> Result<()> {
    let mut directory = fs::DirBuilder::new();
    directory.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory.create(dir)?;
    let key = new_key(rsa)?;
    let cert = ca_params(name, OffsetDateTime::now_utc()).self_signed(&key)?;
    write_pair(&key, &dir.join("ca.key"), &cert.pem(), &dir.join("ca.pem"))
}

fn issue(dir: &Path, name: &str, ae: &AeTitle, rsa: bool) -> Result<()> {
    let path = Path::new(name);
    if !matches!(path.components().next(), Some(Component::Normal(_)))
        || path.file_name().and_then(|s| s.to_str()) != Some(name)
    {
        return Err("name must be a file base name".into());
    }
    let ca_der = read_certificate(&dir.join("ca.pem"))?;
    let ca = x509::parse(&ca_der)?;
    let ca_key = KeyPair::from_pem(&fs::read_to_string(dir.join("ca.key"))?)?;
    if ca_key.public_key_raw() != ca.spki_key {
        return Err("ca.key does not match ca.pem".into());
    }
    let now = OffsetDateTime::now_utc();
    let issuer = ca_params("placeholder", now).self_signed(&ca_key)?;
    let key = new_key(rsa)?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::ExplicitNoCa;
    params.not_before =
        (now - Duration::hours(1)).max(OffsetDateTime::from_unix_timestamp(ca.not_before)?);
    params.not_after =
        (now + Duration::days(365)).min(OffsetDateTime::from_unix_timestamp(ca.not_after)?);
    if params.not_after <= now || params.not_before > now {
        return Err("CA certificate is outside its validity period".into());
    }
    params.custom_extensions.push(annex_g_key_usage());
    let generated = params.signed_by(&key, &issuer, &ca_key)?;
    // An explicit v3 certificate has version, serial, signature algorithm,
    // issuer, validity and subject in that order.
    let der = sign_with_names(generated.der(), &ca_key, 5, ae, Some(&ca.subject))?;
    TrustStore::new(vec![CertificateDer::from(ca_der)])?.verify(
        &der,
        &[],
        None,
        std::time::SystemTime::now(),
    )?;
    Identity::new(
        der.clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        vec![],
    )?;
    write_pair(
        &key,
        &dir.join(format!("{name}.key")),
        &pem("CERTIFICATE", &der),
        &dir.join(format!("{name}.pem")),
    )
}

fn annex_g_key_usage() -> CustomExtension {
    // Named BIT STRING, with digitalSignature and keyAgreement set and
    // trailing unset bits omitted from the DER.
    let mut extension = CustomExtension::from_oid_content(
        &[2, 5, 29, 15],
        prim(TAG_BIT_STRING, vec![3, 0x88]).encode(),
    );
    extension.set_criticality(true);
    extension
}

fn csr(ae: &AeTitle, key_path: &Path, out: &Path, rsa: bool) -> Result<()> {
    let key = new_key(rsa)?;
    let mut params = CertificateParams::default();
    params.custom_extensions.push(annex_g_key_usage());
    let generated = params.serialize_request(&key)?;
    // CertificationRequestInfo starts with version and subject.
    let der = sign_with_names(generated.der(), &key, 1, ae, None)?;
    write_pair(&key, key_path, &pem("CERTIFICATE REQUEST", &der), out)
}

fn run(mut args: impl Iterator<Item = String>) -> Result<()> {
    let cmd = args.next().ok_or(USAGE)?;
    if matches!(cmd.as_str(), "-h" | "--help" | "help") {
        println!("{USAGE}");
        return Ok(());
    }
    if cmd == "show" {
        let path = args.next().ok_or("show requires a certificate")?;
        if args.next().is_some() {
            return Err("show takes one certificate".into());
        }
        let der = read_certificate(Path::new(&path))?;
        let cert = x509::parse(&der)?;
        let ae = certificate_ae(&der)?;
        println!(
            "subject AE title OID: {} (attribute type 2.5.4.106)",
            ae.oid()
        );
        println!(
            "valid: {} .. {}",
            OffsetDateTime::from_unix_timestamp(cert.not_before)?,
            OffsetDateTime::from_unix_timestamp(cert.not_after)?
        );
        return Ok(());
    }
    let mut dir = PathBuf::from("pki");
    let mut name = if cmd == "init" {
        "IEC 62351-4 test root".into()
    } else {
        "e2e".into()
    };
    let mut key = PathBuf::from("e2e.key");
    let mut out = PathBuf::from("e2e.csr");
    let mut rsa = false;
    let mut ae = None;
    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match (cmd.as_str(), flag.as_str()) {
            ("init" | "issue", "-dir" | "--dir") => dir = value()?.into(),
            ("init" | "issue", "-name" | "--name") => name = value()?,
            ("issue" | "csr", "-ae" | "--ae") => ae = Some(value()?.parse()?),
            ("csr", "-key" | "--key") => key = value()?.into(),
            ("csr", "-out" | "--out") => out = value()?.into(),
            ("init" | "issue" | "csr", "-rsa" | "--rsa") => rsa = true,
            _ => return Err(format!("unexpected argument {flag}\n{USAGE}").into()),
        }
    }
    match cmd.as_str() {
        "init" => init(&dir, &name, rsa),
        "issue" => issue(&dir, &name, &ae.ok_or("issue requires -ae")?, rsa),
        "csr" => csr(&ae.ok_or("csr requires -ae")?, &key, &out, rsa),
        _ => Err(USAGE.into()),
    }
}

fn main() -> std::process::ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e-pki: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
