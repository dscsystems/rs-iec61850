#![allow(dead_code)]
use base64::Engine;
use iec61850::{
    asn1::{
        self, cons, raw_content, raw_tlv, Decoder, TAG_BIT_STRING, TAG_OID, TAG_SEQUENCE as SEQ,
        TAG_SET,
    },
    iec62351::{
        e2e::{AeTitle, Config, Identity, Policy},
        pki::TrustStore,
    },
};
use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    SignatureScheme,
};
use std::sync::Arc;

pub struct Pki {
    pub root: rcgen::Certificate,
    pub key: KeyPair,
}
#[derive(Clone)]
pub struct Credential {
    pub certificate: Vec<u8>,
    pub key: Vec<u8>,
    pub key_pem: String,
    pub ae: AeTitle,
}
impl Pki {
    pub fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = params.self_signed(&key).unwrap();
        Self { root, key }
    }
    pub fn issue(&self, qualifier: u32, rsa: bool) -> Credential {
        let key = KeyPair::generate_for(if rsa {
            &rcgen::PKCS_RSA_SHA256
        } else {
            &rcgen::PKCS_ECDSA_P256_SHA256
        })
        .unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyAgreement,
        ];
        let placeholder = params.signed_by(&key, &self.root, &self.key).unwrap();
        let ae = AeTitle {
            ap_title: asn1::Oid::from([1, 3, 6, 1, 4, 1, 55555]),
            ae_qualifier: qualifier,
        };
        let subject = cons(
            SEQ,
            [cons(
                TAG_SET,
                [cons(
                    SEQ,
                    [
                        asn1::oid_elem(TAG_OID, &asn1::Oid::from([2, 5, 4, 106])),
                        asn1::oid_elem(TAG_OID, &ae.oid()),
                    ],
                )],
            )],
        );
        let cert = iec61850::x509::parse(placeholder.der()).unwrap();
        let tbs = Decoder::new(&cert.signed.tbs).expect(SEQ).unwrap();
        let mut d = Decoder::new(tbs);
        let mut body = Vec::new();
        let mut field = 0;
        while d.more() {
            let before = d.rest();
            d.skip().unwrap();
            let full = &before[..before.len() - d.rest().len()];
            if field == 5 {
                body.extend(subject.encode());
            } else {
                body.extend(full);
            }
            field += 1;
        }
        let tbs = raw_content(SEQ, body).encode();
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let signer = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                self.key.serialize_der(),
            )))
            .unwrap();
        let signature = signer
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap()
            .sign(&tbs)
            .unwrap();
        let signature_bits = [vec![0], signature].concat();
        let certificate = cons(
            SEQ,
            [
                raw_tlv(tbs),
                raw_content(SEQ, cert.signed.algorithm),
                asn1::prim(TAG_BIT_STRING, signature_bits),
            ],
        )
        .encode();
        Credential {
            certificate,
            key: key.serialize_der(),
            key_pem: key.serialize_pem(),
            ae,
        }
    }
    pub fn policy(&self) -> Policy {
        Policy::new(Arc::new(
            TrustStore::new(vec![self.root.der().clone()]).unwrap(),
        ))
    }
    pub fn config(&self, credential: &Credential, edit: impl FnOnce(&mut Policy)) -> Arc<Config> {
        let mut policy = self.policy();
        edit(&mut policy);
        let identity = Identity::new(
            credential.certificate.clone(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(credential.key.clone())),
            Vec::new(),
        )
        .unwrap();
        Arc::new(Config::new(identity, policy).unwrap())
    }
}
pub fn pem(der: &[u8]) -> String {
    let b = base64::engine::general_purpose::STANDARD.encode(der);
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        b.as_bytes()
            .chunks(64)
            .map(|s| std::str::from_utf8(s).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    )
}

pub fn elements(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut d = Decoder::new(bytes);
    let mut out = Vec::new();
    while d.more() {
        let before = d.rest();
        d.skip().unwrap();
        out.push(before[..before.len() - d.rest().len()].to_vec());
    }
    out
}
pub fn resigned(
    request: &[u8],
    credential: &Credential,
    change: impl FnOnce(&mut Vec<Vec<u8>>),
    indefinite: bool,
) -> Vec<u8> {
    let mut fields = elements(Decoder::new(request).expect(SEQ).unwrap());
    let tbs = Decoder::new(&fields[1]).expect(SEQ).unwrap();
    let mut body = elements(tbs);
    let mut token = elements(Decoder::new(&body[0]).expect(SEQ).unwrap());
    change(&mut token);
    body[0] = raw_content(SEQ, token.concat()).encode();
    let mut signed = body.concat();
    if indefinite {
        signed.extend([0, 0]);
        fields[1] = [vec![0x30, 0x80], signed.clone()].concat();
    } else {
        fields[1] = raw_content(SEQ, signed.clone()).encode();
    }
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let key = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            credential.key.clone(),
        )))
        .unwrap();
    let scheme = if iec61850::x509::parse(&credential.certificate)
        .unwrap()
        .public_key
        .rsa_bits()
        .is_some()
    {
        SignatureScheme::RSA_PKCS1_SHA256
    } else {
        SignatureScheme::ECDSA_NISTP256_SHA256
    };
    let signature = key.choose_scheme(&[scheme]).unwrap().sign(&signed).unwrap();
    let sig_fields = elements(Decoder::new(&fields[2]).expect(SEQ).unwrap());
    fields[2] = cons(
        SEQ,
        [
            raw_tlv(sig_fields[0].clone()),
            asn1::prim(asn1::TAG_OCTET_STRING, signature),
        ],
    )
    .encode();
    raw_content(SEQ, fields.concat()).encode()
}
