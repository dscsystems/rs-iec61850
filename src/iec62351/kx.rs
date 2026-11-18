//! The key exchange groups of the TLS profile.
//!
//! rustls provides P-256, P-384, X25519MLKEM768 and SecP256r1MLKEM768. This
//! module adds P-521 (which the Go reference offers by default) and
//! SecP384r1MLKEM1024 (which Go offers on request), both on aws-lc-rs.

use rustls::crypto::aws_lc_rs::kx_group;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved, ProtocolVersion};

/// A key exchange group the profile can offer and accept
/// ([`Options::kx_groups`](super::Options::kx_groups)).
///
/// The hybrids combine ECDHE with ML-KEM
/// ([RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html)). They exist
/// in TLS 1.3 only, and protect the key exchange, not the certificate
/// signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KxGroup {
    /// secp256r1, ECDHE.
    P256,
    /// secp384r1, ECDHE.
    P384,
    /// secp521r1, ECDHE.
    P521,
    /// X25519MLKEM768 (TLS 1.3).
    X25519MlKem768,
    /// SecP256r1MLKEM768 (TLS 1.3).
    P256MlKem768,
    /// SecP384r1MLKEM1024 (TLS 1.3).
    P384MlKem1024,
}

/// The groups of the profile when [`Options::kx_groups`](super::Options::kx_groups)
/// is empty, in order of preference: classical ECDHE only, as Go's
/// `iec62351.Curves`.
pub const DEFAULT_KX_GROUPS: &[KxGroup] = &[KxGroup::P256, KxGroup::P384, KxGroup::P521];

impl KxGroup {
    /// The TLS name of the group.
    pub fn named_group(self) -> NamedGroup {
        self.supported().name()
    }

    /// Whether the group is a post-quantum hybrid, usable in TLS 1.3 only.
    pub fn is_hybrid(self) -> bool {
        matches!(self, Self::X25519MlKem768 | Self::P256MlKem768 | Self::P384MlKem1024)
    }

    pub(crate) fn supported(self) -> &'static dyn SupportedKxGroup {
        match self {
            Self::P256 => kx_group::SECP256R1,
            Self::P384 => kx_group::SECP384R1,
            Self::P521 => SECP521R1,
            Self::X25519MlKem768 => kx_group::X25519MLKEM768,
            Self::P256MlKem768 => kx_group::SECP256R1MLKEM768,
            Self::P384MlKem1024 => SECP384R1MLKEM1024,
        }
    }
}

const INVALID_KEY_SHARE: Error = Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);

/// An uncompressed P-521 point: 0x04 and two 66-byte coordinates.
const P521_SHARE_LEN: usize = 133;
const P384_SHARE_LEN: usize = 97;
const MLKEM1024_ENCAPS_LEN: usize = 1568;
const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
/// SecP384r1MLKEM1024's code point (draft-ietf-tls-ecdhe-mlkem).
const SECP384R1MLKEM1024_ID: u16 = 0x11ed;

/// ECDHE on secp521r1.
pub(crate) static SECP521R1: &dyn SupportedKxGroup = &P521;

#[derive(Debug)]
struct P521;

impl SupportedKxGroup for P521 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        use aws_lc_rs::agreement;
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P521, &rng)
            .map_err(|_| Error::General("P-521 key generation failed".into()))?;
        let public = key
            .compute_public_key()
            .map_err(|_| Error::General("P-521 key generation failed".into()))?
            .as_ref()
            .to_vec();
        Ok(Box::new(ActiveP521 { key, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
}

struct ActiveP521 {
    key: aws_lc_rs::agreement::EphemeralPrivateKey,
    public: Vec<u8>,
}

impl ActiveKeyExchange for ActiveP521 {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        use aws_lc_rs::agreement;
        // TLS sends the uncompressed form only (RFC 8446 4.2.8.2, RFC 8422
        // 5.4.1); aws-lc checks that the point is on the curve.
        if peer.len() != P521_SHARE_LEN || peer[0] != 4 {
            return Err(INVALID_KEY_SHARE);
        }
        agreement::agree_ephemeral(
            self.key,
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P521, peer),
            INVALID_KEY_SHARE,
            |secret| Ok(SharedSecret::from(secret)),
        )
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp521r1
    }
}

/// SecP384r1MLKEM1024: the P-384 share first, then ML-KEM-1024's, in both
/// the key shares and the shared secret.
pub(crate) static SECP384R1MLKEM1024: &dyn SupportedKxGroup = &P384MlKem1024;

#[derive(Debug)]
struct P384MlKem1024;

impl SupportedKxGroup for P384MlKem1024 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let classical = kx_group::SECP384R1.start()?;
        let post_quantum = kx_group::MLKEM1024.start()?;
        let public = [classical.pub_key(), post_quantum.pub_key()].concat();
        Ok(Box::new(ActiveP384MlKem1024 { classical, post_quantum, public }))
    }

    fn start_and_complete(&self, client: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client.len() != P384_SHARE_LEN + MLKEM1024_ENCAPS_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (ecdh, mlkem) = client.split_at(P384_SHARE_LEN);
        let cl = kx_group::SECP384R1.start_and_complete(ecdh)?;
        let pq = kx_group::MLKEM1024.start_and_complete(mlkem)?;
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key: [cl.pub_key.as_slice(), &pq.pub_key].concat(),
            secret: SharedSecret::from([cl.secret.secret_bytes(), pq.secret.secret_bytes()].concat()),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::from(SECP384R1MLKEM1024_ID)
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        version == ProtocolVersion::TLSv1_3
    }
}

struct ActiveP384MlKem1024 {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    public: Vec<u8>,
}

impl ActiveKeyExchange for ActiveP384MlKem1024 {
    fn complete(self: Box<Self>, server: &[u8]) -> Result<SharedSecret, Error> {
        if server.len() != P384_SHARE_LEN + MLKEM1024_CIPHERTEXT_LEN {
            return Err(INVALID_KEY_SHARE);
        }
        let (ecdh, mlkem) = server.split_at(P384_SHARE_LEN);
        let cl = self.classical.complete(ecdh)?;
        let pq = self.post_quantum.complete(mlkem)?;
        Ok(SharedSecret::from([cl.secret_bytes(), pq.secret_bytes()].concat()))
    }

    /// Lets a client offering P-384 as well send a single P-384 share.
    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        Some((self.classical.group(), self.classical.pub_key()))
    }

    fn complete_hybrid_component(self: Box<Self>, server: &[u8]) -> Result<SharedSecret, Error> {
        self.classical.complete(server)
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::from(SECP384R1MLKEM1024_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both ends of each group derive one secret, and malformed shares are
    /// refused.
    #[test]
    fn groups_agree() {
        for g in [SECP521R1, SECP384R1MLKEM1024] {
            let client = g.start().unwrap();
            let server = g.start_and_complete(client.pub_key()).unwrap();
            assert_eq!(server.group, g.name());
            let secret = client.complete(&server.pub_key).unwrap();
            assert_eq!(secret.secret_bytes(), server.secret.secret_bytes());

            let client = g.start().unwrap();
            let short = &client.pub_key()[..client.pub_key().len() - 1];
            assert!(g.start_and_complete(short).is_err());
            assert!(client.complete(&server.pub_key[1..]).is_err());
        }
        // A compressed or off-curve P-521 point is refused.
        let client = SECP521R1.start().unwrap();
        let mut bad = client.pub_key().to_vec();
        bad[0] = 2;
        assert!(SECP521R1.start().unwrap().complete(&bad).is_err());
        bad[0] = 4;
        bad[P521_SHARE_LEN - 1] ^= 1;
        assert!(SECP521R1.start().unwrap().complete(&bad).is_err());
    }

    #[test]
    fn hybrid_layout() {
        let client = SECP384R1MLKEM1024.start().unwrap();
        assert_eq!(client.pub_key().len(), P384_SHARE_LEN + MLKEM1024_ENCAPS_LEN);
        // The classical share leads, and is the hybrid component.
        let (group, share) = client.hybrid_component().unwrap();
        assert_eq!(group, NamedGroup::secp384r1);
        assert_eq!(share, &client.pub_key()[..P384_SHARE_LEN]);
        assert_eq!(u16::from(SECP384R1MLKEM1024.name()), 0x11ed);
        assert!(!SECP384R1MLKEM1024.usable_for_version(ProtocolVersion::TLSv1_2));
        assert!(SECP521R1.usable_for_version(ProtocolVersion::TLSv1_2));
    }
}
