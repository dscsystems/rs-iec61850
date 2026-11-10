//! What a server knows of a client asking to associate, for an
//! authenticator to decide on.

use std::net::SocketAddr;
use std::sync::Arc;

use super::{AcseIdentity, Result};

/// What a server knows of a client asking to associate.
#[derive(Debug, Clone, Default)]
pub struct AssociationRequest {
    pub peer: Option<SocketAddr>,
    /// The ACSE authentication value (the password mechanism), `None` when the
    /// client sent none.
    pub password: Option<String>,
    pub called: AcseIdentity,
    pub calling: AcseIdentity,
    /// The DER certificate chain the client presented on the TLS connection
    /// the association runs over, verified by the TLS layer; empty without
    /// TLS. An authenticator can combine the IEC 62351-3 certificate with a
    /// password or an allow-list.
    pub peer_certificates: Vec<Vec<u8>>,
    #[cfg(feature = "tls")]
    pub a_profile_peer: Option<crate::x509::Certificate>,
    #[cfg(feature = "e2e")]
    pub e2e_peer: Option<crate::iec62351::e2e::PeerSecurity>,
}

/// Decides whether to accept a client: `Ok` accepts, an error refuses with the
/// ACSE diagnostic authentication-failure, or authentication-required for
/// [`super::Error::AuthenticationRequired`].
pub type Authenticator = Arc<dyn Fn(&AssociationRequest) -> Result<()> + Send + Sync>;
