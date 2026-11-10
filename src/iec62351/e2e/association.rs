use super::{
    codec::{self, AlgorithmIdentifier, Kind, Signed, Token1, Token2, Token3, Transfer},
    crypto::{self, Dh},
    *,
};
use crate::{asn1::BitString, x509};
use p256::elliptic_curve::zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Requested,
    Established,
    Releasing,
    Closed,
}
#[derive(Debug, Clone)]
pub struct PeerSecurity {
    pub ae: AeTitle,
    pub certificate: Vec<u8>,
    pub association_id: String,
    pub group: Group,
    pub icv: IcvAlgorithm,
    pub validated_at: SystemTime,
}
#[derive(Debug, Default)]
struct Direction {
    key: Vec<u8>,
    last: Option<(SystemTime, i64)>,
    messages: u64,
}
impl Drop for Direction {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
fn set_key(key: &mut Vec<u8>, new: Vec<u8>) {
    key.zeroize();
    *key = new;
}

/// One E2E association, serialized by its environment. Receive and transmit
/// key epochs advance independently during the rekey acknowledgement.
pub struct Association {
    config: Arc<Config>,
    role: Role,
    state: State,
    peer: Option<AeTitle>,
    peer_certificate: Option<Vec<u8>>,
    security: Option<PeerSecurity>,
    own_part: Option<String>,
    id: String,
    dh: Option<Dh>,
    peer_public: Vec<u8>,
    group: Group,
    algorithm: IcvAlgorithm,
    algorithm_id: AlgorithmIdentifier,
    request_tbs: Vec<u8>,
    request_token: Option<Token1>,
    salt: Vec<u8>,
    tx: Direction,
    rx: Direction,
    pending_rx: Vec<u8>,
    pending_tx: Vec<u8>,
    rekey_out: bool,
    rekey_started: Option<SystemTime>,
    rekey_wanted: bool,
    pending_change: bool,
    epoch_start: SystemTime,
    epoch: u64,
    request_sent: bool,
}
impl Association {
    pub fn client(config: Arc<Config>, peer: AeTitle) -> Self {
        Self::new(config, Role::Client, Some(peer))
    }
    pub fn server(config: Arc<Config>) -> Self {
        Self::new(config, Role::Server, None)
    }
    fn new(config: Arc<Config>, role: Role, peer: Option<AeTitle>) -> Self {
        let group = config.policy.dh_groups[0];
        let algorithm = config.policy.icv_algorithms[0];
        let algorithm_id = algorithm.id(config.policy.edition == Edition::Amendment2020
            && config.policy.corrections == Corrections::InForce);
        Self {
            config,
            role,
            state: State::Idle,
            peer,
            peer_certificate: None,
            security: None,
            own_part: None,
            id: String::new(),
            dh: None,
            peer_public: Vec::new(),
            group,
            algorithm,
            algorithm_id,
            request_tbs: Vec::new(),
            request_token: None,
            salt: Vec::new(),
            tx: Direction::default(),
            rx: Direction::default(),
            pending_rx: Vec::new(),
            pending_tx: Vec::new(),
            rekey_out: false,
            rekey_started: None,
            rekey_wanted: false,
            pending_change: false,
            epoch_start: SystemTime::UNIX_EPOCH,
            epoch: 0,
            request_sent: false,
        }
    }
    pub fn peer_security(&self) -> Option<&PeerSecurity> {
        self.security.as_ref()
    }
    pub fn association_id(&self) -> &str {
        &self.id
    }
    pub fn established(&self) -> bool {
        self.state == State::Established
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn edition(&self) -> Edition {
        self.config.policy.edition
    }
    fn now(&self) -> SystemTime {
        (self.config.policy.now)()
    }
    fn event(&self, code: &'static str, error: Option<Error>) {
        if let Some(handler) = &self.config.policy.on_event {
            handler(&Event {
                code,
                association_id: self.id.clone(),
                error,
            });
        }
    }
    fn token(&self, public: Vec<u8>, icv: Vec<AlgorithmIdentifier>) -> Token1 {
        let id = &self.config.identity;
        Token1 {
            sig: id.signature.clone(),
            certificate: id.certificate.clone(),
            path: id.path.clone(),
            version: None,
            id: self.id.clone(),
            group: self.group.code(),
            public,
            hmac: crypto::hmac_id(),
            time: codec::format_time(self.now()),
            icv,
            aea: false,
            encryption: false,
            confidentiality: BitString::from_u32(
                u32::from(self.config.tls_protected),
                if self.config.tls_protected { 1 } else { 0 },
            ),
            attribute: None,
        }
    }
    pub fn handshake_request(&mut self, application: &[u8]) -> Result<Vec<u8>> {
        if self.role != Role::Client || self.state != State::Idle {
            return Err(Error::hs(1, "unexpected handshake request"));
        }
        let dh = Dh::generate(self.group)?;
        self.id = self.config.allocate(self.peer.as_ref().unwrap())?;
        self.own_part = Some(self.id.clone());
        let corrected = self.config.policy.edition == Edition::Amendment2020
            && self.config.policy.corrections == Corrections::InForce;
        let token = self.token(
            dh.public(),
            self.config
                .policy
                .icv_algorithms
                .iter()
                .map(|a| a.id(corrected))
                .collect(),
        );
        let pdu = Signed::encode(
            Kind::HandshakeRequest,
            self.config.protected_protocols.first().map(String::as_str),
            token.element(self.edition()),
            application,
            None,
            &self.config.identity,
        )?;
        self.request_tbs = Signed::parse(&pdu, Kind::HandshakeRequest, self.edition())?.tbs;
        self.request_token = Some(token);
        self.dh = Some(dh);
        self.state = State::Requested;
        Ok(pdu)
    }
    fn check_peer(&self, signed: &Signed, peer: &AeTitle) -> Result<()> {
        let (algorithm, certificate, path) = if let Some(t) = &signed.token1 {
            (&t.sig, &t.certificate, &t.path)
        } else {
            let t = signed.token3.as_ref().unwrap();
            (&t.sig, &t.certificate, &t.path)
        };
        if algorithm != &signed.algorithm {
            return Err(Error::alarm(
                Phase::Handshake,
                "signature algorithm mismatch",
            ));
        }
        if certificate.len() > 8192 {
            return Err(Error::hs(8, "certificate exceeds profile limit"));
        }
        let cert = x509::parse(certificate).map_err(|e| Error::hs(8, e.to_string()))?;
        crypto::verify(&cert, algorithm, &signed.tbs, &signed.signature)?;
        let ae = crypto::profile(certificate, self.config.policy.accept_any_ae_attribute)?;
        if &ae != peer {
            return Err(Error::alarm(
                Phase::Handshake,
                "certificate AE differs from ACSE identity",
            ));
        }
        let now_seconds = crate::time_util::unix_parts(self.now()).0;
        if now_seconds < cert.not_before || now_seconds > cert.not_after {
            return Err(Error::hs(8, "certificate expired or not yet valid"));
        }
        self.config
            .policy
            .trust
            .verify(
                certificate,
                path,
                self.config.policy.revocation.as_deref(),
                self.now(),
            )
            .map_err(|e| {
                Error::hs(
                    if matches!(e, crate::iec62351::Error::Revoked) {
                        8
                    } else {
                        9
                    },
                    e.to_string(),
                )
            })?;
        Ok(())
    }
    fn check_token(&self, t: &Token1, offering: bool) -> Result<SystemTime> {
        if !codec::version_valid(&t.version, offering) {
            return Err(Error::hs(4, "unexpected version"));
        }
        let time = codec::parse_time(&t.time)?;
        if !codec::fresh(time, self.now(), self.config.policy.freshness) {
            return Err(Error::hs(10, "time outside freshness window"));
        }
        let hmac_ok = t.hmac.oid == crypto::hmac_id().oid && t.hmac.null_or_absent();
        let sha256_ok = self.config.policy.accept_sha256_hmac_id
            && t.hmac.oid.arcs() == [2, 16, 840, 1, 101, 3, 4, 2, 1]
            && t.hmac.null_or_absent();
        if !hmac_ok && !sha256_ok {
            return Err(Error::hs(5, "unsupported key derivation hash"));
        }
        if t.aea {
            return Err(Error::hs(
                if offering { 17 } else { 23 },
                "authenticated encryption not implemented",
            ));
        }
        if t.encryption || t.confidentiality.bit(1) {
            return Err(Error::hs(6, "encryption not required"));
        }
        if t.attribute.is_some() {
            if self.config.policy.require_authorization {
                return Err(Error::hs(
                    16,
                    "attribute certificate validation not implemented",
                ));
            }
            self.event("attribute-certificate-ignored", None);
        }
        Ok(time)
    }
    pub fn process_handshake_request(&mut self, bytes: &[u8], calling: AeTitle) -> Result<Vec<u8>> {
        let result = self.process_handshake_request_inner(bytes, calling);
        if let Err(error) = &result {
            self.close();
            self.event("security-error", Some(error.clone()));
        }
        result
    }
    fn process_handshake_request_inner(
        &mut self,
        bytes: &[u8],
        calling: AeTitle,
    ) -> Result<Vec<u8>> {
        if self.role != Role::Server || self.state != State::Idle {
            return Err(Error::hs(1, "unexpected handshake request"));
        }
        self.peer = Some(calling.clone());
        let signed = Signed::parse(bytes, Kind::HandshakeRequest, self.edition())?;
        self.check_peer(&signed, &calling)?;
        if !self
            .config
            .protected_protocols
            .iter()
            .any(|p| Some(p) == signed.protocol.as_ref())
        {
            return Err(Error::hs(2, "protected protocol not supported"));
        }
        let t = signed.token1.as_ref().unwrap();
        let time = self.check_token(t, true)?;
        if !valid_part(&t.id) {
            return Err(Error::hs(1, "client association identifier"));
        }
        let group = Group::from_code(t.group)?;
        if !self.config.policy.dh_groups.contains(&group) {
            return Err(Error::hs(11, "DH group not accepted"));
        }
        let mut selected = None;
        for a in &t.icv {
            if let Some(alg) = IcvAlgorithm::from_id(a) {
                if self.config.policy.icv_algorithms.contains(&alg) {
                    selected = Some((alg, a.clone()));
                    break;
                }
            }
        }
        let (algorithm, id) = selected.ok_or_else(|| Error::hs(13, "no shared ICV algorithm"))?;
        let dh = Dh::generate(group)?;
        let mut check = dh.shared(&t.public)?;
        check.zeroize();
        self.config.remember(
            &calling,
            &t.time,
            &t.id,
            time + self.config.policy.freshness,
        )?;
        self.own_part = Some(self.config.allocate(&calling)?);
        self.id = format!("{}:{}", t.id, self.own_part.as_ref().unwrap());
        self.group = group;
        self.algorithm = algorithm;
        self.algorithm_id = id;
        self.peer_public = t.public.clone();
        self.peer_certificate = Some(t.certificate.clone());
        self.request_tbs = signed.tbs;
        self.request_token = Some(t.clone());
        self.dh = Some(dh);
        self.state = State::Requested;
        self.security = Some(PeerSecurity {
            ae: calling,
            certificate: t.certificate.clone(),
            association_id: self.id.clone(),
            group,
            icv: algorithm,
            validated_at: self.now(),
        });
        Ok(signed.application)
    }
    fn handshake_keys(&mut self, response_tbs: &[u8], peer_public: &[u8]) -> Result<()> {
        let init = match self.config.policy.chain_init {
            ChainInit::ZeroOctet => vec![0],
            ChainInit::Empty => Vec::new(),
            ChainInit::ZeroHash => vec![0; 32],
        };
        self.salt = crypto::hash(&[response_tbs, &crypto::hash(&[&self.request_tbs, &init])]);
        let mut secret = self.dh.as_ref().unwrap().shared(peer_public)?;
        let (client, server) = crypto::derive(self.algorithm, &self.salt, &secret);
        secret.zeroize();
        match self.role {
            Role::Client => {
                set_key(&mut self.tx.key, client);
                set_key(&mut self.rx.key, server);
            }
            Role::Server => {
                set_key(&mut self.tx.key, server);
                set_key(&mut self.rx.key, client);
            }
        }
        self.request_tbs.clear();
        self.state = State::Established;
        self.epoch_start = self.now();
        self.event("handshake-accepted", None);
        Ok(())
    }
    pub fn handshake_accept(&mut self, application: &[u8]) -> Result<Vec<u8>> {
        if self.role != Role::Server || self.state != State::Requested {
            return Err(Error::hs(1, "unexpected handshake accept"));
        }
        let mut token = self.token(
            self.dh.as_ref().unwrap().public(),
            vec![self.algorithm_id.clone()],
        );
        let request = self.request_token.as_ref().unwrap();
        token.hmac = request.hmac.clone();
        token.confidentiality = request.confidentiality.clone();
        let pdu = Signed::encode(
            Kind::HandshakeAccept,
            None,
            token.element(self.edition()),
            application,
            None,
            &self.config.identity,
        )?;
        let parsed = Signed::parse(&pdu, Kind::HandshakeAccept, self.edition())?;
        self.handshake_keys(&parsed.tbs, &self.peer_public.clone())?;
        Ok(pdu)
    }
    pub fn process_handshake_accept(
        &mut self,
        bytes: &[u8],
        responding: &AeTitle,
    ) -> Result<Vec<u8>> {
        let result = self.process_handshake_accept_inner(bytes, responding);
        if let Err(error) = &result {
            self.close();
            self.event("security-error", Some(error.clone()));
        }
        result
    }
    fn process_handshake_accept_inner(
        &mut self,
        bytes: &[u8],
        responding: &AeTitle,
    ) -> Result<Vec<u8>> {
        if self.role != Role::Client
            || self.state != State::Requested
            || self.peer.as_ref() != Some(responding)
        {
            return Err(Error::hs(1, "unexpected handshake acceptance or identity"));
        }
        let signed = Signed::parse(bytes, Kind::HandshakeAccept, self.edition())?;
        self.check_peer(&signed, responding)?;
        let t = signed.token1.as_ref().unwrap();
        let time = self.check_token(t, false)?;
        let (client, server) =
            t.id.split_once(':')
                .ok_or_else(|| Error::hs(1, "server association identifier"))?;
        if client != self.own_part.as_deref().unwrap() || !valid_part(server) {
            return Err(Error::hs(1, "association identifier mismatch"));
        }
        if t.group != self.group.code() {
            return Err(Error::hs(12, "server selected a different DH group"));
        }
        if t.icv.len() != 1 {
            return Err(Error::hs(26, "exactly one ICV algorithm required"));
        }
        let algorithm = IcvAlgorithm::from_id(&t.icv[0])
            .filter(|a| self.config.policy.icv_algorithms.contains(a))
            .ok_or_else(|| Error::hs(13, "unoffered ICV algorithm"))?;
        self.config.remember(
            responding,
            &t.time,
            &t.id,
            time + self.config.policy.freshness,
        )?;
        self.algorithm = algorithm;
        self.algorithm_id = t.icv[0].clone();
        self.id = t.id.clone();
        self.handshake_keys(&signed.tbs, &t.public)?;
        self.peer_public = t.public.clone();
        self.id = t.id.clone();
        self.peer_certificate = Some(t.certificate.clone());
        self.security = Some(PeerSecurity {
            ae: responding.clone(),
            certificate: t.certificate.clone(),
            association_id: self.id.clone(),
            group: self.group,
            icv: algorithm,
            validated_at: self.now(),
        });
        Ok(signed.application)
    }
    pub fn request_rekey(&mut self) {
        if self.role == Role::Client {
            self.rekey_wanted = true;
        } else {
            self.request_sent = false;
            self.rekey_wanted = true;
        }
    }
    pub fn rekey_overdue(&self, grace: Duration) -> bool {
        self.rekey_out
            && self
                .rekey_started
                .is_some_and(|start| self.now().duration_since(start).unwrap_or_default() > grace)
    }
    pub fn rekey_due(&self) -> bool {
        self.role == Role::Client
            && !self.rekey_out
            && (self.rekey_wanted
                || self
                    .now()
                    .duration_since(self.epoch_start)
                    .unwrap_or_default()
                    >= self.config.policy.rekey_interval
                || self.tx.messages >= self.config.policy.max_messages_per_key)
    }
    pub fn seal(&mut self, application: &[u8]) -> Result<Vec<u8>> {
        if !matches!(self.state, State::Established | State::Releasing) {
            return Err(Error::data(1, "association not established"));
        }
        if self.rekey_overdue(Duration::from_secs(30)) {
            self.close();
            return Err(Error::data(0, "rekey acknowledgement overdue"));
        }
        let now = self.now();
        let mut stamp = codec::millis(now);
        if let Some((last, _)) = self.tx.last {
            stamp = stamp.max(last);
        }
        let sequence = match self.tx.last {
            Some((last, n)) if last == stamp => n
                .checked_add(1)
                .ok_or_else(|| Error::data(8, "sequence exhausted"))?,
            _ => 0,
        };
        let new_dh = if self.rekey_due() {
            Some(Dh::generate(self.group)?)
        } else {
            None
        };
        let changed = self.role == Role::Server && self.pending_change;
        let request = self.role == Role::Server
            && !changed
            && !self.request_sent
            && (self.rekey_wanted
                || self.config.policy.rekey_request.is_some_and(|d| {
                    now.duration_since(self.epoch_start).unwrap_or_default() >= d
                }));
        let token = Token2 {
            version: None,
            id: self.id.clone(),
            time: codec::format_time(stamp),
            sequence,
            iv: None,
            rekey: new_dh.as_ref().map(Dh::public),
            request_rekey: request,
            changed_key: changed,
        };
        let tbp = Transfer::body(&token, application)?;
        let nonce = if self.algorithm == IcvAlgorithm::HmacSha256 {
            Vec::new()
        } else {
            crypto::random(12)?
        };
        let icv = self.algorithm.mac(&self.tx.key, &nonce, &tbp)?;
        let pdu = Transfer::encode(
            tbp.clone(),
            &self.algorithm_id,
            &nonce,
            icv,
            self.config.policy.authenticator,
        );
        self.tx.last = Some((stamp, sequence));
        self.tx.messages += 1;
        if let Some(dh) = new_dh {
            let mut secret = dh.shared(&self.peer_public)?;
            self.salt = crypto::hash(&[&tbp, &self.salt]);
            let (client, server) = crypto::derive(self.algorithm, &self.salt, &secret);
            secret.zeroize();
            self.dh = Some(dh);
            set_key(&mut self.tx.key, client);
            self.tx.messages = 0;
            set_key(&mut self.pending_rx, server);
            self.rekey_out = true;
            self.rekey_started = Some(now);
            self.rekey_wanted = false;
            self.event("rekey-started", None);
        }
        if changed {
            set_key(&mut self.tx.key, std::mem::take(&mut self.pending_tx));
            self.tx.messages = 0;
            self.pending_change = false;
            self.epoch += 1;
            self.epoch_start = now;
            self.request_sent = false;
            self.event("rekey-completed", None);
        }
        if request {
            self.rekey_wanted = false;
            self.request_sent = true;
        }
        Ok(pdu)
    }
    pub fn open(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        let result = self.open_inner(bytes);
        if let Err(error) = &result {
            self.close();
            self.event("security-error", Some(error.clone()));
        }
        result
    }
    fn open_inner(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        if !matches!(self.state, State::Established | State::Releasing) {
            return Err(Error::data(1, "association not established"));
        }
        let transfer =
            Transfer::parse(bytes, self.config.policy.authenticator).map_err(|mut e| {
                e.phase = Phase::Data;
                e
            })?;
        if IcvAlgorithm::from_id(&transfer.algorithm) != Some(self.algorithm) {
            return Err(Error::alarm(Phase::Data, "ICV algorithm mismatch"));
        }
        let expected = self
            .algorithm
            .mac(&self.rx.key, &transfer.nonce, &transfer.tbp)?;
        if !crypto::equal(&expected, &transfer.icv) {
            return Err(Error::alarm(Phase::Data, "invalid ICV"));
        }
        let t = &transfer.token;
        if !codec::version_valid(&t.version, false) {
            return Err(Error::data(2, "unexpected version"));
        }
        let time = codec::parse_time(&t.time).map_err(|_| Error::data(7, "invalid time"))?;
        if !codec::fresh(time, self.now(), self.config.policy.freshness) {
            return Err(Error::data(7, "time outside freshness window"));
        }
        if let Some((last, seq)) = self.rx.last {
            if time < last {
                return Err(Error::data(7, "time regressed"));
            }
            if time == last && t.sequence <= seq {
                return Err(Error::alarm(Phase::Data, "replayed transfer"));
            }
            if (time == last && seq.checked_add(1) != Some(t.sequence))
                || (time > last && t.sequence != 0)
            {
                return Err(Error::data(8, "invalid sequence number"));
            }
        } else if t.sequence != 0 {
            return Err(Error::data(8, "first sequence is not zero"));
        }
        if t.id != self.id || t.iv.is_some() {
            return Err(Error::data(1, "association ID or IV mismatch"));
        }
        match self.role {
            Role::Client => {
                if t.rekey.is_some() {
                    return Err(Error::data(1, "server sent DH rekey"));
                }
                if t.changed_key && !self.rekey_out {
                    return Err(Error::data(11, "unexpected changedKey"));
                }
            }
            Role::Server => {
                if t.changed_key || t.request_rekey {
                    return Err(Error::data(1, "client sent server-only key flags"));
                }
                if t.rekey.is_some() && self.pending_change {
                    return Err(Error::data(10, "rekey already pending"));
                }
            }
        }
        let pending = if let Some(public) = &t.rekey {
            let mut secret = self
                .dh
                .as_ref()
                .unwrap()
                .shared(public)
                .map_err(|_| Error::data(1, "invalid rekey public value"))?;
            let salt = crypto::hash(&[&transfer.tbp, &self.salt]);
            let keys = crypto::derive(self.algorithm, &salt, &secret);
            secret.zeroize();
            Some((salt, keys, public.clone()))
        } else {
            None
        };
        self.rx.last = Some((time, t.sequence));
        self.rx.messages += 1;
        if let Some((salt, (client, server), public)) = pending {
            self.salt = salt;
            set_key(&mut self.rx.key, client);
            self.rx.messages = 0;
            set_key(&mut self.pending_tx, server);
            self.peer_public = public;
            self.pending_change = true;
            self.event("rekey-started", None);
        }
        if self.role == Role::Client && t.changed_key {
            set_key(&mut self.rx.key, std::mem::take(&mut self.pending_rx));
            self.rx.messages = 0;
            self.rekey_out = false;
            self.rekey_started = None;
            self.epoch += 1;
            self.epoch_start = self.now();
            self.event("rekey-completed", None);
        }
        if self.role == Role::Client && t.request_rekey {
            self.rekey_wanted = true;
        }
        Ok(transfer.application)
    }
    fn token3(&self) -> Token3 {
        let identity = &self.config.identity;
        Token3 {
            sig: identity.signature.clone(),
            certificate: identity.certificate.clone(),
            path: identity.path.clone(),
            version: None,
            id: (!self.id.is_empty()).then(|| self.id.clone()),
            time: codec::format_time(self.now()),
        }
    }
    pub fn signed_control(
        &mut self,
        kind: Kind,
        diagnostic: Option<u8>,
        application: &[u8],
    ) -> Result<Vec<u8>> {
        if kind.handshake() {
            return Err(Error::hs(1, "use handshake methods"));
        }
        let diagnostic = diagnostic.map(|d| {
            if kind == Kind::DataAbort {
                d
            } else {
                self.config.policy.wire_diag(d)
            }
        });
        let pdu = Signed::encode(
            kind,
            None,
            self.token3().element(),
            application,
            diagnostic,
            &self.config.identity,
        )?;
        if kind == Kind::ReleaseRequest {
            if self.state != State::Established {
                return Err(Error::hs(1, "release before establishment"));
            }
            self.state = State::Releasing;
        }
        if matches!(
            kind,
            Kind::ReleaseResponse
                | Kind::HandshakeReject
                | Kind::ApplicationReject
                | Kind::HandshakeAbort
                | Kind::DataAbort
                | Kind::ApplicationAbort
        ) {
            self.close();
        }
        Ok(pdu)
    }
    pub fn verify_control(&mut self, kind: Kind, bytes: &[u8]) -> Result<Option<u8>> {
        let signed = Signed::parse(bytes, kind, self.edition())?;
        let t = signed
            .token3
            .as_ref()
            .ok_or_else(|| Error::hs(1, "control token missing"))?;
        if let Some(cert) = &self.peer_certificate {
            if cert != &t.certificate {
                return Err(Error::alarm(
                    Phase::Release,
                    "certificate changed since handshake",
                ));
            }
        }
        self.check_peer(
            &signed,
            self.peer
                .as_ref()
                .ok_or_else(|| Error::hs(1, "peer unknown"))?,
        )?;
        if !codec::version_valid(&t.version, false)
            || !codec::fresh(
                codec::parse_time(&t.time)?,
                self.now(),
                self.config.policy.freshness,
            )
        {
            return Err(Error::alarm(
                Phase::Release,
                "invalid control version or time",
            ));
        }
        if let Some(id) = &t.id {
            let client = self.id.split(':').next().unwrap_or("");
            if !self.id.is_empty() && id != &self.id && id != client {
                return Err(Error::alarm(
                    Phase::Release,
                    "control association identifier mismatch",
                ));
            }
        }
        match kind {
            Kind::ReleaseRequest if self.state == State::Established => {
                self.state = State::Releasing
            }
            Kind::ReleaseResponse if self.state == State::Releasing => self.state = State::Closed,
            Kind::ReleaseRequest | Kind::ReleaseResponse => {
                return Err(Error::alarm(Phase::Release, "unexpected release"))
            }
            _ => {
                self.state = State::Closed;
            }
        }
        if self.state == State::Closed {
            self.close();
        }
        Ok(signed.diagnostic.map(|d| {
            if kind == Kind::DataAbort {
                d
            } else {
                self.config.policy.read_diag(d)
            }
        }))
    }
}
fn valid_part(id: &str) -> bool {
    (1..=3).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit())
}
impl Association {
    /// Ends the association, erases traffic/ephemeral keys and returns its ID.
    pub fn close(&mut self) {
        self.state = State::Closed;
        self.tx.key.zeroize();
        self.tx.key.clear();
        self.rx.key.zeroize();
        self.rx.key.clear();
        self.pending_rx.zeroize();
        self.pending_rx.clear();
        self.pending_tx.zeroize();
        self.pending_tx.clear();
        self.dh.take();
        if let (Some(peer), Some(id)) = (&self.peer, self.own_part.take()) {
            self.config.release(peer, &id);
        }
    }
}
impl Drop for Association {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Debug for Association {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Association")
            .field("role", &self.role)
            .field("state", &self.state)
            .field("association_id", &self.id)
            .field("group", &self.group)
            .field("integrity", &self.algorithm)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}
