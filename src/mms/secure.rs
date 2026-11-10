//! MMS integration of native IEC 62351-4 security.
use super::{
    transport::{self, BoxTransport, FramingReader, FramingWriter},
    AcceptOptions, AcseIdentity, Error, InitiateRequest, Options, Result, ServerConn,
};
use crate::{
    asn1::Oid,
    iec62351::e2e::{self, osi as env, AeTitle, Association, Config, Kind},
    osi::{acse, cotp, presentation, session},
};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone)]
pub struct ClientSecurity {
    pub config: Arc<Config>,
    pub peer: AeTitle,
}
#[derive(Debug, Clone)]
pub(crate) struct Security {
    pub association: Arc<Mutex<Association>>,
    pub mms: i64,
    pub acse: i64,
    pub e2e: i64,
}
impl Security {
    pub(crate) fn seal(&self, pdu: &[u8]) -> Result<Vec<u8>> {
        let mut a = self.association.lock().unwrap();
        let application = env::application(a.edition(), self.mms, pdu);
        Ok(a.seal(&application)?)
    }
    pub(crate) fn open(&self, pdu: &[u8]) -> Result<Vec<u8>> {
        let mut a = self.association.lock().unwrap();
        let application = a.open(pdu)?;
        Ok(env::parse_application(a.edition(), self.mms, &application)?)
    }
    pub(crate) fn control(&self, kind: Kind, error: Option<&e2e::Error>) -> Result<Vec<u8>> {
        let pdu = self.association.lock().unwrap().signed_control(
            kind,
            error.and_then(|e| e.diagnostic),
            &[],
        )?;
        let pdu = match kind {
            Kind::HandshakeAbort => env::alternative(&pdu, 0)?,
            Kind::DataAbort => env::alternative(&pdu, 1)?,
            Kind::ApplicationAbort => env::alternative(&pdu, 2)?,
            _ => pdu,
        };
        let tag = match kind {
            Kind::ReleaseRequest => 2,
            Kind::ReleaseResponse => 3,
            _ => 4,
        };
        Ok(acse::kernel_control(
            tag,
            0,
            &[env::external(self.e2e, &pdu)],
        ))
    }
    pub(crate) fn verify_release(&self, apdu: &[u8], response: bool) -> Result<()> {
        let info = acse::control_information(apdu, if response { 3 } else { 2 })?;
        let sec = single_external(&info, self.e2e)?;
        self.association.lock().unwrap().verify_control(
            if response {
                Kind::ReleaseResponse
            } else {
                Kind::ReleaseRequest
            },
            &sec,
        )?;
        Ok(())
    }
    pub(crate) fn verify_abort(&self, apdu: &[u8]) -> Result<()> {
        let info = acse::control_information(apdu, 4)?;
        let sec = single_external(&info, self.e2e)?;
        let (alt, pdu) = env::parse_alternative(&sec)?;
        let kind = match alt {
            0 => Kind::HandshakeAbort,
            1 => Kind::DataAbort,
            2 => Kind::ApplicationAbort,
            _ => return Err(Error::protocol("invalid security abort alternative")),
        };
        self.association
            .lock()
            .unwrap()
            .verify_control(kind, &pdu)?;
        Ok(())
    }
}
fn single_external(info: &[Vec<u8>], context: i64) -> Result<Vec<u8>> {
    if info.len() != 1 {
        return Err(Error::protocol("native mode requires one EXTERNAL"));
    }
    Ok(env::parse_external(&info[0], context)?)
}
fn split(
    ct: cotp::Conn<BoxTransport>,
    association: Association,
    mms: i64,
    acse: i64,
    e2e: i64,
) -> (FramingReader, FramingWriter) {
    let security = Security {
        association: Arc::new(Mutex::new(association)),
        mms,
        acse,
        e2e,
    };
    let (mut reader, mut writer) = transport::split(ct, mms, acse);
    reader.security = Some(security.clone());
    writer.security = Some(security);
    (reader, writer)
}

pub(crate) async fn client_handshake(
    mut ct: cotp::Conn<BoxTransport>,
    opts: &Options,
    security: &ClientSecurity,
    init: &InitiateRequest,
    tls_peer_certificate: Option<&[u8]>,
) -> Result<(FramingReader, FramingWriter, InitiateRequest, AcseIdentity)> {
    let mut association = Association::client(security.config.clone(), security.peer.clone());
    let called = if opts.called.is_empty() {
        security.peer.acse()
    } else {
        opts.called.clone()
    };
    let calling = if opts.calling.is_empty() {
        security.config.identity.ae.acse()
    } else {
        opts.calling.clone()
    };
    if AeTitle::from_acse(&called) != Some(security.peer.clone())
        || AeTitle::from_acse(&calling) != Some(security.config.identity.ae.clone())
    {
        return Err(Error::protocol(
            "E2E ACSE identities differ from configured credentials",
        ));
    }
    let request = association.handshake_request(&env::application(
        association.edition(),
        3,
        &super::pdu::encode_initiate_request(init),
    ))?;
    let aarq = acse::kernel_aarq(
        &e2e::application_context(),
        &called,
        &calling,
        &[env::external(5, &request)],
    );
    let cp = presentation::build_cp_e2e(&aarq);
    let response = match session::connect_client(&mut ct, &[], &[], &cp).await {
        Ok(response) => response,
        Err(crate::osi::Error::Refused { user_data, .. }) => {
            let aare = presentation::parse_cpr_user_data(&user_data)?;
            let result = acse::parse_aare(&aare)?;
            if !result.user_information.is_empty() {
                let sec = single_external(&result.user_information, 5)?;
                let (alt, pdu) = env::parse_alternative(&sec)?;
                let kind = match alt {
                    2 => Kind::ApplicationReject,
                    3 => Kind::HandshakeReject,
                    _ => return Err(Error::protocol("invalid rejecting handshake alternative")),
                };
                let diagnostic = association.verify_control(kind, &pdu)?;
                return Err(Error::E2E(e2e::Error::hs(
                    diagnostic.unwrap_or(0),
                    "peer rejected E2E association",
                )));
            }
            return Err(Error::Rejected(result.diagnostic));
        }
        Err(e) => return Err(e.into()),
    };
    presentation::check_e2e_cpa(&response)?;
    let aare = presentation::parse_cp_user_data(&response)?;
    let result = acse::parse_aare(&aare)?;
    if !result.accepted {
        return Err(Error::Rejected(result.diagnostic));
    }
    if result.application_context != Some(e2e::application_context()) {
        return Err(Error::protocol("native application context mismatch"));
    }
    let responding = if result.responding.is_empty() {
        called
    } else {
        result.responding
    };
    let peer = AeTitle::from_acse(&responding)
        .ok_or_else(|| Error::protocol("responding AE title missing"))?;
    let sec = single_external(&result.user_information, 5)?;
    let (alt, pdu) = env::parse_alternative(&sec)?;
    if alt != 1 {
        return Err(Error::protocol("server did not send HandshakeAcc"));
    }
    let application = match association.process_handshake_accept(&pdu, &peer) {
        Ok(application) => application,
        Err(error) => {
            let state = Security {
                association: Arc::new(Mutex::new(association)),
                mms: 3,
                acse: 1,
                e2e: 5,
            };
            if let Ok(abort) = state.control(Kind::HandshakeAbort, Some(&error)) {
                let pdu = presentation::wrap_abort(1, &abort);
                let _ = session::abort(&mut ct, &pdu).await;
            }
            return Err(error.into());
        }
    };
    if tls_peer_certificate.is_some_and(|tls| {
        association
            .peer_security()
            .is_some_and(|peer| peer.certificate == tls)
    }) {
        return Err(Error::protocol("TLS and E2E peer certificates must differ"));
    }
    let mms = env::parse_application(association.edition(), 3, &application)?;
    let negotiated = super::pdu::parse_initiate_response(&mms)?;
    let (reader, writer) = split(ct, association, 3, 1, 5);
    Ok((reader, writer, negotiated, responding))
}

pub(crate) fn is_native(context: Option<&Oid>, options: &AcceptOptions) -> bool {
    context == Some(&e2e::application_context())
        || (options.e2e.as_ref().is_some_and(|c| c.accept_t100_context)
            && context == Some(&Oid::from([1, 0, 62351, 4, 1, 2, 1, 1])))
}
async fn refuse(
    ct: &mut cotp::Conn<BoxTransport>,
    cp: &presentation::Cp,
    context: &Oid,
    identity: &AcseIdentity,
    diagnostic: i64,
    information: &[Vec<u8>],
) -> Result<()> {
    let aare = acse::kernel_aare(context, false, diagnostic, identity, information);
    session::refuse(
        ct,
        &presentation::build_e2e_answer(&cp.called_psel, &cp.contexts, &aare, false),
    )
    .await?;
    Ok(())
}
pub(crate) async fn server_handshake(
    mut ct: cotp::Conn<BoxTransport>,
    peer: Option<SocketAddr>,
    opts: &AcceptOptions,
    res: session::AcceptResult,
    cp: presentation::Cp,
    areq: acse::AarqRequest,
) -> Result<ServerConn> {
    let context = areq
        .application_context
        .clone()
        .unwrap_or_else(e2e::application_context);
    let Some(config) = &opts.e2e else {
        refuse(&mut ct, &cp, &context, &AcseIdentity::default(), 2, &[]).await?;
        return Err(Error::AssociationRejected("E2E not enabled".into()));
    };
    let identity = config.identity.ae.acse();
    if !is_native(areq.application_context.as_ref(), opts) {
        refuse(&mut ct, &cp, &context, &identity, 2, &[]).await?;
        return Err(Error::AssociationRejected("E2E required".into()));
    }
    let neg = presentation::negotiate(&cp.contexts);
    let security_context = presentation::e2e_context(&cp.contexts);
    let calling = AeTitle::from_acse(&areq.calling);
    let mut context_ids = std::collections::HashSet::new();
    let invalid_contexts = cp
        .contexts
        .iter()
        .any(|c| c.id <= 0 || c.id % 2 != 1 || !context_ids.insert(c.id));
    let invalid = invalid_contexts
        || cp.user_context != neg.acse
        || areq.non_kernel
        || !neg.has_acse()
        || !neg.has_mms()
        || security_context.is_none()
        || calling.is_none()
        || (!areq.called.is_empty()
            && AeTitle::from_acse(&areq.called) != Some(config.identity.ae.clone()));
    if invalid {
        refuse(&mut ct, &cp, &context, &identity, 1, &[]).await?;
        return Err(Error::AssociationRejected(
            "invalid native ACSE context or AE identity".into(),
        ));
    }
    let security_context = security_context.unwrap();
    let mut association = Association::server(config.clone());
    let request = match single_external(&areq.user_information, security_context) {
        Ok(request) => request,
        Err(error) => {
            refuse(&mut ct, &cp, &context, &identity, 1, &[]).await?;
            return Err(error);
        }
    };
    let application = match association.process_handshake_request(&request, calling.unwrap()) {
        Ok(application) => application,
        Err(error) => {
            let sec = association.signed_control(Kind::HandshakeReject, error.diagnostic, &[])?;
            let info = env::external(security_context, &env::alternative(&sec, 3)?);
            refuse(&mut ct, &cp, &context, &identity, 1, &[info]).await?;
            return Err(error.into());
        }
    };
    if opts.peer_certificates.first().is_some_and(|tls| {
        association
            .peer_security()
            .is_some_and(|peer| &peer.certificate == tls)
    }) {
        let error = e2e::Error::hs(8, "TLS and E2E peer certificates must differ");
        let sec = association.signed_control(Kind::HandshakeReject, error.diagnostic, &[])?;
        refuse(
            &mut ct,
            &cp,
            &context,
            &identity,
            1,
            &[env::external(security_context, &env::alternative(&sec, 3)?)],
        )
        .await?;
        return Err(error.into());
    }
    if let Some(auth) = &opts.authenticate {
        let request = super::AssociationRequest {
            peer,
            password: None,
            called: areq.called.clone(),
            calling: areq.calling.clone(),
            peer_certificates: opts.peer_certificates.clone(),
            a_profile_peer: None,
            e2e_peer: association.peer_security().cloned(),
        };
        if let Err(error) = auth(&request) {
            let reject = association.signed_control(Kind::ApplicationReject, None, &[])?;
            refuse(
                &mut ct,
                &cp,
                &context,
                &identity,
                1,
                &[env::external(
                    security_context,
                    &env::alternative(&reject, 2)?,
                )],
            )
            .await?;
            return Err(error);
        }
    }
    let initiation = env::parse_application(association.edition(), neg.mms, &application)
        .map_err(Error::from)
        .and_then(|mms| super::pdu::parse_initiate_request(&mms));
    let proposed = match initiation {
        Ok(proposed) => proposed,
        Err(error) => {
            let initiation_error = crate::asn1::cons(super::pdu::TAG_INITIATE_ERROR, []).encode();
            let reject = association.signed_control(
                Kind::ApplicationReject,
                None,
                &env::application(association.edition(), neg.mms, &initiation_error),
            )?;
            refuse(
                &mut ct,
                &cp,
                &context,
                &identity,
                1,
                &[env::external(
                    security_context,
                    &env::alternative(&reject, 2)?,
                )],
            )
            .await?;
            return Err(error);
        }
    };
    let answer = super::server_conn::clamp_initiate(
        &opts
            .initiate
            .clone()
            .unwrap_or_else(InitiateRequest::server_default),
        &proposed,
    );
    let accepted = association.handshake_accept(&env::application(
        association.edition(),
        neg.mms,
        &super::pdu::encode_initiate_response(&answer),
    ))?;
    let aare = acse::kernel_aare(
        &context,
        true,
        0,
        &identity,
        &[env::external(
            security_context,
            &env::alternative(&accepted, 1)?,
        )],
    );
    let cpa = presentation::build_e2e_answer(&cp.called_psel, &cp.contexts, &aare, true);
    session::reply(&mut ct, res.called_ssel.as_deref().unwrap_or(&[]), &cpa).await?;
    let (reader, mut writer) = split(ct, association, neg.mms, neg.acse, security_context);
    writer.write_timeout = Some(
        opts.write_timeout
            .unwrap_or(std::time::Duration::from_secs(30)),
    );
    super::server_conn::established(reader, writer, peer, areq, proposed, answer)
}
