//! The subset of MMS (ISO 9506) required by IEC 61850-8-1: the `Data` value
//! model, PDU codecs, and client and server connections carrying the
//! confirmed and unconfirmed service set used by ACSI.
//!
//! Most applications only touch [`Value`] and reach the rest through
//! [`crate::client`] and [`crate::server`]. Direct use of this module is for
//! tooling and for services the ACSI layer does not wrap.

mod altaccess;
mod client_ext;
mod conn;
mod errors;
mod pdu;
mod report;
mod server_conn;
mod server_ext;
mod services;
mod transport;
mod typespec;
mod value;
mod value_codec;

pub use altaccess::{
    access_path, alternate_access_element, parse_alternate_access, AccessStep, ListMember,
};
pub use client_ext::{
    encode_status_response, logical, parse_file_name, parse_file_rename, physical,
    JournalStatus, ObtainSource, ServerStatus,
};
pub use conn::{AcseIdentity, ApplicationContext, Conn, HandlerId, Options, Outstanding, State};
pub use errors::{DataAccessError, Error, ErrorClass, Result, ServiceError};
pub use pdu::{
    encode_initiate_request, encode_initiate_response, parse_initiate_request,
    parse_initiate_response, service, InitiateRequest, ServiceSupport, MMS_MAX,
};
pub use report::InformationReport;
pub use server_conn::{
    accept_conn, accept_conn_opts, AcceptOptions, Handler, Request, ServerConn,
};
pub use server_ext::{AssociationRequest, Authenticator};
pub use services::{
    FileEntry, JournalEntry, JournalVariable, ObjectClass, VarRef,
};
pub use transport::{BoxTransport, Transport};
pub use typespec::{decode_type_spec, Component, TypeSpec};
pub use value::{TimeQuality, Type, Value};
pub use value_codec::{
    append_data, data_element, decode_access_result, decode_data, encode_data,
};
