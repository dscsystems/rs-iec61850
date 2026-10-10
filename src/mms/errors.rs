/// DataAccessError codes (ISO 9506-2 `DataAccessError`).
///
/// These surface per-element failures inside read results as well as whole
/// service failures, so the type is both an enum and an [`std::error::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataAccessError {
    ObjectInvalidated,
    HardwareFault,
    TemporarilyUnavailable,
    ObjectAccessDenied,
    ObjectUndefined,
    InvalidAddress,
    TypeUnsupported,
    TypeInconsistent,
    ObjectAttributeInconsistent,
    ObjectAccessUnsupported,
    ObjectNonExistent,
    ObjectValueInvalid,
    /// A code outside the range this crate names.
    Other(u8),
}

impl DataAccessError {
    /// Returns the wire code.
    pub fn code(self) -> u8 {
        match self {
            DataAccessError::ObjectInvalidated => 0,
            DataAccessError::HardwareFault => 1,
            DataAccessError::TemporarilyUnavailable => 2,
            DataAccessError::ObjectAccessDenied => 3,
            DataAccessError::ObjectUndefined => 4,
            DataAccessError::InvalidAddress => 5,
            DataAccessError::TypeUnsupported => 6,
            DataAccessError::TypeInconsistent => 7,
            DataAccessError::ObjectAttributeInconsistent => 8,
            DataAccessError::ObjectAccessUnsupported => 9,
            DataAccessError::ObjectNonExistent => 10,
            DataAccessError::ObjectValueInvalid => 11,
            DataAccessError::Other(n) => n,
        }
    }

    /// Returns the error for a wire code.
    pub fn from_code(code: u8) -> DataAccessError {
        match code {
            0 => DataAccessError::ObjectInvalidated,
            1 => DataAccessError::HardwareFault,
            2 => DataAccessError::TemporarilyUnavailable,
            3 => DataAccessError::ObjectAccessDenied,
            4 => DataAccessError::ObjectUndefined,
            5 => DataAccessError::InvalidAddress,
            6 => DataAccessError::TypeUnsupported,
            7 => DataAccessError::TypeInconsistent,
            8 => DataAccessError::ObjectAttributeInconsistent,
            9 => DataAccessError::ObjectAccessUnsupported,
            10 => DataAccessError::ObjectNonExistent,
            11 => DataAccessError::ObjectValueInvalid,
            n => DataAccessError::Other(n),
        }
    }
}

impl std::fmt::Display for DataAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DataAccessError::ObjectInvalidated => "object-invalidated",
            DataAccessError::HardwareFault => "hardware-fault",
            DataAccessError::TemporarilyUnavailable => "temporarily-unavailable",
            DataAccessError::ObjectAccessDenied => "object-access-denied",
            DataAccessError::ObjectUndefined => "object-undefined",
            DataAccessError::InvalidAddress => "invalid-address",
            DataAccessError::TypeUnsupported => "type-unsupported",
            DataAccessError::TypeInconsistent => "type-inconsistent",
            DataAccessError::ObjectAttributeInconsistent => "object-attribute-inconsistent",
            DataAccessError::ObjectAccessUnsupported => "object-access-unsupported",
            DataAccessError::ObjectNonExistent => "object-non-existent",
            DataAccessError::ObjectValueInvalid => "object-value-invalid",
            DataAccessError::Other(n) => return write!(f, "data-access-error({n})"),
        };
        f.write_str(s)
    }
}

impl std::error::Error for DataAccessError {}

/// The error class of an MMS confirmed-ErrorPDU (`errorClass` CHOICE index).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorClass(pub u8);

impl ErrorClass {
    pub const VMD_STATE: ErrorClass = ErrorClass(0);
    pub const APPLICATION_REFERENCE: ErrorClass = ErrorClass(1);
    pub const DEFINITION: ErrorClass = ErrorClass(2);
    pub const RESOURCE: ErrorClass = ErrorClass(3);
    pub const SERVICE: ErrorClass = ErrorClass(4);
    pub const SERVICE_PREEMPT: ErrorClass = ErrorClass(5);
    pub const TIME_RESOLUTION: ErrorClass = ErrorClass(6);
    pub const ACCESS: ErrorClass = ErrorClass(7);
    pub const INITIATE: ErrorClass = ErrorClass(8);
    pub const CONCLUDE: ErrorClass = ErrorClass(9);
    pub const CANCEL: ErrorClass = ErrorClass(10);
    pub const FILE: ErrorClass = ErrorClass(11);
    pub const OTHERS: ErrorClass = ErrorClass(12);
}

impl std::fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const NAMES: [&str; 13] = [
            "vmd-state",
            "application-reference",
            "definition",
            "resource",
            "service",
            "service-preempt",
            "time-resolution",
            "access",
            "initiate",
            "conclude",
            "cancel",
            "file",
            "others",
        ];
        match NAMES.get(usize::from(self.0)) {
            Some(name) => f.write_str(name),
            None => write!(f, "unknown"),
        }
    }
}

/// An MMS confirmed-ErrorPDU or reject surfaced to the caller of a confirmed
/// service.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct ServiceError {
    /// The `errorClass` CHOICE index.
    pub class: ErrorClass,
    /// The value within the class.
    pub code: u8,
    /// True when the PDU was a rejectPDU rather than a confirmed error.
    pub rejected: bool,
    pub detail: String,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.rejected {
            // A reject's class is its RejectPDU category, a different enum from
            // the service error classes.
            write!(f, "mms: service reject: {}({})", reject_category(self.class.0), self.code)?;
        } else {
            write!(f, "mms: service error: {}({})", self.class, self.code)?;
        }
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

/// Names a RejectPDU `rejectReason` category (ISO 9506-2).
fn reject_category(category: u8) -> &'static str {
    match category {
        1 => "confirmed-requestPDU",
        2 => "confirmed-responsePDU",
        3 => "confirmed-errorPDU",
        4 => "unconfirmedPDU",
        5 => "pdu-error",
        6 => "cancel-requestPDU",
        7 => "cancel-responsePDU",
        8 => "cancel-errorPDU",
        9 => "conclude-requestPDU",
        10 => "conclude-responsePDU",
        11 => "conclude-errorPDU",
        _ => "unknown",
    }
}

impl ServiceError {
    /// Returns a confirmed-service error of the given class and code.
    pub fn new(class: ErrorClass, code: u8) -> ServiceError {
        ServiceError {
            class,
            code,
            rejected: false,
            detail: String::new(),
        }
    }

    /// Returns the error with explanatory detail attached.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> ServiceError {
        self.detail = detail.into();
        self
    }
}

/// Errors raised by the MMS layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error("mms: {0}")]
    Access(#[from] DataAccessError),
    #[error(transparent)]
    Asn1(#[from] crate::asn1::Error),
    #[error(transparent)]
    Osi(#[from] crate::osi::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("mms: {0}")]
    Protocol(String),
    /// The server refused the association: its AARE carried result rejected,
    /// with this ACSE service-user diagnostic.
    #[error("mms: association rejected{}", rejected_reason(*.0))]
    Rejected(i64),
    /// The association ended by an abort (ACSE A-ABORT over a session ABORT)
    /// rather than a release: by the peer, or by `abort` on this end.
    #[error("mms: association aborted{0}")]
    Aborted(String),
    /// An authenticator refused the association; the client was told so (an
    /// AARE with result rejected) before the connection was closed.
    #[error("mms: association rejected: {0}")]
    AssociationRejected(String),
    /// Returned by an authenticator, rejects the association as needing
    /// authentication (ACSE diagnostic authentication-required) rather than
    /// as having failed it.
    #[error("mms: authentication required")]
    AuthenticationRequired,
    /// A data set the server has but would not delete: one it was configured
    /// with, or one a control block uses (IEC 61850-7-2).
    #[error("mms: named variable list exists but was not deleted")]
    NotDeleted,
    #[error("mms: connection closed")]
    Closed,
    #[error("mms: request timed out")]
    Timeout,
    /// The outbound unconfirmed queue was saturated and the report was
    /// dropped. A buffered RCB answers this by setting `BufOvfl`.
    #[error("mms: unconfirmed queue full")]
    ReportQueueFull,
}

impl Error {
    pub(crate) fn protocol(msg: impl Into<String>) -> Error {
        Error::Protocol(msg.into())
    }

    /// Reports whether the error is an association refused for a failed or
    /// missing authentication.
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            Error::Rejected(d) if *d == crate::osi::acse::DIAG_AUTHENTICATION_FAILURE
                || *d == crate::osi::acse::DIAG_AUTHENTICATION_REQUIRED
        )
    }

    /// Returns the confirmed-error or reject the peer answered with, if that
    /// is what this is.
    pub fn as_service_error(&self) -> Option<&ServiceError> {
        match self {
            Error::Service(se) => Some(se),
            _ => None,
        }
    }

    /// Returns the data access error of a failed item, if that is what this
    /// is.
    pub fn as_access_error(&self) -> Option<DataAccessError> {
        match self {
            Error::Access(e) => Some(*e),
            _ => None,
        }
    }

    /// Rebuilds an equivalent error for a second recipient. The original is
    /// handed to the first; the others get the same kind with its message.
    pub(crate) fn duplicate(&self) -> Error {
        match self {
            Error::Service(se) => Error::Service(se.clone()),
            Error::Access(e) => Error::Access(*e),
            Error::Rejected(d) => Error::Rejected(*d),
            Error::Aborted(s) => Error::Aborted(s.clone()),
            Error::Closed => Error::Closed,
            Error::Timeout => Error::Timeout,
            Error::NotDeleted => Error::NotDeleted,
            Error::ReportQueueFull => Error::ReportQueueFull,
            Error::AuthenticationRequired => Error::AuthenticationRequired,
            Error::AssociationRejected(s) => Error::AssociationRejected(s.clone()),
            other => Error::Protocol(other.to_string()),
        }
    }
}

fn rejected_reason(diagnostic: i64) -> String {
    match diagnostic {
        crate::osi::acse::DIAG_AUTHENTICATION_FAILURE => ": authentication failure".into(),
        crate::osi::acse::DIAG_AUTHENTICATION_REQUIRED => ": authentication required".into(),
        d => format!(" (diagnostic {d})"),
    }
}

/// Result alias for the MMS layer.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_error_codes_round_trip() {
        for code in 0u8..=11 {
            let e = DataAccessError::from_code(code);
            assert_eq!(e.code(), code);
            assert!(
                !e.to_string().contains("data-access-error("),
                "code {code} should have a name"
            );
        }
        // Unknown codes survive as-is rather than being lost.
        assert_eq!(DataAccessError::from_code(200).code(), 200);
        assert_eq!(
            DataAccessError::from_code(200).to_string(),
            "data-access-error(200)"
        );
    }

    #[test]
    fn service_errors_render_class_code_and_detail() {
        let e = ServiceError::new(ErrorClass::ACCESS, 3);
        assert_eq!(e.to_string(), "mms: service error: access(3)");

        let e = ServiceError {
            rejected: true,
            ..ServiceError::new(ErrorClass(1), 1).with_detail("unknown service")
        };
        assert_eq!(
            e.to_string(),
            "mms: service reject: confirmed-requestPDU(1): unknown service"
        );
    }
}
