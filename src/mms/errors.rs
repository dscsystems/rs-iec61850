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
        let kind = if self.rejected { "reject" } else { "error" };
        write!(f, "mms: service {kind}: {}({})", self.class, self.code)?;
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
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
    #[error("mms: association rejected: {0}")]
    Rejected(String),
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
            ..ServiceError::new(ErrorClass::SERVICE, 1).with_detail("unknown service")
        };
        assert_eq!(
            e.to_string(),
            "mms: service reject: service(1): unknown service"
        );
    }
}
