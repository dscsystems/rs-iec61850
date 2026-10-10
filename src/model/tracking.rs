//! The enumerations of the service tracking objects (IEC 61850-7-2 Edition 2,
//! the LTRK logical node).

/// Identifies an ACSI service in a service tracking object's `serviceType`
/// (the `ServiceType` enumeration of IEC 61850-7-2 Edition 2). The values are
/// the standard's, as libiec61850 numbers them too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceType(pub i32);

impl ServiceType {
    pub const UNKNOWN: ServiceType = ServiceType(0);
    pub const ASSOCIATE: ServiceType = ServiceType(1);
    pub const ABORT: ServiceType = ServiceType(2);
    pub const RELEASE: ServiceType = ServiceType(3);
    pub const GET_SERVER_DIRECTORY: ServiceType = ServiceType(4);
    pub const GET_LOGICAL_DEVICE_DIRECTORY: ServiceType = ServiceType(5);
    pub const GET_ALL_DATA_VALUES: ServiceType = ServiceType(6);
    pub const GET_DATA_VALUES: ServiceType = ServiceType(7);
    pub const SET_DATA_VALUES: ServiceType = ServiceType(8);
    pub const GET_DATA_DIRECTORY: ServiceType = ServiceType(9);
    pub const GET_DATA_DEFINITION: ServiceType = ServiceType(10);
    pub const GET_DATA_SET_VALUES: ServiceType = ServiceType(11);
    pub const SET_DATA_SET_VALUES: ServiceType = ServiceType(12);
    pub const CREATE_DATA_SET: ServiceType = ServiceType(13);
    pub const DELETE_DATA_SET: ServiceType = ServiceType(14);
    pub const GET_DATA_SET_DIRECTORY: ServiceType = ServiceType(15);
    pub const SELECT_ACTIVE_SG: ServiceType = ServiceType(16);
    pub const SELECT_EDIT_SG: ServiceType = ServiceType(17);
    pub const SET_EDIT_SG_VALUE: ServiceType = ServiceType(18);
    pub const CONFIRM_EDIT_SG_VALUES: ServiceType = ServiceType(19);
    pub const GET_EDIT_SG_VALUE: ServiceType = ServiceType(20);
    pub const GET_SGCB_VALUES: ServiceType = ServiceType(21);
    pub const REPORT: ServiceType = ServiceType(22);
    pub const GET_BRCB_VALUES: ServiceType = ServiceType(23);
    pub const SET_BRCB_VALUES: ServiceType = ServiceType(24);
    pub const GET_URCB_VALUES: ServiceType = ServiceType(25);
    pub const SET_URCB_VALUES: ServiceType = ServiceType(26);
    pub const GET_LCB_VALUES: ServiceType = ServiceType(27);
    pub const SET_LCB_VALUES: ServiceType = ServiceType(28);
    pub const QUERY_LOG_BY_TIME: ServiceType = ServiceType(29);
    pub const QUERY_LOG_AFTER: ServiceType = ServiceType(30);
    pub const GET_LOG_STATUS: ServiceType = ServiceType(31);
    pub const SEND_GOOSE_MESSAGE: ServiceType = ServiceType(32);
    pub const GET_GOCB_VALUES: ServiceType = ServiceType(33);
    pub const SET_GOCB_VALUES: ServiceType = ServiceType(34);
    pub const GET_GO_REFERENCE: ServiceType = ServiceType(35);
    pub const GET_GOOSE_ELEMENT_NUMBER: ServiceType = ServiceType(36);
    pub const SEND_MSV_MESSAGE: ServiceType = ServiceType(37);
    pub const GET_MSVCB_VALUES: ServiceType = ServiceType(38);
    pub const SET_MSVCB_VALUES: ServiceType = ServiceType(39);
    pub const SEND_USV_MESSAGE: ServiceType = ServiceType(40);
    pub const GET_USVCB_VALUES: ServiceType = ServiceType(41);
    pub const SET_USVCB_VALUES: ServiceType = ServiceType(42);
    pub const SELECT: ServiceType = ServiceType(43);
    pub const SELECT_WITH_VALUE: ServiceType = ServiceType(44);
    pub const CANCEL: ServiceType = ServiceType(45);
    pub const OPERATE: ServiceType = ServiceType(46);
    pub const COMMAND_TERMINATION: ServiceType = ServiceType(47);
    pub const TIME_ACTIVATED_OPERATE: ServiceType = ServiceType(48);
    pub const GET_FILE: ServiceType = ServiceType(49);
    pub const SET_FILE: ServiceType = ServiceType(50);
    pub const DELETE_FILE: ServiceType = ServiceType(51);
    pub const GET_FILE_ATTRIBUTE_VALUES: ServiceType = ServiceType(52);
    pub const TIME_SYNCHRONISATION: ServiceType = ServiceType(53);
    pub const INTERNAL_CHANGE: ServiceType = ServiceType(54);
}

/// The outcome of a tracked service, a tracking object's `errorCode` (the
/// `ServiceError` enumeration of IEC 61850-7-2 Edition 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceErrorCode(pub i32);

impl ServiceErrorCode {
    pub const NO_ERROR: ServiceErrorCode = ServiceErrorCode(0);
    pub const INSTANCE_NOT_AVAILABLE: ServiceErrorCode = ServiceErrorCode(1);
    pub const INSTANCE_IN_USE: ServiceErrorCode = ServiceErrorCode(2);
    pub const ACCESS_VIOLATION: ServiceErrorCode = ServiceErrorCode(3);
    pub const ACCESS_NOT_ALLOWED_IN_CURRENT_STATE: ServiceErrorCode = ServiceErrorCode(4);
    pub const PARAMETER_VALUE_INAPPROPRIATE: ServiceErrorCode = ServiceErrorCode(5);
    pub const PARAMETER_VALUE_INCONSISTENT: ServiceErrorCode = ServiceErrorCode(6);
    pub const CLASS_NOT_SUPPORTED: ServiceErrorCode = ServiceErrorCode(7);
    pub const INSTANCE_LOCKED_BY_OTHER_CLIENT: ServiceErrorCode = ServiceErrorCode(8);
    pub const CONTROL_MUST_BE_SELECTED: ServiceErrorCode = ServiceErrorCode(9);
    pub const TYPE_CONFLICT: ServiceErrorCode = ServiceErrorCode(10);
    pub const FAILED_DUE_TO_COMMUNICATIONS_CONSTRAINT: ServiceErrorCode = ServiceErrorCode(11);
    pub const FAILED_DUE_TO_SERVER_CONSTRAINT: ServiceErrorCode = ServiceErrorCode(12);
}
