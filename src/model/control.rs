/// The control model of a controllable object (the `ctlModel` configuration
/// attribute, IEC 61850-7-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CtlModel {
    #[default]
    StatusOnly,
    DirectNormal,
    SboNormal,
    DirectEnhanced,
    SboEnhanced,
    /// A value outside the range the standard defines.
    Other(u8),
}

impl CtlModel {
    pub fn from_code(code: u8) -> CtlModel {
        match code {
            0 => CtlModel::StatusOnly,
            1 => CtlModel::DirectNormal,
            2 => CtlModel::SboNormal,
            3 => CtlModel::DirectEnhanced,
            4 => CtlModel::SboEnhanced,
            n => CtlModel::Other(n),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            CtlModel::StatusOnly => 0,
            CtlModel::DirectNormal => 1,
            CtlModel::SboNormal => 2,
            CtlModel::DirectEnhanced => 3,
            CtlModel::SboEnhanced => 4,
            CtlModel::Other(n) => n,
        }
    }

    /// Reports whether the model requires a select step before the operate.
    pub fn has_select(self) -> bool {
        matches!(self, CtlModel::SboNormal | CtlModel::SboEnhanced)
    }

    /// Reports whether the model uses enhanced security, which adds a
    /// CommandTermination after the operate.
    pub fn is_enhanced(self) -> bool {
        matches!(self, CtlModel::DirectEnhanced | CtlModel::SboEnhanced)
    }

    /// Reports whether the object accepts commands at all.
    pub fn is_controllable(self) -> bool {
        !matches!(self, CtlModel::StatusOnly)
    }
}

impl std::fmt::Display for CtlModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            CtlModel::StatusOnly => "status-only",
            CtlModel::DirectNormal => "direct-with-normal-security",
            CtlModel::SboNormal => "sbo-with-normal-security",
            CtlModel::DirectEnhanced => "direct-with-enhanced-security",
            CtlModel::SboEnhanced => "sbo-with-enhanced-security",
            CtlModel::Other(n) => return write!(f, "ctlModel({n})"),
        })
    }
}

/// The originator category (`orCat`) of a control command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrCat {
    #[default]
    NotSupported,
    BayControl,
    StationControl,
    RemoteControl,
    AutomaticBay,
    AutomaticStation,
    AutomaticRemote,
    Maintenance,
    Process,
    Other(u8),
}

impl OrCat {
    pub fn from_code(code: u8) -> OrCat {
        match code {
            0 => OrCat::NotSupported,
            1 => OrCat::BayControl,
            2 => OrCat::StationControl,
            3 => OrCat::RemoteControl,
            4 => OrCat::AutomaticBay,
            5 => OrCat::AutomaticStation,
            6 => OrCat::AutomaticRemote,
            7 => OrCat::Maintenance,
            8 => OrCat::Process,
            n => OrCat::Other(n),
        }
    }

    pub fn code(self) -> u8 {
        match self {
            OrCat::NotSupported => 0,
            OrCat::BayControl => 1,
            OrCat::StationControl => 2,
            OrCat::RemoteControl => 3,
            OrCat::AutomaticBay => 4,
            OrCat::AutomaticStation => 5,
            OrCat::AutomaticRemote => 6,
            OrCat::Maintenance => 7,
            OrCat::Process => 8,
            OrCat::Other(n) => n,
        }
    }
}

impl std::fmt::Display for OrCat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OrCat::NotSupported => "not-supported",
            OrCat::BayControl => "bay-control",
            OrCat::StationControl => "station-control",
            OrCat::RemoteControl => "remote-control",
            OrCat::AutomaticBay => "automatic-bay",
            OrCat::AutomaticStation => "automatic-station",
            OrCat::AutomaticRemote => "automatic-remote",
            OrCat::Maintenance => "maintenance",
            OrCat::Process => "process",
            OrCat::Other(n) => return write!(f, "orCat({n})"),
        })
    }
}

/// The additional cause returned with a negative control response and with
/// CommandTermination- (IEC 61850-7-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddCause(pub u8);

impl AddCause {
    pub const UNKNOWN: AddCause = AddCause(0);
    pub const NOT_SUPPORTED: AddCause = AddCause(1);
    pub const BLOCKED_BY_SWITCHING_HIERARCHY: AddCause = AddCause(2);
    pub const SELECT_FAILED: AddCause = AddCause(3);
    pub const INVALID_POSITION: AddCause = AddCause(4);
    pub const POSITION_REACHED: AddCause = AddCause(5);
    pub const PARAMETER_CHANGE_IN_EXECUTION: AddCause = AddCause(6);
    pub const STEP_LIMIT: AddCause = AddCause(7);
    pub const BLOCKED_BY_MODE: AddCause = AddCause(8);
    pub const BLOCKED_BY_PROCESS: AddCause = AddCause(9);
    pub const BLOCKED_BY_INTERLOCKING: AddCause = AddCause(10);
    pub const BLOCKED_BY_SYNCHROCHECK: AddCause = AddCause(11);
    pub const COMMAND_ALREADY_IN_EXECUTION: AddCause = AddCause(12);
    pub const BLOCKED_BY_HEALTH: AddCause = AddCause(13);
    pub const ONE_OF_N_CONTROL: AddCause = AddCause(14);
    pub const ABORTION_BY_CANCEL: AddCause = AddCause(15);
    pub const TIME_LIMIT_OVER: AddCause = AddCause(16);
    pub const ABORTION_BY_TRIP: AddCause = AddCause(17);
    pub const OBJECT_NOT_SELECTED: AddCause = AddCause(18);
    pub const OBJECT_ALREADY_SELECTED: AddCause = AddCause(19);
    pub const NO_ACCESS_AUTHORITY: AddCause = AddCause(20);
    pub const ENDED_WITH_OVERSHOOT: AddCause = AddCause(21);
    pub const ABORTION_DUE_TO_DEVIATION: AddCause = AddCause(22);
    pub const ABORTION_BY_COMMUNICATION_LOSS: AddCause = AddCause(23);
    pub const BLOCKED_BY_COMMAND: AddCause = AddCause(24);
    /// The standard's "None": the peer answered negatively without naming a
    /// cause. It is a value seen on the wire, unlike [`AddCause::NONE`].
    pub const NONE_REPORTED: AddCause = AddCause(25);
    /// The diagnosis for an operate whose parameters do not match the select
    /// that reserved the object, a differing `ctlNum` above all.
    pub const INCONSISTENT_PARAMETERS: AddCause = AddCause(26);
    pub const LOCKED_BY_OTHER_CLIENT: AddCause = AddCause(27);

    /// Not an IEC 61850 value: this crate's "no error", returned by a control
    /// handler to accept a command.
    ///
    /// Every value a peer can send is 0..=27, so 255 cannot collide with one.
    pub const NONE: AddCause = AddCause(255);

    /// Reports whether the cause means the command was accepted.
    pub fn is_accepted(self) -> bool {
        self == AddCause::NONE
    }
}

impl std::fmt::Display for AddCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const NAMES: [&str; 28] = [
            "unknown",
            "not-supported",
            "blocked-by-switching-hierarchy",
            "select-failed",
            "invalid-position",
            "position-reached",
            "parameter-change-in-execution",
            "step-limit",
            "blocked-by-mode",
            "blocked-by-process",
            "blocked-by-interlocking",
            "blocked-by-synchrocheck",
            "command-already-in-execution",
            "blocked-by-health",
            "1-of-n-control",
            "abortion-by-cancel",
            "time-limit-over",
            "abortion-by-trip",
            "object-not-selected",
            "object-already-selected",
            "no-access-authority",
            "ended-with-overshoot",
            "abortion-due-to-deviation",
            "abortion-by-communication-loss",
            "blocked-by-command",
            "none-reported",
            "inconsistent-parameters",
            "locked-by-other-client",
        ];
        if self.0 == 255 {
            return f.write_str("none");
        }
        match NAMES.get(usize::from(self.0)) {
            Some(name) => f.write_str(name),
            None => write!(f, "addCause({})", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_models_round_trip_through_their_codes() {
        for code in 0u8..=4 {
            assert_eq!(CtlModel::from_code(code).code(), code);
        }
        // An out-of-range value survives rather than collapsing to a default.
        assert_eq!(CtlModel::from_code(9).code(), 9);
        assert_eq!(CtlModel::from_code(9).to_string(), "ctlModel(9)");
    }

    /// Which of select and CommandTermination a model needs is decided from
    /// these two predicates; getting either wrong breaks control end to end.
    #[test]
    fn the_four_control_models_classify_correctly() {
        assert!(!CtlModel::DirectNormal.has_select());
        assert!(!CtlModel::DirectNormal.is_enhanced());

        assert!(CtlModel::SboNormal.has_select());
        assert!(!CtlModel::SboNormal.is_enhanced());

        assert!(!CtlModel::DirectEnhanced.has_select());
        assert!(CtlModel::DirectEnhanced.is_enhanced());

        assert!(CtlModel::SboEnhanced.has_select());
        assert!(CtlModel::SboEnhanced.is_enhanced());

        assert!(!CtlModel::StatusOnly.is_controllable());
        assert!(CtlModel::DirectNormal.is_controllable());
    }

    #[test]
    fn originator_categories_round_trip_and_name_themselves() {
        for code in 0u8..=8 {
            assert_eq!(OrCat::from_code(code).code(), code);
        }
        assert_eq!(OrCat::StationControl.to_string(), "station-control");
        assert_eq!(OrCat::from_code(99).to_string(), "orCat(99)");
    }

    /// The accept sentinel must never collide with a value a peer can send.
    #[test]
    fn the_accept_sentinel_is_outside_the_wire_range() {
        assert!(AddCause::NONE.is_accepted());
        assert!(!AddCause::NONE_REPORTED.is_accepted());
        for code in 0u8..=27 {
            assert!(!AddCause(code).is_accepted(), "{code} must not read as accepted");
        }
        assert_eq!(AddCause::NONE.to_string(), "none");
        assert_eq!(AddCause::NONE_REPORTED.to_string(), "none-reported");
    }

    #[test]
    fn every_standard_add_cause_has_a_name() {
        for code in 0u8..=27 {
            let s = AddCause(code).to_string();
            assert!(!s.starts_with("addCause("), "code {code} needs a name");
        }
        assert_eq!(
            AddCause::BLOCKED_BY_INTERLOCKING.to_string(),
            "blocked-by-interlocking"
        );
        assert_eq!(AddCause(200).to_string(), "addCause(200)");
    }
}
