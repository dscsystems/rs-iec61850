/// A functional constraint (IEC 61850-7-2).
///
/// The same object exposes different views under different constraints, so a
/// data attribute is addressed by reference *and* functional constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum Fc {
    #[default]
    None,
    /// Status information.
    St,
    /// Measurands.
    Mx,
    /// Control.
    Co,
    /// Set points.
    Sp,
    /// Setting group.
    Sg,
    /// Setting group editable.
    Se,
    /// Substitution.
    Sv,
    /// Configuration.
    Cf,
    /// Description.
    Dc,
    /// Extended definition.
    Ex,
    /// Operate received.
    Or,
    /// Blocking.
    Bl,
    /// Unbuffered report control.
    Rp,
    /// Buffered report control.
    Br,
    /// Log control.
    Lg,
    /// GOOSE control.
    Go,
    /// GSSE control (legacy).
    Gs,
    /// Multicast sampled values control.
    Ms,
    /// Unicast sampled values control.
    Us,
    /// A wildcard for lookups; never appears on the wire.
    All,
}

impl Fc {
    /// Every constraint that can appear in a model, in declaration order.
    pub const ALL_VALUES: [Fc; 19] = [
        Fc::St,
        Fc::Mx,
        Fc::Co,
        Fc::Sp,
        Fc::Sg,
        Fc::Se,
        Fc::Sv,
        Fc::Cf,
        Fc::Dc,
        Fc::Ex,
        Fc::Or,
        Fc::Bl,
        Fc::Rp,
        Fc::Br,
        Fc::Lg,
        Fc::Go,
        Fc::Gs,
        Fc::Ms,
        Fc::Us,
    ];

    /// Returns the two-letter mnemonic, or the empty string for
    /// [`Fc::None`].
    pub fn as_str(self) -> &'static str {
        match self {
            Fc::None => "",
            Fc::St => "ST",
            Fc::Mx => "MX",
            Fc::Co => "CO",
            Fc::Sp => "SP",
            Fc::Sg => "SG",
            Fc::Se => "SE",
            Fc::Sv => "SV",
            Fc::Cf => "CF",
            Fc::Dc => "DC",
            Fc::Ex => "EX",
            Fc::Or => "OR",
            Fc::Bl => "BL",
            Fc::Rp => "RP",
            Fc::Br => "BR",
            Fc::Lg => "LG",
            Fc::Go => "GO",
            Fc::Gs => "GS",
            Fc::Ms => "MS",
            Fc::Us => "US",
            Fc::All => "*",
        }
    }

    /// Reports whether the constraint matches `other` for lookup purposes.
    ///
    /// [`Fc::All`] and [`Fc::None`] match anything, which is what makes a
    /// reference usable without knowing the constraint in advance.
    pub fn matches(self, other: Fc) -> bool {
        self == Fc::All || self == Fc::None || self == other
    }

    /// Reports whether the constraint names a report control block.
    pub fn is_report(self) -> bool {
        matches!(self, Fc::Rp | Fc::Br)
    }

    /// Reports whether the constraint names a setting group value.
    pub fn is_setting_group(self) -> bool {
        matches!(self, Fc::Sg | Fc::Se)
    }
}

impl std::fmt::Display for Fc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The error from parsing an unknown functional-constraint mnemonic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("model: unknown functional constraint {0:?}")]
pub struct ParseFcError(pub String);

impl std::str::FromStr for Fc {
    type Err = ParseFcError;

    /// Parses a mnemonic, case-insensitively.
    fn from_str(s: &str) -> Result<Fc, ParseFcError> {
        let u = s.trim().to_ascii_uppercase();
        if u == "*" {
            return Ok(Fc::All);
        }
        Fc::ALL_VALUES
            .into_iter()
            .find(|fc| fc.as_str() == u)
            .ok_or_else(|| ParseFcError(s.to_string()))
    }
}

/// Parses a functional-constraint mnemonic, case-insensitively.
pub fn parse_fc(s: &str) -> Result<Fc, ParseFcError> {
    s.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_constraint_round_trips_through_its_mnemonic() {
        for fc in Fc::ALL_VALUES {
            let s = fc.as_str();
            assert_eq!(s.len(), 2, "{fc} should be a two-letter mnemonic");
            assert_eq!(parse_fc(s).unwrap(), fc);
            // Parsing is case-insensitive and tolerates surrounding space.
            assert_eq!(parse_fc(&s.to_lowercase()).unwrap(), fc);
            assert_eq!(parse_fc(&format!("  {s} ")).unwrap(), fc);
        }
    }

    #[test]
    fn the_wildcard_parses_but_none_does_not() {
        assert_eq!(parse_fc("*").unwrap(), Fc::All);
        assert_eq!(Fc::None.as_str(), "");
        // An empty mnemonic is not a constraint, it is the absence of one.
        assert!(parse_fc("").is_err());
        assert!(parse_fc("XX").is_err());
        assert!(parse_fc("STATUS").is_err());
    }

    #[test]
    fn the_wildcard_matches_any_constraint() {
        assert!(Fc::All.matches(Fc::Mx));
        assert!(Fc::None.matches(Fc::Mx));
        assert!(Fc::Mx.matches(Fc::Mx));
        assert!(!Fc::Mx.matches(Fc::St));
    }

    #[test]
    fn report_and_setting_group_constraints_are_recognised() {
        assert!(Fc::Rp.is_report() && Fc::Br.is_report());
        assert!(!Fc::St.is_report());
        assert!(Fc::Sg.is_setting_group() && Fc::Se.is_setting_group());
        assert!(!Fc::Sp.is_setting_group());
    }

    #[test]
    fn the_default_is_the_absence_of_a_constraint() {
        assert_eq!(Fc::default(), Fc::None);
    }
}
