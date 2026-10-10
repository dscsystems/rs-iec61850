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
    /// Service response, the constraint of the service tracking classes
    /// (`CST`, `BTS`, `CTS`...) that IEC 61850-7-2 Edition 2 added.
    Sr,
    /// A constraint whose mnemonic this crate does not know: one added by a
    /// later edition, or a vendor extension.
    ///
    /// It is carried rather than rejected so the object stays visible and
    /// browsable. [`parse_fc_lenient`] produces it; the verbatim mnemonic is
    /// kept alongside it (`DataAttribute::fc_name`, `Fcda::fc_name`).
    Unknown,
}

impl Fc {
    /// Every constraint that can appear in a model, in declaration order.
    pub const ALL_VALUES: [Fc; 20] = [
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
        Fc::Sr,
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
            Fc::Sr => "SR",
            Fc::Unknown => "??",
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

/// Parses a functional-constraint mnemonic, yielding [`Fc::Unknown`] rather
/// than an error for one this crate does not know, and [`Fc::None`] for an
/// empty one.
pub fn parse_fc_lenient(s: &str) -> Fc {
    let u = s.trim();
    if u.is_empty() {
        return Fc::None;
    }
    u.parse().unwrap_or(Fc::Unknown)
}

/// Renders the mnemonic to use in an MMS item ID or type specification.
///
/// `raw` is the mnemonic as it appeared in the source document, used for
/// [`Fc::Unknown`], whose variant has no spelling of its own.
pub fn fc_text(fc: Fc, raw: &str) -> String {
    if fc != Fc::Unknown {
        return fc.as_str().to_string();
    }
    let u = raw.trim().to_ascii_uppercase();
    if u.is_empty() {
        fc.as_str().to_string()
    } else {
        u
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_constraint_round_trips_through_its_mnemonic() {
        for fc in Fc::ALL_VALUES {
            let s = fc.as_str();
            assert_eq!(s.len(), 2, "{fc} should be a two-letter mnemonic");
            assert_eq!(parse_fc_lenient(s), fc);
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

    /// An unknown constraint is carried, with its verbatim mnemonic, rather
    /// than rejected: the object under it stays visible.
    #[test]
    fn an_unknown_constraint_is_carried_leniently() {
        assert_eq!(parse_fc_lenient("ZZ"), Fc::Unknown);
        assert_eq!(parse_fc_lenient(" "), Fc::None);
        assert_eq!(parse_fc_lenient("sr"), Fc::Sr);
        assert_eq!(Fc::Sr.to_string(), "SR");
        assert!(parse_fc("ZZ").is_err());
        assert_eq!(fc_text(Fc::Unknown, " zz "), "ZZ");
        assert_eq!(fc_text(Fc::Unknown, ""), "??");
        assert_eq!(fc_text(Fc::Mx, "ignored"), "MX");
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
