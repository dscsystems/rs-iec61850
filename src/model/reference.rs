use super::Fc;

/// An IEC 61850 object reference of the form `LD/LN.DO[.DA...]`, for example
/// `ied1LD0/GGIO1.AnIn1.mag.f`.
///
/// The logical device part is the full MMS domain name (the IED name followed
/// by the logical-device instance).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectReference(String);

/// The error from parsing a structurally invalid object reference.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefError {
    #[error("model: reference {0:?} must be LD/LN.DO...")]
    Shape(String),
    #[error("model: reference {0:?} has an empty component")]
    EmptyComponent(String),
}

impl ObjectReference {
    /// Wraps `s` without validating it.
    ///
    /// References read from a device are taken as given; use
    /// [`parse`](ObjectReference::parse) where the input is untrusted.
    pub fn new(s: impl Into<String>) -> ObjectReference {
        ObjectReference(s.into())
    }

    /// Validates `s` and returns it as a reference.
    pub fn parse(s: impl Into<String>) -> Result<ObjectReference, RefError> {
        let r = ObjectReference(s.into());
        r.validate()?;
        Ok(r)
    }

    /// Checks structural validity: exactly one `/`, and no empty components.
    pub fn validate(&self) -> Result<(), RefError> {
        let Some((ld, rest)) = self.0.split_once('/') else {
            return Err(RefError::Shape(self.0.clone()));
        };
        if ld.is_empty() || rest.is_empty() {
            return Err(RefError::Shape(self.0.clone()));
        }
        if rest.split('.').any(str::is_empty) {
            return Err(RefError::EmptyComponent(self.0.clone()));
        }
        Ok(())
    }

    /// Returns the reference as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the logical device (MMS domain) part.
    pub fn ld(&self) -> &str {
        self.0.split_once('/').map_or("", |(ld, _)| ld)
    }

    /// Returns the logical node name.
    pub fn ln(&self) -> &str {
        match self.0.split_once('/') {
            Some((_, rest)) => rest.split('.').next().unwrap_or(""),
            None => "",
        }
    }

    /// Returns the components after the logical device: LN, DO, DA...
    pub fn path(&self) -> Vec<&str> {
        match self.0.split_once('/') {
            Some((_, rest)) => rest.split('.').collect(),
            None => Vec::new(),
        }
    }

    /// Returns the reference with the last component removed, or `None` at the
    /// logical-node level.
    pub fn parent(&self) -> Option<ObjectReference> {
        let i = self.0.rfind('.')?;
        Some(ObjectReference(self.0[..i].to_string()))
    }

    /// Returns the reference extended by one component.
    pub fn child(&self, name: &str) -> ObjectReference {
        ObjectReference(format!("{}.{name}", self.0))
    }

    /// Converts the reference plus a functional constraint to an MMS
    /// `(domain, itemID)` pair: `LD/LN.DO.DA` under `MX` becomes
    /// `("LD", "LN$MX$DO$DA")`.
    pub fn to_mms(&self, fc: Fc) -> (String, String) {
        let domain = self.ld().to_string();
        let parts = self.path();
        if parts.is_empty() {
            return (domain, String::new());
        }
        let mut item = String::from(parts[0]);
        if fc != Fc::None && fc != Fc::All {
            item.push('$');
            item.push_str(fc.as_str());
        }
        for p in &parts[1..] {
            item.push('$');
            item.push_str(p);
        }
        (domain, item)
    }
}

impl std::fmt::Display for ObjectReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ObjectReference {
    fn from(s: &str) -> ObjectReference {
        ObjectReference(s.to_string())
    }
}

impl From<String> for ObjectReference {
    fn from(s: String) -> ObjectReference {
        ObjectReference(s)
    }
}

impl AsRef<str> for ObjectReference {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Converts an MMS `(domain, itemID)` pair back to a reference and functional
/// constraint.
///
/// ItemIDs without a constraint component (as some servers emit for dataset
/// entries) yield [`Fc::None`].
pub fn from_mms(domain: &str, item: &str) -> (ObjectReference, Fc) {
    let mut fc = Fc::None;
    let mut path: Vec<&str> = Vec::new();
    for (i, p) in item.split('$').enumerate() {
        // The constraint, when present, is always the second component.
        if i == 1 {
            if let Ok(f) = p.parse::<Fc>() {
                fc = f;
                continue;
            }
        }
        path.push(p);
    }
    (
        ObjectReference(format!("{domain}/{}", path.join("."))),
        fc,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_decomposes_into_its_parts() {
        let r = ObjectReference::parse("ied1LD0/GGIO1.AnIn1.mag.f").unwrap();
        assert_eq!(r.ld(), "ied1LD0");
        assert_eq!(r.ln(), "GGIO1");
        assert_eq!(r.path(), ["GGIO1", "AnIn1", "mag", "f"]);
        assert_eq!(
            r.parent().unwrap(),
            ObjectReference::new("ied1LD0/GGIO1.AnIn1.mag")
        );
        assert_eq!(
            r.parent().unwrap().child("q"),
            ObjectReference::new("ied1LD0/GGIO1.AnIn1.mag.q")
        );
    }

    #[test]
    fn a_logical_node_reference_has_no_parent() {
        let r = ObjectReference::parse("ied1LD0/GGIO1").unwrap();
        assert_eq!(r.ln(), "GGIO1");
        assert_eq!(r.path(), ["GGIO1"]);
        assert!(r.parent().is_none());
    }

    #[test]
    fn structurally_invalid_references_are_rejected() {
        assert!(ObjectReference::parse("no-slash").is_err());
        assert!(ObjectReference::parse("/GGIO1").is_err());
        assert!(ObjectReference::parse("LD/").is_err());
        assert!(ObjectReference::parse("LD/GGIO1..mag").is_err());
        assert!(ObjectReference::parse("").is_err());
    }

    #[test]
    fn mms_names_round_trip_through_the_reference_form() {
        let r = ObjectReference::new("ied1LD0/GGIO1.AnIn1.mag.f");
        let (domain, item) = r.to_mms(Fc::Mx);
        assert_eq!(domain, "ied1LD0");
        assert_eq!(item, "GGIO1$MX$AnIn1$mag$f");

        let (back, fc) = from_mms(&domain, &item);
        assert_eq!(back, r);
        assert_eq!(fc, Fc::Mx);
    }

    #[test]
    fn a_reference_without_a_constraint_omits_the_fc_component() {
        let r = ObjectReference::new("LD/LLN0.Mod");
        assert_eq!(r.to_mms(Fc::None).1, "LLN0$Mod");
        assert_eq!(r.to_mms(Fc::All).1, "LLN0$Mod");
    }

    /// Some servers emit dataset entries with no constraint component; those
    /// must not be misread as naming a data object called "MX".
    #[test]
    fn an_item_id_without_a_constraint_yields_no_constraint() {
        let (r, fc) = from_mms("LD", "LLN0$Mod$stVal");
        assert_eq!(fc, Fc::None);
        assert_eq!(r, ObjectReference::new("LD/LLN0.Mod.stVal"));

        // A logical node on its own.
        let (r, fc) = from_mms("LD", "GGIO1");
        assert_eq!(fc, Fc::None);
        assert_eq!(r, ObjectReference::new("LD/GGIO1"));
    }

    #[test]
    fn every_constraint_survives_the_mms_round_trip() {
        for fc in Fc::ALL_VALUES {
            let r = ObjectReference::new("LD/LN.DO.DA");
            let (d, i) = r.to_mms(fc);
            assert_eq!(from_mms(&d, &i), (r, fc), "round trip failed for {fc}");
        }
    }
}
