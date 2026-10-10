/// A non-fatal problem found while interpreting a data model.
///
/// Interpretation is deliberately permissive: an unknown basic type, an
/// unknown functional constraint or an unresolvable dataset member is recorded
/// as a diagnostic and the model is still usable. One unrecognised construct
/// must not make a whole IED unreadable; a vendor file or a newer SCL release
/// is far more common than a schema change that actually matters, and a hard
/// failure gives the operator nothing to work with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostic {
    /// Locates the construct, for example `IED1LD0/MMXU1.TotW.mag` or, while
    /// parsing SCL, `SCL/IED[name=SIMPLE]/DataTypeTemplates`.
    pub path: String,
    /// Describes the problem in one line.
    pub message: String,
}

impl Diagnostic {
    /// Returns a diagnostic for `path`.
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}
