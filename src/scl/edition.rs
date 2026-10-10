//! The SCL editions a document may declare.

/// The SCL namespace every published edition shares.
pub const SCL_NAMESPACE: &str = "http://www.iec.ch/61850/2003/SCL";

/// Identifies which release of IEC 61850-6 a document was written against,
/// from its SCL namespace, version, revision and release attributes
/// (IEC 61850-6 clause 1.2).
///
/// The element names of a document are matched by local name, so every
/// edition parses; the edition matters for interpreting the attributes whose
/// meaning or presence changed, and for reporting a file this crate cannot
/// fully understand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Edition {
    /// The SCL namespace URI. All published editions share
    /// [`SCL_NAMESPACE`]; a different URI is a vendor schema.
    pub namespace: String,
    /// `2003` (Ed 1) or `2007` (Ed 2 and later).
    pub version: String,
    /// `A` (Ed 1), `B` (Ed 2.0), `C` (Ed 2.2).
    pub revision: String,
    /// The SCL schema release, for example `4` for 2007B4.
    pub release: String,
}

/// The published SCL code components: version, revision and release.
const KNOWN: [(&str, &str, &str); 7] = [
    ("2003", "A", ""),
    ("2007", "B", ""),
    ("2007", "B", "1"),
    ("2007", "B", "2"),
    ("2007", "B", "3"),
    ("2007", "B", "4"),
    ("2007", "C", "5"),
];

impl Edition {
    /// Reports whether the edition is one this crate has seen.
    ///
    /// A document that declares no version at all, which some tools emit,
    /// reports known, because absent attributes are legal and the parser is
    /// permissive.
    pub fn known(&self) -> bool {
        if self.version.is_empty() {
            return true;
        }
        KNOWN.iter().any(|(v, r, rel)| {
            self.version == *v && self.revision.eq_ignore_ascii_case(r) && self.release == *rel
        })
    }

    /// Reports whether the document declares the Edition 1 SCL (2003), whose
    /// data model and control blocks differ from Edition 2's.
    pub fn is_ed1(&self) -> bool {
        self.version == "2003"
    }

    /// Reports whether the document is Edition 2 or later, the editions this
    /// crate implements. Edition 1 files load, with the differences recorded
    /// as diagnostics.
    pub fn at_least_ed2(&self) -> bool {
        self.version == "2007"
    }

    /// Returns the diagnostics worth reporting for the edition: a vendor
    /// namespace, or a version this crate does not know.
    pub(crate) fn validate(&self, path: &str) -> Vec<String> {
        if self.namespace.is_empty() {
            return Vec::new();
        }
        if self.namespace != SCL_NAMESPACE {
            return vec![format!(
                "{path}: SCL namespace {:?} is not the IEC 61850 one; parsing by local element name",
                self.namespace
            )];
        }
        if self.known() {
            return Vec::new();
        }
        vec![format!(
            "{path}: SCL version {} revision {} release {} is not a published IEC 61850-6 \
             code component; parsing by local element name",
            self.version, self.revision, self.release
        )]
    }
}

impl std::fmt::Display for Edition {
    /// Renders the edition as `2007B4`, the identifier used in the SCL
    /// conformance literature, or `unknown` when no version is declared.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.version.is_empty() {
            return f.write_str("unknown");
        }
        write!(
            f,
            "{}{}{}",
            self.version,
            self.revision.to_ascii_uppercase(),
            self.release
        )
    }
}
