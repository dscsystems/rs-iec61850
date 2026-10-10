//! Alternate access (ISO 9506-2 `AlternateAccess`): the selection of part of a
//! variable, which IEC 61850 datasets use to name array elements and their
//! components.

use crate::asn1::{
    self, cons, context_constructed, context_primitive, prim, uint_elem, Class, Decoder, Element,
    TAG_SEQUENCE,
};

use super::pdu::SVC_GET_NAMED_VAR_LIST_ATTR;
use super::services::{object_name, parse_object_name};
use super::{Conn, Error, Result, Type, TypeSpec, VarRef};

/// One member of a named variable list: the variable, and the part of it the
/// list selects.
///
/// IEC 61850 datasets name array elements and their components this way:
/// `MHAI1.HA.phsAHar(9).cVal` is the variable `MHAI1$MX$HA$phsAHar` with
/// alternate access "element 9, component cVal".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListMember {
    pub var: VarRef,
    /// The content octets of the member's `alternateAccess [5]`, exactly as
    /// the server sent them, or empty when the member is the whole variable.
    /// Kept raw so it can be replayed verbatim; [`parse_alternate_access`]
    /// interprets it.
    pub alternate_access: Vec<u8>,
}

/// One step of an alternate access: a structure component by name, or an
/// array element by index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessStep {
    Component(String),
    Index(usize),
}

impl std::fmt::Display for AccessStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessStep::Component(c) => write!(f, ".{c}"),
            AccessStep::Index(i) => write!(f, "({i})"),
        }
    }
}

fn unsupported() -> Error {
    // IEC 61850-8-1 datasets only ever select one element, so an index range,
    // all elements or a named access is refused rather than half-supported.
    Error::protocol("alternate access selects more than one element")
}

/// Decodes the content of an `alternateAccess [5]` into a chain of steps.
///
/// ```text
/// AlternateAccess ::= SEQUENCE OF CHOICE {
///   unnamed AlternateAccessSelection, named [5] ... }
/// AlternateAccessSelection ::= CHOICE {
///   selectAlternateAccess [0] IMPLICIT SEQUENCE {
///     accessSelection CHOICE { component [0], index [1], indexRange [2], allElements [3] },
///     alternateAccess AlternateAccess },
///   selectAccess CHOICE { component [1], index [2], indexRange [3], allElements [4] } }
/// ```
///
/// libiec61850 encodes `phsAHar(10).cVal.mag` as selectAlternateAccess(index
/// 10, selectAlternateAccess(component cVal, selectAccess(component mag))).
pub fn parse_alternate_access(content: &[u8]) -> Result<Vec<AccessStep>> {
    let mut dec = Decoder::new(content);
    let mut steps = Vec::new();
    let mut n = 0;
    while dec.more() {
        let (tag, c) = dec.read_tlv()?;
        n += 1;
        if n > 1 {
            return Err(unsupported());
        }
        if tag == context_constructed(0) {
            // selectAlternateAccess
            let mut sd = Decoder::new(c);
            let (stag, sc) = sd.read_tlv()?;
            steps.extend(selection(stag.number, stag.constructed, sc, 0)?);
            let rest = sd.expect(TAG_SEQUENCE)?;
            steps.extend(parse_alternate_access(rest)?);
        } else if tag.class == Class::ContextSpecific && (1..=4).contains(&tag.number) {
            // selectAccess
            steps.extend(selection(tag.number, tag.constructed, c, 1)?);
        } else {
            return Err(unsupported());
        }
    }
    Ok(steps)
}

/// Decodes one accessSelection. Its CHOICE numbers sit one higher in
/// selectAccess than in selectAlternateAccess, which `offset` absorbs.
fn selection(num: u32, constructed: bool, c: &[u8], offset: u32) -> Result<Vec<AccessStep>> {
    match num.checked_sub(offset) {
        Some(0) => {
            if constructed {
                return Err(Error::protocol("constructed component name"));
            }
            // A component path may be written whole, "cVal$mag".
            Ok(String::from_utf8_lossy(c)
                .split('$')
                .map(|p| AccessStep::Component(p.to_string()))
                .collect())
        }
        Some(1) => Ok(vec![AccessStep::Index(asn1::decode_uint(c)? as usize)]),
        _ => Err(unsupported()),
    }
}

/// Resolves alternate-access steps against the variable's type, returning the
/// child-index path to the selected element and its type.
pub fn access_path<'a>(spec: &'a TypeSpec, steps: &[AccessStep]) -> Result<(Vec<usize>, &'a TypeSpec)> {
    let mut cur = spec;
    let mut path = Vec::with_capacity(steps.len());
    for s in steps {
        match s {
            AccessStep::Component(name) => {
                if cur.kind != Some(Type::Structure) {
                    return Err(Error::protocol(format!("component {name:?} of a non-structure")));
                }
                let i = cur
                    .components
                    .iter()
                    .position(|c| c.name == *name)
                    .ok_or_else(|| Error::protocol(format!("no component {name:?}")))?;
                path.push(i);
                cur = &cur.components[i].spec;
            }
            AccessStep::Index(i) => {
                if cur.kind != Some(Type::Array) {
                    return Err(Error::protocol(format!("index {i} of a non-array")));
                }
                if cur.elements > 0 && *i >= cur.elements {
                    return Err(Error::protocol(format!(
                        "index {i} out of range {}",
                        cur.elements
                    )));
                }
                path.push(*i);
                cur = cur
                    .element
                    .as_deref()
                    .ok_or_else(|| Error::protocol(format!("index {i} past a leaf")))?;
            }
        }
    }
    Ok((path, cur))
}

/// Encodes steps as an `alternateAccess [5]` element's content, the form
/// libiec61850 produces: every step but the last a selectAlternateAccess, the
/// last a selectAccess.
pub fn alternate_access_element(steps: &[AccessStep]) -> Vec<u8> {
    fn build(steps: &[AccessStep]) -> Element {
        let (s, rest) = steps.split_first().expect("non-empty");
        if rest.is_empty() {
            return match s {
                AccessStep::Component(c) => prim(context_primitive(1), c.as_bytes().to_vec()),
                AccessStep::Index(i) => uint_elem(context_primitive(2), *i as u64),
            };
        }
        let sel = match s {
            AccessStep::Component(c) => prim(context_primitive(0), c.as_bytes().to_vec()),
            AccessStep::Index(i) => uint_elem(context_primitive(1), *i as u64),
        };
        cons(context_constructed(0), [sel, cons(TAG_SEQUENCE, [build(rest)])])
    }
    if steps.is_empty() {
        return Vec::new();
    }
    build(steps).encode()
}

/// Decodes a GetNamedVariableListAttributes-Response, keeping each member's
/// alternate access:
///
/// ```text
/// SEQUENCE { mmsDeletable [0] BOOLEAN,
///            listOfVariable [1] SEQUENCE OF SEQUENCE {
///              variableSpecification VariableSpecification,   -- name [0]
///              alternateAccess [5] IMPLICIT AlternateAccess OPTIONAL } }
/// ```
pub(crate) fn parse_list_members(content: &[u8]) -> Result<(Vec<ListMember>, bool)> {
    let mut inner = Decoder::new(content);
    let deletable = match inner.optional(context_primitive(0))? {
        Some(b) => asn1::decode_bool(b).unwrap_or(false),
        None => false,
    };
    let list = inner.expect(context_constructed(1))?;
    let mut out = Vec::new();
    let mut ld = Decoder::new(list);
    while ld.more() {
        let entry = ld.expect(TAG_SEQUENCE)?;
        let mut ed = Decoder::new(entry);
        let spec = ed.expect(context_constructed(0))?;
        let var = parse_object_name(spec)?;
        let alternate_access = ed
            .optional(context_constructed(5))?
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        out.push(ListMember {
            var,
            alternate_access,
        });
    }
    Ok((out, deletable))
}

impl Conn {
    /// Reads a named variable list's definition, keeping each member's
    /// alternate access, and whether the list is deletable (MMS
    /// getNamedVariableListAttributes, service 12).
    pub async fn get_named_variable_list_members(
        &self,
        domain: &str,
        list_name: &str,
    ) -> Result<(Vec<ListMember>, bool)> {
        let req = cons(
            context_constructed(SVC_GET_NAMED_VAR_LIST_ATTR),
            [object_name(domain, list_name)],
        );
        let resp = self.call_inner(req).await?;
        let content = Decoder::new(&resp).expect(context_constructed(SVC_GET_NAMED_VAR_LIST_ATTR))?;
        parse_list_members(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::Component;

    /// The GetNamedVariableListAttributes response libiec61850 v1.6's
    /// `server_example_complex_array` sends for `MHAI1$TestMHAI` (the content
    /// of the [12] response element), captured on the wire.
    const COMPLEX_ARRAY_NVL: &str = concat!(
        "800100a18201313030a029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617",
        "2a50382010730",
        "30a029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617",
        "2a5038201083",
        "03aa029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617",
        "2a50da00b810109300681046356616c",
        "3043a029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617",
        "2a516a014810",
        "10a300fa00d80046356616c300581036d6167",
        "304aa029a1271a1074657374436f6d706c657841727261791a134d48414931244d58244841247068734148617",
        "2a51da01b81010b3016a01480046356616c300ca00a80036d6167300381016",
        "6"
    );

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn c(s: &str) -> AccessStep {
        AccessStep::Component(s.into())
    }

    #[test]
    fn list_members_keep_their_alternate_access() {
        let (members, deletable) = parse_list_members(&hex(COMPLEX_ARRAY_NVL)).unwrap();
        assert!(!deletable);
        assert_eq!(members.len(), 5);
        let want = [
            vec![AccessStep::Index(7)],
            vec![AccessStep::Index(8)],
            vec![AccessStep::Index(9), c("cVal")],
            vec![AccessStep::Index(10), c("cVal"), c("mag")],
            vec![AccessStep::Index(11), c("cVal"), c("mag"), c("f")],
        ];
        for (i, m) in members.iter().enumerate() {
            assert_eq!(m.var, VarRef::new("testComplexArray", "MHAI1$MX$HA$phsAHar"));
            let steps = parse_alternate_access(&m.alternate_access).unwrap();
            assert_eq!(steps, want[i], "member {i}");
            // Re-encoding reproduces libiec61850's octets exactly.
            assert_eq!(alternate_access_element(&steps), m.alternate_access, "member {i}");
        }
    }

    #[test]
    fn an_access_path_resolves_against_the_type() {
        let float = || TypeSpec::scalar(Type::Float32);
        let analogue = || TypeSpec::structure(vec![Component { name: "f".into(), spec: float() }]);
        let vector = TypeSpec::structure(vec![
            Component { name: "mag".into(), spec: analogue() },
            Component { name: "ang".into(), spec: analogue() },
        ]);
        let cmv = TypeSpec::structure(vec![
            Component { name: "cVal".into(), spec: vector },
            Component { name: "q".into(), spec: TypeSpec::sized(Type::BitString, 13) },
        ]);
        let arr = TypeSpec::array(16, cmv);
        let (path, spec) = access_path(
            &arr,
            &[AccessStep::Index(11), c("cVal"), c("mag"), c("f")],
        )
        .unwrap();
        assert_eq!(path, [11, 0, 0, 0]);
        assert_eq!(spec.kind, Some(Type::Float32));
        assert!(access_path(&arr, &[AccessStep::Index(16)]).is_err());
        assert!(access_path(&arr, &[AccessStep::Index(1), c("nope")]).is_err());
        assert!(parse_alternate_access(&[0x84, 0x00]).is_err(), "allElements");
    }
}
