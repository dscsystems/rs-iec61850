use crate::asn1::{context_constructed, Decoder};

use super::services::{parse_object_name, VarRef};
use super::{decode_access_result, Value};

/// An unconfirmed MMS InformationReport PDU, the transport for IEC 61850
/// buffered and unbuffered reports.
#[derive(Debug, Clone, Default)]
pub struct InformationReport {
    /// Set when the report references a named variable list. RCB reports use
    /// `"RPT"` as the conventional name. This holds only the item ID;
    /// [`list_ref`](InformationReport::list_ref) carries the domain as well.
    pub list_name: String,
    /// The item IDs of the `listOfVariable` form's entries, in the same order
    /// as `values`.
    pub var_names: Vec<String>,
    /// The decoded access results, in specification order.
    pub values: Vec<Value>,
    /// Reports that the access specification was a `variableListName` rather
    /// than a `listOfVariable`.
    pub is_vmd_named: bool,
    /// The fully scoped name of the referenced variable list. A proxy needs
    /// the domain as well as the item to attribute a report.
    pub list_ref: VarRef,
    /// The fully scoped names of the `listOfVariable` entries, in the same
    /// order as `values`. An entry is empty when the specification used an
    /// alternative other than `name [0]`.
    pub var_refs: Vec<VarRef>,
}

/// Decodes an InformationReport: a `variableAccessSpecification` CHOICE
/// followed by `listOfAccessResult SEQUENCE OF AccessResult`.
pub(crate) fn parse_information_report(body: &[u8]) -> Option<InformationReport> {
    let mut dec = Decoder::new(body);
    let mut rep = InformationReport::default();

    let spec = dec.peek().ok()?;
    // VariableAccessSpecification ::= CHOICE {
    //   listOfVariable   [0] IMPLICIT SEQUENCE OF ...,
    //   variableListName [1] ObjectName }
    //
    // Transposing these two decodes every IEC 61850 RCB report (which always
    // names a variable list) as a list of variable specifications, losing the
    // report's name.
    if spec == context_constructed(0) {
        // listOfVariable
        let (_, c) = dec.read_tlv().ok()?;
        parse_var_spec_list(c, &mut rep);
    } else if spec == context_constructed(1) {
        // variableListName
        let (_, c) = dec.read_tlv().ok()?;
        rep.is_vmd_named = true;
        if let Ok(r) = parse_object_name(c) {
            rep.list_name = r.item.clone();
            rep.list_ref = r;
        }
    } else {
        // An unknown specification; skip one element and try the results.
        dec.skip().ok()?;
    }

    // listOfAccessResult [0] IMPLICIT SEQUENCE OF AccessResult
    if let Ok(Some(ar_content)) = dec.optional(context_constructed(0)) {
        let mut ar = Decoder::new(ar_content);
        while ar.more() {
            match decode_access_result(&mut ar) {
                Ok(v) => rep.values.push(v),
                Err(_) => break,
            }
        }
    }
    Some(rep)
}

/// Decodes the `listOfVariable` form's VariableSpecifications.
///
/// Each entry is a CHOICE whose `name [0]` alternative carries an ObjectName;
/// other alternatives (address, variableDescription, scatteredAccess) leave an
/// empty entry so the positions still line up with `listOfAccessResult`.
fn parse_var_spec_list(content: &[u8], rep: &mut InformationReport) {
    let mut dec = Decoder::new(content);
    while dec.more() {
        let Ok((tag, vs)) = dec.read_tlv() else {
            return;
        };
        let mut r = VarRef::default();
        if tag == context_constructed(0) {
            // name [0] ObjectName
            if let Ok(parsed) = parse_object_name(vs) {
                r = parsed;
            }
        }
        rep.var_names.push(r.item.clone());
        rep.var_refs.push(r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::{cons, context_primitive, prim, TAG_SEQUENCE, TAG_VISIBLE_STRING};
    use crate::mms::{data_element, Value};

    fn object_name(domain: &str, item: &str) -> crate::asn1::Element {
        cons(
            context_constructed(1),
            [
                prim(TAG_VISIBLE_STRING, domain.as_bytes().to_vec()),
                prim(TAG_VISIBLE_STRING, item.as_bytes().to_vec()),
            ],
        )
    }

    /// Every IEC 61850 RCB report names a variable list. Decoding that as a
    /// list of variable specifications loses the report's identity.
    #[test]
    fn a_variable_list_name_report_keeps_its_name_and_domain() {
        let body = cons(
            TAG_SEQUENCE, // stand-in wrapper, only the children are decoded
            [],
        );
        let _ = body;

        let mut buf = Vec::new();
        cons(context_constructed(1), [object_name("ied1LD0", "RPT")]).append(&mut buf);
        cons(
            context_constructed(0),
            [
                data_element(&Value::visible_string("EventsRCB01")).unwrap(),
                data_element(&Value::uint32(7)).unwrap(),
            ],
        )
        .append(&mut buf);

        let rep = parse_information_report(&buf).expect("report parses");
        assert!(rep.is_vmd_named);
        assert_eq!(rep.list_name, "RPT");
        assert_eq!(rep.list_ref.domain, "ied1LD0");
        assert_eq!(rep.values.len(), 2);
        assert_eq!(rep.values[0].text(), "EventsRCB01");
        assert_eq!(rep.values[1].as_u32(), 7);
    }

    #[test]
    fn a_list_of_variable_report_keeps_each_member_reference() {
        let mut buf = Vec::new();
        cons(
            context_constructed(0),
            [
                cons(context_constructed(0), [object_name("ied1LD0", "GGIO1$ST$Ind1")]),
                cons(context_constructed(0), [object_name("ied1LD0", "GGIO1$ST$Ind2")]),
            ],
        )
        .append(&mut buf);
        cons(
            context_constructed(0),
            [
                data_element(&Value::boolean(true)).unwrap(),
                data_element(&Value::boolean(false)).unwrap(),
            ],
        )
        .append(&mut buf);

        let rep = parse_information_report(&buf).expect("report parses");
        assert!(!rep.is_vmd_named);
        assert_eq!(rep.var_names, ["GGIO1$ST$Ind1", "GGIO1$ST$Ind2"]);
        assert_eq!(rep.var_refs[0].domain, "ied1LD0");
        assert_eq!(rep.values.len(), 2);
        assert!(rep.values[0].as_bool() && !rep.values[1].as_bool());
    }

    /// Positions must still line up when a specification uses an alternative
    /// other than `name [0]`, or the values are attributed to the wrong
    /// members.
    #[test]
    fn an_unnamed_specification_still_occupies_its_position() {
        let mut buf = Vec::new();
        cons(
            context_constructed(0),
            [
                // address [1], which carries no name
                prim(context_primitive(1), vec![0x01, 0x02]),
                cons(context_constructed(0), [object_name("LD", "B")]),
            ],
        )
        .append(&mut buf);
        cons(
            context_constructed(0),
            [
                data_element(&Value::int32(1)).unwrap(),
                data_element(&Value::int32(2)).unwrap(),
            ],
        )
        .append(&mut buf);

        let rep = parse_information_report(&buf).expect("report parses");
        assert_eq!(rep.var_names.len(), 2);
        assert_eq!(rep.var_names[0], "", "the unnamed entry holds its slot");
        assert_eq!(rep.var_names[1], "B");
        assert_eq!(rep.values.len(), 2);
    }

    #[test]
    fn a_truncated_report_yields_what_was_decodable_rather_than_panicking() {
        assert!(parse_information_report(&[]).is_none());
        // A well-formed specification with no results is an empty report.
        let mut buf = Vec::new();
        cons(context_constructed(1), [object_name("LD", "RPT")]).append(&mut buf);
        let rep = parse_information_report(&buf).unwrap();
        assert!(rep.values.is_empty());
    }
}
