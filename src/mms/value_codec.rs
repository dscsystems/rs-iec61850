use crate::asn1::{
    self, bit_string_elem, bool_elem, cons, context_constructed, context_primitive, int_elem,
    prim, uint_elem, Class, Decoder, Element, Tag,
};

use super::{DataAccessError, Error, Result, Value};

/// MMS `Data` CHOICE context tags (ISO 9506-2).
pub(crate) const TAG_DATA_ARRAY: u32 = 1;
pub(crate) const TAG_DATA_STRUCTURE: u32 = 2;
pub(crate) const TAG_DATA_BOOLEAN: u32 = 3;
pub(crate) const TAG_DATA_BIT_STRING: u32 = 4;
pub(crate) const TAG_DATA_INTEGER: u32 = 5;
pub(crate) const TAG_DATA_UNSIGNED: u32 = 6;
pub(crate) const TAG_DATA_FLOAT: u32 = 7;
pub(crate) const TAG_DATA_OCTET_STRING: u32 = 9;
pub(crate) const TAG_DATA_VIS_STRING: u32 = 10;
pub(crate) const TAG_DATA_GEN_TIME: u32 = 11;
pub(crate) const TAG_DATA_BIN_TIME: u32 = 12;
pub(crate) const TAG_DATA_MMS_STRING: u32 = 16;
pub(crate) const TAG_DATA_UTC_TIME: u32 = 17;

/// Nesting limit for values and type specifications.
pub(crate) const MAX_VALUE_DEPTH: usize = 32;

/// Converts a value into its BER element as an MMS `Data` CHOICE.
///
/// Returns `None` for [`Value::None`], which has no wire representation.
pub fn data_element(v: &Value) -> Option<Element> {
    let el = match v {
        Value::None => return None,
        Value::Array(children) | Value::Structure(children) => {
            let n = if matches!(v, Value::Array(_)) {
                TAG_DATA_ARRAY
            } else {
                TAG_DATA_STRUCTURE
            };
            cons(
                context_constructed(n),
                children.iter().filter_map(data_element),
            )
        }
        Value::Boolean(b) => bool_elem(context_primitive(TAG_DATA_BOOLEAN), *b),
        Value::BitString(bs) => bit_string_elem(context_primitive(TAG_DATA_BIT_STRING), bs),
        Value::Integer(n) => int_elem(context_primitive(TAG_DATA_INTEGER), *n),
        Value::Unsigned(n) => uint_elem(context_primitive(TAG_DATA_UNSIGNED), *n),
        Value::Float32(f) => {
            let mut buf = Vec::with_capacity(5);
            asn1::append_float32(&mut buf, *f);
            prim(context_primitive(TAG_DATA_FLOAT), buf)
        }
        Value::Float64(f) => {
            let mut buf = Vec::with_capacity(9);
            asn1::append_float64(&mut buf, *f);
            prim(context_primitive(TAG_DATA_FLOAT), buf)
        }
        Value::OctetString(b) => prim(context_primitive(TAG_DATA_OCTET_STRING), b.clone()),
        Value::VisibleString(b) => prim(context_primitive(TAG_DATA_VIS_STRING), b.clone()),
        Value::GeneralizedTime(b) => prim(context_primitive(TAG_DATA_GEN_TIME), b.clone()),
        Value::BinaryTime(b) => prim(context_primitive(TAG_DATA_BIN_TIME), b.clone()),
        Value::MmsString(b) => prim(context_primitive(TAG_DATA_MMS_STRING), b.clone()),
        Value::UtcTime(b) => prim(context_primitive(TAG_DATA_UTC_TIME), b.to_vec()),
        // Only valid inside an AccessResult, where it is encoded as [0] INTEGER.
        Value::DataAccessError(e) => {
            uint_elem(context_primitive(0), u64::from(e.code()))
        }
    };
    Some(el)
}

/// Encodes `v` as an MMS `Data` CHOICE element onto `dst`.
pub fn append_data(dst: &mut Vec<u8>, v: &Value) {
    if let Some(el) = data_element(v) {
        el.append(dst);
    }
}

/// Encodes `v` as a fresh buffer.
pub fn encode_data(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    append_data(&mut out, v);
    out
}

/// Decodes one MMS `Data` CHOICE element from `dec`.
pub fn decode_data(dec: &mut Decoder<'_>) -> Result<Value> {
    decode_data_at(dec, 0)
}

fn decode_data_at(dec: &mut Decoder<'_>, depth: usize) -> Result<Value> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::protocol(format!(
            "data nesting exceeds {MAX_VALUE_DEPTH}"
        )));
    }
    let (tag, content) = dec.read_tlv()?;
    decode_data_tlv(tag, content, depth)
}

fn decode_data_tlv(tag: Tag, content: &[u8], depth: usize) -> Result<Value> {
    if tag.class != Class::ContextSpecific {
        return Err(Error::protocol(format!("data with tag {tag}")));
    }
    let v = match tag.number {
        TAG_DATA_ARRAY | TAG_DATA_STRUCTURE => {
            let mut children = Vec::new();
            let mut inner = Decoder::new(content);
            while inner.more() {
                children.push(decode_data_at(&mut inner, depth + 1)?);
            }
            if tag.number == TAG_DATA_ARRAY {
                Value::Array(children)
            } else {
                Value::Structure(children)
            }
        }
        TAG_DATA_BOOLEAN => Value::Boolean(asn1::decode_bool(content)?),
        TAG_DATA_BIT_STRING => Value::BitString(asn1::decode_bit_string(content)?),
        TAG_DATA_INTEGER => Value::Integer(asn1::decode_int(content)?),
        TAG_DATA_UNSIGNED => Value::Unsigned(asn1::decode_uint(content)?),
        TAG_DATA_FLOAT => {
            let f = asn1::decode_float(content)?;
            // The exponent-width octet plus a 4- or 8-octet mantissa tells
            // the two widths apart.
            if content.len() == 5 {
                Value::Float32(f as f32)
            } else {
                Value::Float64(f)
            }
        }
        TAG_DATA_OCTET_STRING => Value::OctetString(content.to_vec()),
        TAG_DATA_VIS_STRING => Value::VisibleString(content.to_vec()),
        TAG_DATA_GEN_TIME => Value::GeneralizedTime(content.to_vec()),
        TAG_DATA_BIN_TIME => {
            if content.len() != 4 && content.len() != 6 {
                return Err(Error::protocol(format!(
                    "binary-time of {} octets",
                    content.len()
                )));
            }
            Value::BinaryTime(content.to_vec())
        }
        TAG_DATA_MMS_STRING => Value::MmsString(content.to_vec()),
        TAG_DATA_UTC_TIME => Value::utc_time_raw(content)?,
        n => {
            return Err(Error::protocol(format!("unsupported data tag [{n}]")));
        }
    };
    Ok(v)
}

/// Decodes one MMS `AccessResult`: either `[0]` failure (returned as a
/// [`Value::DataAccessError`]) or a `Data` success.
pub fn decode_access_result(dec: &mut Decoder<'_>) -> Result<Value> {
    let tag = dec.peek()?;
    if tag.class == Class::ContextSpecific && tag.number == 0 && !tag.constructed {
        let (_, content) = dec.read_tlv()?;
        let code = asn1::decode_uint(content)?;
        return Ok(Value::access_error(DataAccessError::from_code(code as u8)));
    }
    decode_data(dec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::TimeQuality;

    fn round_trip(v: &Value) -> Value {
        let encoded = encode_data(v);
        let mut dec = Decoder::new(&encoded);
        let back = decode_data(&mut dec).expect("decode");
        assert!(!dec.more(), "decoder left trailing bytes for {v}");
        back
    }

    #[test]
    fn every_scalar_family_round_trips() {
        for v in [
            Value::boolean(true),
            Value::boolean(false),
            Value::int32(-5),
            Value::int64(i64::MIN),
            Value::uint32(230),
            Value::float32(230.4),
            Value::float64(-1.5e300),
            Value::octet_string(vec![1, 2, 3]),
            Value::visible_string("simpleIOGenericIO"),
            Value::mms_string("text"),
            Value::bit_string_bits(&[0x80, 0x08], 13),
            Value::utc_time_parts(1_786_838_400, 0, TimeQuality::accuracy(10)),
            Value::binary_time(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_786_838_400)),
        ] {
            assert_eq!(round_trip(&v), v, "round trip failed for {v}");
        }
    }

    #[test]
    fn float_width_is_preserved_across_the_round_trip() {
        // The two widths share one tag and are told apart by content length,
        // so a float32 must not come back as a float64.
        assert_eq!(round_trip(&Value::float32(1.0)).type_of(), super::super::Type::Float32);
        assert_eq!(round_trip(&Value::float64(1.0)).type_of(), super::super::Type::Float64);
        assert_eq!(encode_data(&Value::float32(1.0)).len(), 7);
        assert_eq!(encode_data(&Value::float64(1.0)).len(), 11);
    }

    #[test]
    fn nested_structures_and_arrays_round_trip() {
        // The shape of a typical MV: { mag: { f }, q, t }.
        let v = Value::structure(vec![
            Value::structure(vec![Value::float32(230.4)]),
            Value::bit_string_bits(&[0x00, 0x00], 13),
            Value::utc_time_parts(1_786_838_400, 500_000_000, TimeQuality::accuracy(10)),
            Value::array(vec![Value::int32(1), Value::int32(2), Value::int32(3)]),
        ]);
        assert_eq!(round_trip(&v), v);
    }

    #[test]
    fn a_none_value_encodes_to_nothing() {
        assert!(data_element(&Value::None).is_none());
        assert!(encode_data(&Value::None).is_empty());
    }

    #[test]
    fn access_results_carry_either_a_failure_code_or_data() {
        let failure = encode_data(&Value::access_error(DataAccessError::ObjectNonExistent));
        let mut dec = Decoder::new(&failure);
        assert_eq!(
            decode_access_result(&mut dec).unwrap().as_access_error(),
            Some(DataAccessError::ObjectNonExistent)
        );

        let success = encode_data(&Value::int32(7));
        let mut dec = Decoder::new(&success);
        assert_eq!(decode_access_result(&mut dec).unwrap(), Value::int32(7));
    }

    #[test]
    fn a_universal_class_tag_is_not_mms_data() {
        // MMS Data is entirely context-specific; a SEQUENCE here means the
        // caller is decoding at the wrong place in the PDU.
        let mut buf = Vec::new();
        asn1::append_tlv(&mut buf, asn1::TAG_SEQUENCE, &[]);
        let mut dec = Decoder::new(&buf);
        assert!(decode_data(&mut dec).is_err());
    }

    #[test]
    fn unsupported_and_malformed_data_is_rejected() {
        // [8] is not a Data alternative this crate handles.
        let mut buf = Vec::new();
        asn1::append_tlv(&mut buf, context_primitive(8), &[0]);
        assert!(decode_data(&mut Decoder::new(&buf)).is_err());

        // A binary time must be 4 or 6 octets.
        let mut buf = Vec::new();
        asn1::append_tlv(&mut buf, context_primitive(TAG_DATA_BIN_TIME), &[0; 5]);
        assert!(decode_data(&mut Decoder::new(&buf)).is_err());

        // A UtcTime must be exactly 8.
        let mut buf = Vec::new();
        asn1::append_tlv(&mut buf, context_primitive(TAG_DATA_UTC_TIME), &[0; 7]);
        assert!(decode_data(&mut Decoder::new(&buf)).is_err());
    }

    #[test]
    fn deeply_nested_data_is_rejected_rather_than_overflowing_the_stack() {
        let mut buf = Vec::new();
        let depth = MAX_VALUE_DEPTH + 8;
        // Innermost value, then wrap it repeatedly in structures.
        let mut inner = encode_data(&Value::boolean(true));
        for _ in 0..depth {
            let mut next = Vec::new();
            asn1::append_tlv(&mut next, context_constructed(TAG_DATA_STRUCTURE), &inner);
            inner = next;
        }
        buf.extend_from_slice(&inner);
        assert!(decode_data(&mut Decoder::new(&buf)).is_err());
    }
}
