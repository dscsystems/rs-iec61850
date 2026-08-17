use crate::asn1::{
    self, bool_elem, cons, context_constructed, context_primitive, int_elem, prim, uint_elem,
    Class, Decoder, Element, TAG_INTEGER, TAG_SEQUENCE,
};

use super::value_codec::*;
use super::{Error, Result, Type, Value};

/// A named member of a structure [`TypeSpec`].
#[derive(Debug, Clone, PartialEq)]
pub struct Component {
    pub name: String,
    pub spec: TypeSpec,
}

/// Describes an MMS variable type as reported by
/// `getVariableAccessAttributes` (ISO 9506-2 `TypeSpecification`).
///
/// It is the raw material the client uses to reconstruct a server's data
/// model when no SCL file is available.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TypeSpec {
    pub kind: Option<Type>,
    /// Type-dependent: the bit width for integer and unsigned, the declared
    /// length for strings and octet strings (negative meaning variable up to
    /// `-size`), and the bit count for bit strings (negative meaning
    /// variable).
    pub size: i32,
    /// The declared element count of an array.
    pub elements: usize,
    /// The element type of an array.
    pub element: Option<Box<TypeSpec>>,
    /// Structure components in declaration order.
    pub components: Vec<Component>,
}

impl TypeSpec {
    /// Returns a scalar type specification.
    pub fn scalar(kind: Type) -> TypeSpec {
        TypeSpec {
            kind: Some(kind),
            ..Default::default()
        }
    }

    /// Returns a sized type specification (integer width, string length, bit
    /// count).
    pub fn sized(kind: Type, size: i32) -> TypeSpec {
        TypeSpec {
            kind: Some(kind),
            size,
            ..Default::default()
        }
    }

    /// Returns an array of `elements` copies of `element`.
    pub fn array(elements: usize, element: TypeSpec) -> TypeSpec {
        TypeSpec {
            kind: Some(Type::Array),
            elements,
            element: Some(Box::new(element)),
            ..Default::default()
        }
    }

    /// Returns a structure of the given named components.
    pub fn structure(components: Vec<Component>) -> TypeSpec {
        TypeSpec {
            kind: Some(Type::Structure),
            components,
            ..Default::default()
        }
    }

    /// Encodes the specification as a BER `TypeSpecification` CHOICE element.
    pub fn ber(&self) -> Option<Element> {
        let kind = self.kind?;
        let el = match kind {
            Type::Array => cons(
                context_constructed(TAG_DATA_ARRAY),
                [
                    uint_elem(context_primitive(1), self.elements as u64),
                    cons(
                        context_constructed(2),
                        self.element.as_ref().and_then(|e| e.ber()),
                    ),
                ],
            ),
            Type::Structure => {
                let comps = cons(
                    context_constructed(1),
                    self.components.iter().map(|c| {
                        cons(
                            TAG_SEQUENCE,
                            [
                                prim(context_primitive(0), c.name.as_bytes().to_vec()),
                                cons(context_constructed(1), c.spec.ber()),
                            ],
                        )
                    }),
                );
                cons(context_constructed(TAG_DATA_STRUCTURE), [comps])
            }
            Type::Boolean => prim(context_primitive(TAG_DATA_BOOLEAN), Vec::new()),
            Type::BitString => int_elem(
                context_primitive(TAG_DATA_BIT_STRING),
                i64::from(self.size),
            ),
            Type::Integer => uint_elem(context_primitive(TAG_DATA_INTEGER), self.size as u64),
            Type::Unsigned => uint_elem(context_primitive(TAG_DATA_UNSIGNED), self.size as u64),
            // Unlike float *values*, a floating-point type specification is a
            // constructed SEQUENCE of two INTEGERs: format width then
            // exponent width.
            Type::Float32 => cons(
                context_constructed(TAG_DATA_FLOAT),
                [int_elem(TAG_INTEGER, 32), int_elem(TAG_INTEGER, 8)],
            ),
            Type::Float64 => cons(
                context_constructed(TAG_DATA_FLOAT),
                [int_elem(TAG_INTEGER, 64), int_elem(TAG_INTEGER, 11)],
            ),
            Type::OctetString => int_elem(
                context_primitive(TAG_DATA_OCTET_STRING),
                i64::from(self.size),
            ),
            Type::VisibleString => int_elem(
                context_primitive(TAG_DATA_VIS_STRING),
                i64::from(self.size),
            ),
            Type::GeneralizedTime => prim(context_primitive(TAG_DATA_GEN_TIME), Vec::new()),
            Type::BinaryTime => bool_elem(context_primitive(TAG_DATA_BIN_TIME), true),
            Type::MmsString => int_elem(
                context_primitive(TAG_DATA_MMS_STRING),
                i64::from(self.size),
            ),
            Type::UtcTime => prim(context_primitive(TAG_DATA_UTC_TIME), Vec::new()),
            Type::None | Type::DataAccessError => return None,
        };
        Some(el)
    }

    /// Returns a zero value matching the specification, used by servers and
    /// tests to materialise a model.
    pub fn default_value(&self) -> Value {
        let Some(kind) = self.kind else {
            return Value::None;
        };
        match kind {
            Type::Array => {
                let element = self.element.as_deref();
                Value::Array(
                    (0..self.elements)
                        .map(|_| element.map_or(Value::None, TypeSpec::default_value))
                        .collect(),
                )
            }
            Type::Structure => Value::Structure(
                self.components
                    .iter()
                    .map(|c| c.spec.default_value())
                    .collect(),
            ),
            Type::Boolean => Value::boolean(false),
            Type::BitString => Value::bit_string(self.size.unsigned_abs() as usize),
            Type::Integer => Value::int64(0),
            Type::Unsigned => Value::uint32(0),
            Type::Float32 => Value::float32(0.0),
            Type::Float64 => Value::float64(0.0),
            Type::OctetString => Value::octet_string(Vec::new()),
            Type::VisibleString => Value::visible_string(""),
            Type::MmsString => Value::mms_string(""),
            Type::GeneralizedTime => Value::GeneralizedTime(Vec::new()),
            Type::BinaryTime => Value::BinaryTime(vec![0; 6]),
            Type::UtcTime => Value::UtcTime([0; 8]),
            Type::None | Type::DataAccessError => Value::None,
        }
    }
}

/// Decodes one `TypeSpecification` element from `dec`.
pub fn decode_type_spec(dec: &mut Decoder<'_>) -> Result<TypeSpec> {
    decode_type_spec_at(dec, 0)
}

fn decode_type_spec_at(dec: &mut Decoder<'_>, depth: usize) -> Result<TypeSpec> {
    if depth > MAX_VALUE_DEPTH {
        return Err(Error::protocol(format!(
            "type nesting exceeds {MAX_VALUE_DEPTH}"
        )));
    }
    let (tag, content) = dec.read_tlv()?;
    if tag.class != Class::ContextSpecific {
        return Err(Error::protocol(format!("type specification tag {tag}")));
    }
    let ts = match tag.number {
        TAG_DATA_ARRAY => {
            let mut inner = Decoder::new(content);
            // An optional packed flag, which this implementation ignores.
            inner.optional(context_primitive(0))?;
            let nc = inner.expect(context_primitive(1))?;
            let elements = asn1::decode_uint(nc)? as usize;
            let ec = inner.expect(context_constructed(2))?;
            let element = decode_type_spec_at(&mut Decoder::new(ec), depth + 1)?;
            TypeSpec::array(elements, element)
        }
        TAG_DATA_STRUCTURE => {
            let mut inner = Decoder::new(content);
            inner.optional(context_primitive(0))?; // packed
            let comps_content = inner.expect(context_constructed(1))?;
            let mut comps = Decoder::new(comps_content);
            let mut components = Vec::new();
            while comps.more() {
                let seq = comps.expect(TAG_SEQUENCE)?;
                let mut cd = Decoder::new(seq);
                let name = match cd.optional(context_primitive(0))? {
                    Some(n) => String::from_utf8_lossy(n).into_owned(),
                    None => String::new(),
                };
                let spec_content = cd.expect(context_constructed(1))?;
                let spec = decode_type_spec_at(&mut Decoder::new(spec_content), depth + 1)?;
                components.push(Component { name, spec });
            }
            TypeSpec::structure(components)
        }
        TAG_DATA_BOOLEAN => TypeSpec::scalar(Type::Boolean),
        TAG_DATA_BIT_STRING => {
            TypeSpec::sized(Type::BitString, asn1::decode_int(content)? as i32)
        }
        TAG_DATA_INTEGER => TypeSpec::sized(Type::Integer, asn1::decode_uint(content)? as i32),
        TAG_DATA_UNSIGNED => TypeSpec::sized(Type::Unsigned, asn1::decode_uint(content)? as i32),
        TAG_DATA_FLOAT => {
            // floating-point [7] IMPLICIT SEQUENCE { format-width, exponent-width }
            let mut fd = Decoder::new(content);
            let fw = fd.expect(TAG_INTEGER)?;
            let width = asn1::decode_int(fw)?;
            if width > 32 {
                TypeSpec::scalar(Type::Float64)
            } else {
                TypeSpec::scalar(Type::Float32)
            }
        }
        TAG_DATA_OCTET_STRING => {
            TypeSpec::sized(Type::OctetString, asn1::decode_int(content)? as i32)
        }
        TAG_DATA_VIS_STRING => {
            TypeSpec::sized(Type::VisibleString, asn1::decode_int(content)? as i32)
        }
        TAG_DATA_GEN_TIME => TypeSpec::scalar(Type::GeneralizedTime),
        TAG_DATA_BIN_TIME => TypeSpec::scalar(Type::BinaryTime),
        TAG_DATA_MMS_STRING => {
            TypeSpec::sized(Type::MmsString, asn1::decode_int(content)? as i32)
        }
        TAG_DATA_UTC_TIME => TypeSpec::scalar(Type::UtcTime),
        n => {
            return Err(Error::protocol(format!(
                "unsupported type specification tag [{n}]"
            )));
        }
    };
    Ok(ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(ts: &TypeSpec) -> TypeSpec {
        let encoded = ts.ber().expect("encodable").encode();
        decode_type_spec(&mut Decoder::new(&encoded)).expect("decode")
    }

    #[test]
    fn scalar_specifications_round_trip() {
        for ts in [
            TypeSpec::scalar(Type::Boolean),
            TypeSpec::sized(Type::Integer, 32),
            TypeSpec::sized(Type::Unsigned, 8),
            TypeSpec::scalar(Type::Float32),
            TypeSpec::scalar(Type::Float64),
            TypeSpec::sized(Type::VisibleString, 129),
            TypeSpec::sized(Type::OctetString, -64),
            TypeSpec::sized(Type::BitString, 13),
            TypeSpec::scalar(Type::UtcTime),
            TypeSpec::scalar(Type::BinaryTime),
            TypeSpec::scalar(Type::GeneralizedTime),
            TypeSpec::sized(Type::MmsString, 64),
        ] {
            assert_eq!(round_trip(&ts), ts, "round trip failed for {ts:?}");
        }
    }

    /// Floating-point type specifications are a constructed SEQUENCE of two
    /// INTEGERs (format width, exponent width), unlike float *values*, which
    /// are the primitive MMS FloatingPoint octet string. Getting this wrong
    /// makes every measurand in a retrieved model undecodable.
    #[test]
    fn a_float_type_specification_is_a_constructed_sequence_of_two_integers() {
        let el = TypeSpec::scalar(Type::Float32).ber().unwrap();
        let encoded = el.encode();
        assert_eq!(encoded[0], 0xa7, "float typespec must be constructed [7]");

        let mut dec = Decoder::new(&encoded);
        let content = dec.expect(context_constructed(TAG_DATA_FLOAT)).unwrap();
        let mut inner = Decoder::new(content);
        assert_eq!(asn1::decode_int(inner.expect(TAG_INTEGER).unwrap()).unwrap(), 32);
        assert_eq!(asn1::decode_int(inner.expect(TAG_INTEGER).unwrap()).unwrap(), 8);

        let el64 = TypeSpec::scalar(Type::Float64).ber().unwrap().encode();
        let mut dec = Decoder::new(&el64);
        let content = dec.expect(context_constructed(TAG_DATA_FLOAT)).unwrap();
        let mut inner = Decoder::new(content);
        assert_eq!(asn1::decode_int(inner.expect(TAG_INTEGER).unwrap()).unwrap(), 64);
        assert_eq!(asn1::decode_int(inner.expect(TAG_INTEGER).unwrap()).unwrap(), 11);
    }

    #[test]
    fn a_structure_round_trips_with_its_component_names_in_order() {
        // The shape of an MV as a server reports it.
        let ts = TypeSpec::structure(vec![
            Component {
                name: "mag".into(),
                spec: TypeSpec::structure(vec![Component {
                    name: "f".into(),
                    spec: TypeSpec::scalar(Type::Float32),
                }]),
            },
            Component {
                name: "q".into(),
                spec: TypeSpec::sized(Type::BitString, 13),
            },
            Component {
                name: "t".into(),
                spec: TypeSpec::scalar(Type::UtcTime),
            },
        ]);
        let back = round_trip(&ts);
        assert_eq!(back, ts);
        let names: Vec<&str> = back.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["mag", "q", "t"], "component order must be preserved");
    }

    #[test]
    fn arrays_round_trip_with_their_element_type() {
        let ts = TypeSpec::array(4, TypeSpec::sized(Type::Integer, 32));
        let back = round_trip(&ts);
        assert_eq!(back, ts);
        assert_eq!(back.elements, 4);
        assert_eq!(
            back.element.as_deref().unwrap().kind,
            Some(Type::Integer)
        );
    }

    #[test]
    fn default_values_match_the_shape_of_the_specification() {
        let ts = TypeSpec::structure(vec![
            Component {
                name: "f".into(),
                spec: TypeSpec::scalar(Type::Float32),
            },
            Component {
                name: "q".into(),
                spec: TypeSpec::sized(Type::BitString, 13),
            },
            Component {
                name: "arr".into(),
                spec: TypeSpec::array(3, TypeSpec::scalar(Type::Boolean)),
            },
        ]);
        let v = ts.default_value();
        assert_eq!(v.type_of(), Type::Structure);
        assert_eq!(v.len(), 3);
        assert_eq!(v.index(0).unwrap(), &Value::float32(0.0));
        assert_eq!(v.index(1).unwrap().bit_len(), 13);
        assert_eq!(v.index(2).unwrap().len(), 3);
    }

    #[test]
    fn a_variable_length_bit_string_still_yields_a_usable_default() {
        // A negative size means "variable up to N"; the default takes the
        // magnitude rather than panicking on the negative.
        let v = TypeSpec::sized(Type::BitString, -13).default_value();
        assert_eq!(v.bit_len(), 13);
    }

    #[test]
    fn unsupported_specifications_are_rejected() {
        assert!(TypeSpec::default().ber().is_none());
        assert_eq!(TypeSpec::default().default_value(), Value::None);

        let mut buf = Vec::new();
        asn1::append_tlv(&mut buf, context_primitive(8), &[0]);
        assert!(decode_type_spec(&mut Decoder::new(&buf)).is_err());

        let mut buf = Vec::new();
        asn1::append_tlv(&mut buf, asn1::TAG_SEQUENCE, &[]);
        assert!(decode_type_spec(&mut Decoder::new(&buf)).is_err());
    }
}
