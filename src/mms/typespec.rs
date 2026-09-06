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

/// Bounds on a decoded `TypeSpecification`.
///
/// A type specification comes from a peer and
/// [`default_value`](TypeSpec::default_value) materialises it, so every
/// declared size is an allocation request from an untrusted source. The
/// absurd ones are rejected at the decode boundary: a `Vec` of a trillion
/// elements does not fail gracefully, it aborts the process.
const MAX_ARRAY_ELEMENTS: usize = 1 << 16; // one declared array dimension
const MAX_BIT_STRING_BITS: i64 = 1 << 16; // declared bit-string width
const MAX_DEFAULT_VALUES: usize = 1 << 20; // total Values default_value may create

/// Saturates just past [`MAX_DEFAULT_VALUES`], so that a deeply nested array
/// cannot overflow the very count it is being checked against.
const VALUE_CEILING: usize = MAX_DEFAULT_VALUES + 1;

impl TypeSpec {
    /// Returns how many [`Value`]s [`default_value`](TypeSpec::default_value)
    /// would allocate, saturating at [`VALUE_CEILING`].
    fn value_count(&self) -> usize {
        match self.kind {
            Some(Type::Array) => {
                let per = self.element.as_deref().map_or(0, TypeSpec::value_count);
                if per == 0 || self.elements == 0 {
                    return 1;
                }
                if self.elements >= VALUE_CEILING / per {
                    return VALUE_CEILING;
                }
                1 + self.elements * per
            }
            Some(Type::Structure) => {
                let mut total = 1usize;
                for c in &self.components {
                    total = total.saturating_add(c.spec.value_count());
                    if total >= VALUE_CEILING {
                        return VALUE_CEILING;
                    }
                }
                total
            }
            _ => 1,
        }
    }
}

/// Decodes one `TypeSpecification` element from `dec`.
pub fn decode_type_spec(dec: &mut Decoder<'_>) -> Result<TypeSpec> {
    let ts = decode_type_spec_at(dec, 0)?;
    // The per-field caps bound each dimension on its own; nested arrays still
    // multiply, so the whole tree is costed once here.
    let n = ts.value_count();
    if n > MAX_DEFAULT_VALUES {
        return Err(Error::protocol(format!(
            "type specification materialises {n} values, over the {MAX_DEFAULT_VALUES} limit"
        )));
    }
    Ok(ts)
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
            let declared = asn1::decode_uint(nc)?;
            if declared > MAX_ARRAY_ELEMENTS as u64 {
                return Err(Error::protocol(format!(
                    "array of {declared} elements, over the {MAX_ARRAY_ELEMENTS} limit"
                )));
            }
            let elements = declared as usize;
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
            // A negative size is MMS's way of declaring a fixed-length bit
            // string, so the magnitude is what has to be bounded.
            let bits = asn1::decode_int(content)?;
            if !(-MAX_BIT_STRING_BITS..=MAX_BIT_STRING_BITS).contains(&bits) {
                return Err(Error::protocol(format!(
                    "bit string of {bits} bits, over the {MAX_BIT_STRING_BITS} limit"
                )));
            }
            TypeSpec::sized(Type::BitString, bits as i32)
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

    /// Encodes `array [1] { numberOfElements [1] n, elementType [2] elem }`
    /// with `n` written straight out, so a size no constructor would accept
    /// can still be put on the wire the way a peer would.
    fn hostile_array(n: u64, elem: Element) -> Element {
        cons(
            context_constructed(TAG_DATA_ARRAY),
            [
                uint_elem(context_primitive(1), n),
                cons(context_constructed(2), [elem]),
            ],
        )
    }

    /// Encodes `bit-string [4] IMPLICIT INTEGER` with an arbitrary width.
    fn hostile_bit_string(bits: i64) -> Element {
        crate::asn1::int_elem(context_primitive(TAG_DATA_BIT_STRING), bits)
    }

    /// Type specifications whose declared sizes are far larger than any real
    /// model, encoded as a peer could send them. Each is a handful of octets,
    /// so the cost of accepting one is unbounded relative to the cost of
    /// sending it.
    #[test]
    fn decoding_rejects_hostile_declared_sizes() {
        let boolean = || prim(context_primitive(TAG_DATA_BOOLEAN), Vec::new());
        let cases: Vec<(&str, Element)> = vec![
            // A 64-bit all-ones length, which is what a negative count
            // arrives as once it is read as unsigned.
            ("array/all-ones", hostile_array(u64::MAX, boolean())),
            // 16 GiB of values from a dozen octets.
            ("array/huge", hostile_array(1 << 31, boolean())),
            // Each dimension is individually plausible; the product is not.
            (
                "array/nested",
                hostile_array(
                    MAX_ARRAY_ELEMENTS as u64,
                    hostile_array(MAX_ARRAY_ELEMENTS as u64, boolean()),
                ),
            ),
            // bit_string allocates size/8 octets: a fatal allocation
            // failure, which aborts rather than unwinding.
            ("bitstring/huge", hostile_bit_string(1 << 40)),
            ("bitstring/min", hostile_bit_string(-(1i64 << 62))),
        ];
        for (name, element) in cases {
            let encoded = element.encode();
            let got = decode_type_spec(&mut Decoder::new(&encoded));
            assert!(
                got.is_err(),
                "{name}: accepted a {}-octet spec: {:?}",
                encoded.len(),
                got.ok()
            );
        }
    }

    /// A specification within the limits still decodes and materialises.
    #[test]
    fn decoding_accepts_realistic_declared_sizes() {
        let ts = TypeSpec::structure(vec![
            Component {
                name: "arr".into(),
                spec: TypeSpec::array(256, TypeSpec::scalar(Type::Boolean)),
            },
            Component {
                name: "q".into(),
                spec: TypeSpec::sized(Type::BitString, 13),
            },
            Component {
                name: "neg".into(),
                spec: TypeSpec::sized(Type::BitString, -64),
            },
        ]);
        let back = round_trip(&ts);
        let v = back.default_value();
        assert_eq!(v.len(), 3);
        assert_eq!(v.index(0).unwrap().len(), 256, "array elements");
        assert_eq!(v.index(1).unwrap().bit_len(), 13, "bit string width");
        // A negative size is a fixed-length declaration: the default value is
        // the full width, not an error.
        assert_eq!(v.index(2).unwrap().bit_len(), 64, "fixed-width bit string");
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

