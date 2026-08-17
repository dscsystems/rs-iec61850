use std::time::SystemTime;

use crate::asn1::BitString;
use crate::time_util;

use super::DataAccessError;

/// Identifies the concrete kind of a [`Value`], mirroring the MMS `Data`
/// CHOICE plus `DataAccessError`, which surfaces per-element failures in read
/// results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    None,
    Array,
    Structure,
    Boolean,
    BitString,
    Integer,
    Unsigned,
    Float32,
    Float64,
    OctetString,
    VisibleString,
    GeneralizedTime,
    BinaryTime,
    MmsString,
    UtcTime,
    DataAccessError,
}

impl std::fmt::Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Type::None => "none",
            Type::Array => "array",
            Type::Structure => "structure",
            Type::Boolean => "boolean",
            Type::BitString => "bit-string",
            Type::Integer => "integer",
            Type::Unsigned => "unsigned",
            Type::Float32 => "float32",
            Type::Float64 => "float64",
            Type::OctetString => "octet-string",
            Type::VisibleString => "visible-string",
            Type::GeneralizedTime => "generalized-time",
            Type::BinaryTime => "binary-time",
            Type::MmsString => "mms-string",
            Type::UtcTime => "utc-time",
            Type::DataAccessError => "data-access-error",
        };
        f.write_str(s)
    }
}

/// The IEC 61850 `UtcTime` quality octet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeQuality(pub u8);

impl TimeQuality {
    pub const LEAP_SECONDS_KNOWN: TimeQuality = TimeQuality(0x80);
    pub const CLOCK_FAILURE: TimeQuality = TimeQuality(0x40);
    pub const CLOCK_NOT_SYNCHRONIZED: TimeQuality = TimeQuality(0x20);
    /// Declares no fraction accuracy.
    pub const ACCURACY_UNSPECIFIED: TimeQuality = TimeQuality(0x1f);

    /// Returns a quality declaring `n` bits of fraction accuracy, clamped to
    /// the 0..=24 the encoding allows.
    pub fn accuracy(n: u8) -> TimeQuality {
        TimeQuality(TimeQuality::LEAP_SECONDS_KNOWN.0 | n.min(24))
    }

    /// Returns the declared accuracy in bits of the second fraction.
    pub fn accuracy_bits(self) -> u8 {
        self.0 & 0x1f
    }

    pub fn has(self, flag: TimeQuality) -> bool {
        self.0 & flag.0 != 0
    }
}

/// An MMS data value: a tagged union over the MMS `Data` CHOICE.
///
/// [`Value::None`] is the empty value and is not valid on the wire.
///
/// Accessors are lenient in the same way the reference Go implementation is:
/// reading a value of the wrong family yields the zero of the requested type
/// rather than panicking, because report and read results routinely mix
/// types and callers should not have to match exhaustively to render one.
#[derive(Debug, Clone, Default)]
pub enum Value {
    #[default]
    None,
    Array(Vec<Value>),
    Structure(Vec<Value>),
    Boolean(bool),
    BitString(BitString),
    Integer(i64),
    Unsigned(u64),
    Float32(f32),
    Float64(f64),
    OctetString(Vec<u8>),
    VisibleString(Vec<u8>),
    GeneralizedTime(Vec<u8>),
    /// MMS `TimeOfDay`: 4 or 6 octets (milliseconds since midnight, and for
    /// the 6-octet form days since 1984-01-01).
    BinaryTime(Vec<u8>),
    MmsString(Vec<u8>),
    /// IEC 61850 `UtcTime`: seconds, a 24-bit second fraction and the time
    /// quality octet.
    UtcTime([u8; 8]),
    DataAccessError(DataAccessError),
}

// Constructors.
impl Value {
    pub fn boolean(v: bool) -> Value {
        Value::Boolean(v)
    }

    pub fn int8(v: i8) -> Value {
        Value::Integer(i64::from(v))
    }
    pub fn int16(v: i16) -> Value {
        Value::Integer(i64::from(v))
    }
    pub fn int32(v: i32) -> Value {
        Value::Integer(i64::from(v))
    }
    pub fn int64(v: i64) -> Value {
        Value::Integer(v)
    }

    pub fn uint8(v: u8) -> Value {
        Value::Unsigned(u64::from(v))
    }
    pub fn uint16(v: u16) -> Value {
        Value::Unsigned(u64::from(v))
    }
    pub fn uint32(v: u32) -> Value {
        Value::Unsigned(u64::from(v))
    }
    pub fn uint64(v: u64) -> Value {
        Value::Unsigned(v)
    }

    pub fn float32(v: f32) -> Value {
        Value::Float32(v)
    }
    pub fn float64(v: f64) -> Value {
        Value::Float64(v)
    }

    /// Returns an all-zero bit string of `length` bits.
    pub fn bit_string(length: usize) -> Value {
        Value::BitString(BitString::new(length))
    }

    /// Returns a bit string over a copy of `bits`.
    pub fn bit_string_bits(bits: &[u8], length: usize) -> Value {
        Value::BitString(BitString {
            bits: bits.to_vec(),
            length,
        })
    }

    pub fn octet_string(b: impl Into<Vec<u8>>) -> Value {
        Value::OctetString(b.into())
    }

    pub fn visible_string(s: impl AsRef<str>) -> Value {
        Value::VisibleString(s.as_ref().as_bytes().to_vec())
    }

    pub fn mms_string(s: impl AsRef<str>) -> Value {
        Value::MmsString(s.as_ref().as_bytes().to_vec())
    }

    pub fn generalized_time(s: impl AsRef<str>) -> Value {
        Value::GeneralizedTime(s.as_ref().as_bytes().to_vec())
    }

    pub fn array(elements: impl Into<Vec<Value>>) -> Value {
        Value::Array(elements.into())
    }

    pub fn structure(members: impl Into<Vec<Value>>) -> Value {
        Value::Structure(members.into())
    }

    /// Returns an IEC 61850 `UtcTime` value: seconds, a 24-bit second
    /// fraction and the time quality octet.
    pub fn utc_time(t: SystemTime, q: TimeQuality) -> Value {
        let (secs, nanos) = time_util::unix_parts(t);
        Value::utc_time_parts(secs, nanos, q)
    }

    /// Returns a `UtcTime` from an explicit second and nanosecond count.
    pub fn utc_time_parts(secs: i64, nanos: u32, q: TimeQuality) -> Value {
        // The fraction is the nanosecond count scaled into 24 bits.
        let frac = ((u64::from(nanos) << 24) / 1_000_000_000) as u32;
        let s = secs as u32;
        Value::UtcTime([
            (s >> 24) as u8,
            (s >> 16) as u8,
            (s >> 8) as u8,
            s as u8,
            (frac >> 16) as u8,
            (frac >> 8) as u8,
            frac as u8,
            q.0,
        ])
    }

    /// Returns the current time with 10 bits of declared accuracy.
    pub fn utc_time_now() -> Value {
        Value::utc_time(SystemTime::now(), TimeQuality::accuracy(10))
    }

    /// Wraps 8 raw `UtcTime` octets.
    pub fn utc_time_raw(b: &[u8]) -> super::Result<Value> {
        let arr: [u8; 8] = b.try_into().map_err(|_| {
            super::Error::protocol(format!("UtcTime needs 8 octets, got {}", b.len()))
        })?;
        Ok(Value::UtcTime(arr))
    }

    /// Returns an MMS `TimeOfDay` (6 octets: milliseconds since midnight,
    /// then days since 1984-01-01).
    pub fn binary_time(t: SystemTime) -> Value {
        let (secs, nanos) = time_util::unix_parts(t);
        let days_since_epoch = secs.div_euclid(86_400);
        let ms = (secs.rem_euclid(86_400) * 1000 + i64::from(nanos / 1_000_000)) as u32;
        let days = (days_since_epoch - time_util::BINARY_TIME_EPOCH_DAYS).max(0) as u16;
        Value::BinaryTime(vec![
            (ms >> 24) as u8,
            (ms >> 16) as u8,
            (ms >> 8) as u8,
            ms as u8,
            (days >> 8) as u8,
            days as u8,
        ])
    }

    /// Wraps a `DataAccessError` code as a value, as it appears inside read
    /// `AccessResult`s.
    pub fn access_error(code: DataAccessError) -> Value {
        Value::DataAccessError(code)
    }
}

// Accessors.
impl Value {
    /// Returns the value's type tag.
    pub fn type_of(&self) -> Type {
        match self {
            Value::None => Type::None,
            Value::Array(_) => Type::Array,
            Value::Structure(_) => Type::Structure,
            Value::Boolean(_) => Type::Boolean,
            Value::BitString(_) => Type::BitString,
            Value::Integer(_) => Type::Integer,
            Value::Unsigned(_) => Type::Unsigned,
            Value::Float32(_) => Type::Float32,
            Value::Float64(_) => Type::Float64,
            Value::OctetString(_) => Type::OctetString,
            Value::VisibleString(_) => Type::VisibleString,
            Value::GeneralizedTime(_) => Type::GeneralizedTime,
            Value::BinaryTime(_) => Type::BinaryTime,
            Value::MmsString(_) => Type::MmsString,
            Value::UtcTime(_) => Type::UtcTime,
            Value::DataAccessError(_) => Type::DataAccessError,
        }
    }

    /// Returns the boolean content, or false for any other type.
    pub fn as_bool(&self) -> bool {
        matches!(self, Value::Boolean(true))
    }

    /// Returns the value as a signed integer, converting from the other
    /// numeric families and truncating floats.
    pub fn as_i64(&self) -> i64 {
        match self {
            Value::Integer(n) => *n,
            Value::Unsigned(n) => *n as i64,
            Value::Boolean(b) => i64::from(*b),
            Value::Float32(f) => *f as i64,
            Value::Float64(f) => *f as i64,
            _ => 0,
        }
    }

    pub fn as_i32(&self) -> i32 {
        self.as_i64() as i32
    }

    pub fn as_u64(&self) -> u64 {
        match self {
            Value::Unsigned(n) => *n,
            _ => self.as_i64() as u64,
        }
    }

    pub fn as_u32(&self) -> u32 {
        self.as_u64() as u32
    }

    /// Returns the value as a double, converting from the integer families.
    pub fn as_f64(&self) -> f64 {
        match self {
            Value::Float32(f) => f64::from(*f),
            Value::Float64(f) => *f,
            Value::Integer(n) => *n as f64,
            Value::Unsigned(n) => *n as f64,
            _ => 0.0,
        }
    }

    pub fn as_f32(&self) -> f32 {
        self.as_f64() as f32
    }

    /// Returns the string content for string types, and the [`Display`]
    /// rendering otherwise.
    ///
    /// [`Display`]: std::fmt::Display
    pub fn text(&self) -> String {
        match self {
            Value::VisibleString(b) | Value::MmsString(b) | Value::GeneralizedTime(b) => {
                String::from_utf8_lossy(b).into_owned()
            }
            other => other.to_string(),
        }
    }

    /// Returns the raw content octets for bit strings (packed bits), octet
    /// strings, string types and the time types.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Value::BitString(bs) => &bs.bits,
            Value::OctetString(b)
            | Value::VisibleString(b)
            | Value::GeneralizedTime(b)
            | Value::BinaryTime(b)
            | Value::MmsString(b) => b,
            Value::UtcTime(b) => b,
            _ => &[],
        }
    }

    /// Returns the number of valid bits for bit strings.
    pub fn bit_len(&self) -> usize {
        match self {
            Value::BitString(bs) => bs.length,
            _ => 0,
        }
    }

    /// Returns bit `i` of a bit string (0 = MSB of the first octet).
    pub fn bit(&self, i: usize) -> bool {
        match self {
            Value::BitString(bs) => bs.bit(i),
            _ => false,
        }
    }

    /// Sets bit `i` of a bit string; out-of-range indices are ignored.
    pub fn set_bit(&mut self, i: usize, on: bool) {
        if let Value::BitString(bs) = self {
            bs.set_bit(i, on);
        }
    }

    /// Returns the number of children for arrays and structures.
    pub fn len(&self) -> usize {
        self.children().len()
    }

    /// Reports whether an array or structure has no children.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns child `i` of an array or structure.
    pub fn index(&self, i: usize) -> Option<&Value> {
        self.children().get(i)
    }

    /// Returns a mutable reference to child `i`.
    pub fn index_mut(&mut self, i: usize) -> Option<&mut Value> {
        self.children_mut().get_mut(i)
    }

    /// Returns the children of an array or structure, or an empty slice.
    pub fn children(&self) -> &[Value] {
        match self {
            Value::Array(c) | Value::Structure(c) => c,
            _ => &[],
        }
    }

    /// Returns the children of an array or structure mutably.
    pub fn children_mut(&mut self) -> &mut [Value] {
        match self {
            Value::Array(c) | Value::Structure(c) => c,
            _ => &mut [],
        }
    }

    /// Replaces child `i`; out-of-range indices are ignored.
    pub fn set_index(&mut self, i: usize, c: Value) {
        if let Some(slot) = self.index_mut(i) {
            *slot = c;
        }
    }

    /// Returns the `DataAccessError` code when the value is a per-element
    /// failure.
    pub fn as_access_error(&self) -> Option<DataAccessError> {
        match self {
            Value::DataAccessError(e) => Some(*e),
            _ => None,
        }
    }

    /// Converts `UtcTime` and `BinaryTime` values to a `SystemTime`.
    pub fn time(&self) -> Option<SystemTime> {
        match self {
            Value::UtcTime(b) => {
                let secs = i64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                let frac =
                    (u64::from(b[4]) << 16) | (u64::from(b[5]) << 8) | u64::from(b[6]);
                let nanos = ((frac * 1_000_000_000) >> 24) as u32;
                Some(time_util::from_unix(secs, nanos))
            }
            Value::BinaryTime(b) if b.len() == 4 || b.len() == 6 => {
                let ms = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
                let days = if b.len() == 6 {
                    i64::from(u16::from_be_bytes([b[4], b[5]]))
                } else {
                    0
                };
                let secs = (time_util::BINARY_TIME_EPOCH_DAYS + days) * 86_400
                    + i64::from(ms / 1000);
                Some(time_util::from_unix(secs, (ms % 1000) * 1_000_000))
            }
            _ => None,
        }
    }

    /// Returns the quality octet of a `UtcTime` value.
    pub fn time_quality(&self) -> TimeQuality {
        match self {
            Value::UtcTime(b) => TimeQuality(b[7]),
            _ => TimeQuality(0),
        }
    }
}

/// Deep equality of type and content.
///
/// Two NaN floats compare equal here: values are compared to decide whether a
/// report should fire, and a measurand that is NaN in both the old and new
/// sample has not changed.
impl PartialEq for Value {
    fn eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::None, Value::None) => true,
            (Value::Array(a), Value::Array(b)) | (Value::Structure(a), Value::Structure(b)) => {
                a == b
            }
            (Value::Boolean(a), Value::Boolean(b)) => a == b,
            (Value::BitString(a), Value::BitString(b)) => a == b,
            (Value::Integer(a), Value::Integer(b)) => a == b,
            (Value::Unsigned(a), Value::Unsigned(b)) => a == b,
            (Value::Float32(a), Value::Float32(b)) => a == b || (a.is_nan() && b.is_nan()),
            (Value::Float64(a), Value::Float64(b)) => a == b || (a.is_nan() && b.is_nan()),
            (Value::OctetString(a), Value::OctetString(b))
            | (Value::VisibleString(a), Value::VisibleString(b))
            | (Value::GeneralizedTime(a), Value::GeneralizedTime(b))
            | (Value::BinaryTime(a), Value::BinaryTime(b))
            | (Value::MmsString(a), Value::MmsString(b)) => a == b,
            (Value::UtcTime(a), Value::UtcTime(b)) => a == b,
            (Value::DataAccessError(a), Value::DataAccessError(b)) => a == b,
            _ => false,
        }
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::None => f.write_str("<none>"),
            Value::Boolean(b) => write!(f, "{b}"),
            Value::Integer(n) => write!(f, "{n}"),
            Value::Unsigned(n) => write!(f, "{n}"),
            Value::Float32(v) => write!(f, "{v}"),
            Value::Float64(v) => write!(f, "{v}"),
            Value::VisibleString(b) | Value::MmsString(b) | Value::GeneralizedTime(b) => {
                write!(f, "{:?}", String::from_utf8_lossy(b))
            }
            Value::OctetString(b) => {
                for byte in b {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Value::BitString(bs) => {
                for i in 0..bs.length {
                    f.write_str(if bs.bit(i) { "1" } else { "0" })?;
                }
                Ok(())
            }
            Value::UtcTime(_) | Value::BinaryTime(_) => match self.time() {
                Some(t) => f.write_str(&time_util::format_system_time(t)),
                None => f.write_str("<invalid-time>"),
            },
            Value::Array(c) => {
                f.write_str("[")?;
                for (i, v) in c.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Value::Structure(c) => {
                f.write_str("{")?;
                for (i, v) in c.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("}")
            }
            Value::DataAccessError(e) => write!(f, "error:{e}"),
        }
    }
}

// Conversions for the common literal cases, so callers can write
// `srv.set("...", 230.4)` rather than spelling out a constructor.
impl From<bool> for Value {
    fn from(v: bool) -> Value {
        Value::Boolean(v)
    }
}
impl From<i32> for Value {
    fn from(v: i32) -> Value {
        Value::Integer(i64::from(v))
    }
}
impl From<i64> for Value {
    fn from(v: i64) -> Value {
        Value::Integer(v)
    }
}
impl From<u32> for Value {
    fn from(v: u32) -> Value {
        Value::Unsigned(u64::from(v))
    }
}
impl From<u64> for Value {
    fn from(v: u64) -> Value {
        Value::Unsigned(v)
    }
}
impl From<f32> for Value {
    fn from(v: f32) -> Value {
        Value::Float32(v)
    }
}
impl From<f64> for Value {
    fn from(v: f64) -> Value {
        Value::Float64(v)
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Value {
        Value::visible_string(v)
    }
}
impl From<String> for Value {
    fn from(v: String) -> Value {
        Value::VisibleString(v.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::time::UNIX_EPOCH;

    #[test]
    fn numeric_accessors_convert_across_families() {
        assert_eq!(Value::int32(-5).as_i64(), -5);
        assert_eq!(Value::uint32(230).as_i64(), 230);
        assert_eq!(Value::float32(230.4).as_i64(), 230, "floats truncate");
        assert_eq!(Value::int32(7).as_f64(), 7.0);
        assert_eq!(Value::boolean(true).as_i64(), 1);
        // The wrong family yields a zero rather than panicking.
        assert_eq!(Value::visible_string("x").as_i64(), 0);
        assert_eq!(Value::visible_string("x").as_f64(), 0.0);
        assert!(!Value::int32(1).as_bool());
    }

    #[test]
    fn utc_time_round_trips_to_within_the_fraction_resolution() {
        // The 24-bit fraction resolves to about 60 ns, so compare with a
        // tolerance rather than for equality.
        let t = UNIX_EPOCH + Duration::new(1_786_838_400, 123_456_789);
        let v = Value::utc_time(t, TimeQuality::accuracy(10));
        let back = v.time().unwrap();
        let delta = back.duration_since(t).unwrap_or_else(|e| e.duration());
        assert!(delta < Duration::from_nanos(120), "delta was {delta:?}");
        assert_eq!(v.time_quality().accuracy_bits(), 10);
        assert!(v.time_quality().has(TimeQuality::LEAP_SECONDS_KNOWN));
        assert_eq!(v.bytes().len(), 8);
    }

    #[test]
    fn binary_time_round_trips_to_the_millisecond() {
        let t = UNIX_EPOCH + Duration::new(1_786_838_400, 250_000_000);
        let v = Value::binary_time(t);
        assert_eq!(v.bytes().len(), 6);
        let back = v.time().unwrap();
        assert_eq!(back, UNIX_EPOCH + Duration::new(1_786_838_400, 250_000_000));
    }

    #[test]
    fn bit_strings_expose_individual_bits() {
        let mut v = Value::bit_string(13);
        v.set_bit(0, true);
        v.set_bit(12, true);
        assert_eq!(v.bit_len(), 13);
        assert!(v.bit(0) && v.bit(12) && !v.bit(1));
        assert!(!v.bit(99), "out of range reads false");
        assert_eq!(v.to_string(), "1000000000001");
    }

    #[test]
    fn nested_values_expose_their_children() {
        let v = Value::structure(vec![
            Value::float32(230.4),
            Value::bit_string(13),
            Value::array(vec![Value::int32(1), Value::int32(2)]),
        ]);
        assert_eq!(v.len(), 3);
        assert_eq!(v.index(0).unwrap().as_f32(), 230.4);
        assert_eq!(v.index(2).unwrap().len(), 2);
        assert!(v.index(9).is_none());
        // A scalar has no children rather than erroring.
        assert_eq!(Value::int32(1).len(), 0);
    }

    #[test]
    fn equality_is_deep_and_treats_nan_as_unchanged() {
        let a = Value::structure(vec![Value::int32(1), Value::visible_string("x")]);
        assert_eq!(a, a.clone());
        assert_ne!(a, Value::structure(vec![Value::int32(2), Value::visible_string("x")]));
        // Different families are never equal, even at the same numeric value.
        assert_ne!(Value::int32(1), Value::uint32(1));
        // A measurand that is NaN in both samples has not changed.
        assert_eq!(Value::float32(f32::NAN), Value::float32(f32::NAN));
        assert_ne!(Value::float32(1.0), Value::float32(2.0));
    }

    #[test]
    fn display_renders_each_family_readably() {
        assert_eq!(Value::boolean(true).to_string(), "true");
        assert_eq!(Value::int32(-5).to_string(), "-5");
        assert_eq!(Value::visible_string("hi").to_string(), "\"hi\"");
        assert_eq!(Value::octet_string(vec![0xde, 0xad]).to_string(), "dead");
        assert_eq!(
            Value::array(vec![Value::int32(1), Value::int32(2)]).to_string(),
            "[1, 2]"
        );
        assert_eq!(
            Value::structure(vec![Value::boolean(false)]).to_string(),
            "{false}"
        );
        assert_eq!(
            Value::access_error(DataAccessError::ObjectNonExistent).to_string(),
            "error:object-non-existent"
        );
    }

    #[test]
    fn text_returns_string_content_and_falls_back_to_display() {
        assert_eq!(Value::visible_string("text").text(), "text");
        assert_eq!(Value::mms_string("text").text(), "text");
        assert_eq!(Value::int32(42).text(), "42");
    }

    #[test]
    fn from_impls_cover_the_common_literals() {
        assert_eq!(Value::from(true), Value::Boolean(true));
        assert_eq!(Value::from(-5i32), Value::Integer(-5));
        assert_eq!(Value::from(230u32), Value::Unsigned(230));
        assert_eq!(Value::from(230.4f32), Value::Float32(230.4));
        assert_eq!(Value::from("s"), Value::visible_string("s"));
    }

    #[test]
    fn utc_time_raw_rejects_a_wrong_length() {
        assert!(Value::utc_time_raw(&[0; 8]).is_ok());
        assert!(Value::utc_time_raw(&[0; 7]).is_err());
        assert!(Value::utc_time_raw(&[]).is_err());
    }
}
