use super::{prim, Element, Error, Result, Tag};

/// Appends the minimal two's-complement content octets for `v` (no tag or
/// length).
pub fn append_int(dst: &mut Vec<u8>, v: i64) {
    let n = int_size(v);
    for i in (0..n).rev() {
        dst.push((v >> (i * 8)) as u8);
    }
}

/// Returns the minimal two's-complement octet count for `v`.
pub fn int_size(v: i64) -> usize {
    let mut n = 1;
    let mut v = v;
    while !(-0x80..=0x7f).contains(&v) {
        v >>= 8;
        n += 1;
    }
    n
}

/// Decodes two's-complement content octets.
pub fn decode_int(content: &[u8]) -> Result<i64> {
    if content.is_empty() || content.len() > 8 {
        return Err(Error::bad_value(format!(
            "integer of {} octets",
            content.len()
        )));
    }
    let mut v = i64::from(content[0] as i8); // sign-extend
    for &b in &content[1..] {
        v = (v << 8) | i64::from(b);
    }
    Ok(v)
}

/// Appends minimal unsigned content octets for `v`, adding a leading zero
/// octet when the high bit would otherwise read as a sign.
pub fn append_uint(dst: &mut Vec<u8>, v: u64) {
    let n = uint_size(v);
    for i in (0..n).rev() {
        // A 9-octet encoding (top bit set in a full-width value) shifts by 64
        // for the leading pad octet, which is exactly the zero we want.
        dst.push(v.checked_shr((i * 8) as u32).unwrap_or(0) as u8);
    }
}

/// Returns the octet count [`append_uint`] produces for `v`.
pub fn uint_size(v: u64) -> usize {
    let mut n = 1;
    let mut v = v;
    while v > 0x7f {
        v >>= 8;
        n += 1;
    }
    n
}

/// Decodes unsigned content octets.
///
/// A leading zero octet is permitted, as produced for values with the top
/// bit set.
pub fn decode_uint(content: &[u8]) -> Result<u64> {
    if content.is_empty() {
        return Err(Error::bad_value("empty unsigned"));
    }
    if content.len() > 9 || (content.len() == 9 && content[0] != 0) {
        return Err(Error::bad_value(format!(
            "unsigned of {} octets",
            content.len()
        )));
    }
    let mut v: u64 = 0;
    for &b in content {
        v = (v << 8) | u64::from(b);
    }
    Ok(v)
}

/// Returns an INTEGER-content primitive element with tag `t`.
pub fn int_elem(t: Tag, v: i64) -> Element {
    let mut buf = Vec::with_capacity(int_size(v));
    append_int(&mut buf, v);
    prim(t, buf)
}

/// Returns an unsigned-content primitive element with tag `t`.
pub fn uint_elem(t: Tag, v: u64) -> Element {
    let mut buf = Vec::with_capacity(uint_size(v));
    append_uint(&mut buf, v);
    prim(t, buf)
}

/// Returns a BOOLEAN-content primitive element with tag `t`.
pub fn bool_elem(t: Tag, v: bool) -> Element {
    prim(t, if v { vec![0xff] } else { vec![0x00] })
}

/// Decodes BOOLEAN content octets.
pub fn decode_bool(content: &[u8]) -> Result<bool> {
    if content.len() != 1 {
        return Err(Error::bad_value(format!(
            "boolean of {} octets",
            content.len()
        )));
    }
    Ok(content[0] != 0)
}

/// A BER bit string: `bits` holds the packed bits MSB-first, `length` is the
/// number of valid bits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BitString {
    pub bits: Vec<u8>,
    pub length: usize,
}

impl BitString {
    /// Returns an all-zero bit string of `n` bits.
    pub fn new(n: usize) -> BitString {
        BitString {
            bits: vec![0; n.div_ceil(8)],
            length: n,
        }
    }

    /// Returns bit `i` (0 = MSB of the first octet), false when out of range.
    pub fn bit(&self, i: usize) -> bool {
        if i >= self.length {
            return false;
        }
        self.bits[i / 8] & (0x80 >> (i % 8)) != 0
    }

    /// Sets bit `i` to `v`; out-of-range indices are ignored.
    pub fn set_bit(&mut self, i: usize, v: bool) {
        if i >= self.length {
            return;
        }
        if v {
            self.bits[i / 8] |= 0x80 >> (i % 8);
        } else {
            self.bits[i / 8] &= !(0x80 >> (i % 8));
        }
    }

    /// Returns the bit string as a `u32`, bit 0 being the most significant
    /// bit of the first octet. Used by the fixed-width IEC 61850 bit strings
    /// (Quality, TrgOps, OptFlds).
    pub fn to_u32(&self) -> u32 {
        let mut v = 0u32;
        for i in 0..self.length.min(32) {
            if self.bit(i) {
                v |= 1 << i;
            }
        }
        v
    }

    /// Returns an `n`-bit string built from `v`, bit 0 being the most
    /// significant bit of the first octet.
    pub fn from_u32(v: u32, n: usize) -> BitString {
        let mut bs = BitString::new(n);
        for i in 0..n.min(32) {
            bs.set_bit(i, v & (1 << i) != 0);
        }
        bs
    }
}

/// Appends bit string content octets (padding count prefix then packed bits).
pub fn append_bit_string(dst: &mut Vec<u8>, bs: &BitString) {
    let pad = bs.bits.len() * 8 - bs.length;
    dst.push(pad as u8);
    dst.extend_from_slice(&bs.bits);
}

/// Decodes bit string content octets.
pub fn decode_bit_string(content: &[u8]) -> Result<BitString> {
    if content.is_empty() {
        return Err(Error::bad_value("empty bit string"));
    }
    let pad = usize::from(content[0]);
    let bits = &content[1..];
    if pad > 7 || (bits.is_empty() && pad != 0) {
        return Err(Error::bad_value(format!("bit string padding {pad}")));
    }
    Ok(BitString {
        bits: bits.to_vec(),
        length: bits.len() * 8 - pad,
    })
}

/// Returns a bit-string-content primitive element with tag `t`.
pub fn bit_string_elem(t: Tag, bs: &BitString) -> Element {
    let mut buf = Vec::with_capacity(bs.bits.len() + 1);
    append_bit_string(&mut buf, bs);
    prim(t, buf)
}

/// Appends MMS FloatingPoint content octets for a 32-bit IEEE 754 value:
/// one exponent-width octet (8) then the big-endian value.
///
/// MMS floats are not ASN.1 REALs; this format is shared by MMS, GOOSE and
/// SV, so it lives here.
pub fn append_float32(dst: &mut Vec<u8>, v: f32) {
    dst.push(8);
    dst.extend_from_slice(&v.to_bits().to_be_bytes());
}

/// Appends MMS FloatingPoint content octets for a 64-bit IEEE 754 value
/// (exponent width 11).
pub fn append_float64(dst: &mut Vec<u8>, v: f64) {
    dst.push(11);
    dst.extend_from_slice(&v.to_bits().to_be_bytes());
}

/// Decodes MMS FloatingPoint content octets into an `f64` (exact for both
/// widths).
pub fn decode_float(content: &[u8]) -> Result<f64> {
    match content.len() {
        5 => {
            let bits = u32::from_be_bytes([content[1], content[2], content[3], content[4]]);
            Ok(f64::from(f32::from_bits(bits)))
        }
        9 => {
            let mut bits: u64 = 0;
            for &b in &content[1..] {
                bits = (bits << 8) | u64::from(b);
            }
            Ok(f64::from_bits(bits))
        }
        _ => Err(Error::bad_value(format!(
            "floating point of {} octets",
            content.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn integers_round_trip_at_the_width_boundaries() {
        for v in [
            0i64, 1, -1, 127, -128, 128, -129, 32767, -32768, i64::MAX, i64::MIN,
        ] {
            let mut buf = Vec::new();
            append_int(&mut buf, v);
            assert_eq!(buf.len(), int_size(v), "int_size disagrees for {v}");
            assert_eq!(decode_int(&buf).unwrap(), v);
        }
    }

    #[test]
    fn unsigned_values_get_a_leading_zero_when_the_top_bit_is_set() {
        let mut buf = Vec::new();
        append_uint(&mut buf, 0x80);
        assert_eq!(buf, vec![0x00, 0x80], "must not read back as negative");
        assert_eq!(decode_uint(&buf).unwrap(), 0x80);

        for v in [0u64, 1, 0x7f, 0x80, 0xffff, u64::MAX] {
            let mut b = Vec::new();
            append_uint(&mut b, v);
            assert_eq!(b.len(), uint_size(v));
            assert_eq!(decode_uint(&b).unwrap(), v);
        }
    }

    #[test]
    fn bit_strings_round_trip_with_padding() {
        // The 13-bit Quality bit string is the motivating case.
        let mut bs = BitString::new(13);
        bs.set_bit(0, true);
        bs.set_bit(12, true);
        let mut buf = Vec::new();
        append_bit_string(&mut buf, &bs);
        assert_eq!(buf[0], 3, "13 bits in 2 octets leaves 3 padding bits");
        let back = decode_bit_string(&buf).unwrap();
        assert_eq!(back.length, 13);
        assert!(back.bit(0) && back.bit(12) && !back.bit(1));
    }

    #[test]
    fn bit_string_u32_conversion_is_symmetric() {
        let bs = BitString::from_u32(0b1_0000_0000_0101, 13);
        assert_eq!(bs.to_u32(), 0b1_0000_0000_0101);
        assert!(bs.bit(0) && bs.bit(2) && bs.bit(12));
    }

    #[test]
    fn mms_floats_round_trip_at_both_widths() {
        let mut buf = Vec::new();
        append_float32(&mut buf, 230.4);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf[0], 8, "exponent width octet for f32");
        assert!((decode_float(&buf).unwrap() - 230.4).abs() < 1e-4);

        let mut buf = Vec::new();
        append_float64(&mut buf, -1.5e300);
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 11, "exponent width octet for f64");
        assert_eq!(decode_float(&buf).unwrap(), -1.5e300);
    }

    #[test]
    fn malformed_primitives_are_rejected() {
        assert!(decode_int(&[]).is_err());
        assert!(decode_uint(&[]).is_err());
        assert!(decode_bool(&[1, 2]).is_err());
        assert!(decode_bit_string(&[]).is_err());
        assert!(decode_bit_string(&[8]).is_err(), "padding > 7");
        assert!(decode_float(&[0; 4]).is_err());
    }
}
