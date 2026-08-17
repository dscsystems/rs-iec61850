//! Minimal BER (ISO 8825-1) runtime used by the MMS, ACSE, presentation,
//! GOOSE and SV codecs in this crate.
//!
//! It is deliberately small: tag/length/value framing, bounds-checked
//! decoding of untrusted input, and primitive value helpers. Typed PDU
//! grammars live in the modules that own them.
//!
//! Two encoding styles are offered:
//!
//! * [`Element`] builders ([`cons`], [`prim`], [`int_elem`], ...) for the
//!   control-plane PDUs where clarity beats allocation counts.
//! * `append_*` helpers ([`append_tag`], [`append_length`], [`append_int`],
//!   ...) for the GOOSE and SV hot paths.

mod decoder;
mod element;
mod oid;
mod primitives;

pub use decoder::Decoder;
pub use element::{cons, prim, raw_content, raw_tlv, Element};
pub use oid::{append_oid, decode_oid, oid_elem, Oid};
pub use primitives::{
    append_bit_string, append_float32, append_float64, append_int, append_uint, bit_string_elem,
    bool_elem, decode_bit_string, decode_bool, decode_float, decode_int, decode_uint, int_elem,
    int_size, uint_elem, uint_size, BitString,
};

/// Tag class of a BER element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Class {
    Universal = 0,
    Application = 1,
    ContextSpecific = 2,
    Private = 3,
}

impl Class {
    fn from_bits(b: u8) -> Class {
        match b & 3 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        }
    }
}

/// Identifies a BER element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Tag {
    pub class: Class,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    pub const fn new(class: Class, constructed: bool, number: u32) -> Tag {
        Tag {
            class,
            constructed,
            number,
        }
    }
}

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let class = match self.class {
            Class::Universal => "UNIVERSAL",
            Class::Application => "APPLICATION",
            Class::ContextSpecific => "CONTEXT",
            Class::Private => "PRIVATE",
        };
        let pc = if self.constructed {
            "constructed"
        } else {
            "primitive"
        };
        write!(f, "[{} {} {}]", class, self.number, pc)
    }
}

/// Common universal tags.
pub const TAG_BOOLEAN: Tag = Tag::new(Class::Universal, false, 1);
pub const TAG_INTEGER: Tag = Tag::new(Class::Universal, false, 2);
pub const TAG_BIT_STRING: Tag = Tag::new(Class::Universal, false, 3);
pub const TAG_OCTET_STRING: Tag = Tag::new(Class::Universal, false, 4);
pub const TAG_NULL: Tag = Tag::new(Class::Universal, false, 5);
pub const TAG_OID: Tag = Tag::new(Class::Universal, false, 6);
pub const TAG_UTF8_STRING: Tag = Tag::new(Class::Universal, false, 12);
pub const TAG_SEQUENCE: Tag = Tag::new(Class::Universal, true, 16);
pub const TAG_SET: Tag = Tag::new(Class::Universal, true, 17);
pub const TAG_GENERAL_TIME: Tag = Tag::new(Class::Universal, false, 24);
pub const TAG_GRAPHIC_STRING: Tag = Tag::new(Class::Universal, false, 25);
pub const TAG_VISIBLE_STRING: Tag = Tag::new(Class::Universal, false, 26);

/// Returns a primitive context-specific tag `[n]`.
pub const fn context_primitive(n: u32) -> Tag {
    Tag::new(Class::ContextSpecific, false, n)
}

/// Returns a constructed context-specific tag `[n]`.
pub const fn context_constructed(n: u32) -> Tag {
    Tag::new(Class::ContextSpecific, true, n)
}

/// Returns a constructed application-class tag.
pub const fn application_constructed(n: u32) -> Tag {
    Tag::new(Class::Application, true, n)
}

/// Returns a primitive application-class tag.
pub const fn application_primitive(n: u32) -> Tag {
    Tag::new(Class::Application, false, n)
}

/// Nesting limit enforced by the depth-aware decoder helpers.
pub const MAX_DEPTH: usize = 64;

/// Errors produced by the BER decoder.
///
/// Every variant carries the byte offset at which the fault was detected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("asn1: truncated element while {what} at offset {offset}")]
    Truncated { what: &'static str, offset: usize },
    #[error("asn1: malformed tag ({what}) at offset {offset}")]
    BadTag { what: &'static str, offset: usize },
    #[error("asn1: malformed length ({what}) at offset {offset}")]
    BadLength { what: &'static str, offset: usize },
    #[error("asn1: nesting too deep at offset {offset}")]
    TooDeep { offset: usize },
    #[error("asn1: expected {expected}, got {got} at offset {offset}")]
    Unexpected {
        expected: Tag,
        got: Tag,
        offset: usize,
    },
    #[error("asn1: malformed value ({what})")]
    BadValue { what: String },
}

impl Error {
    pub(crate) fn bad_value(what: impl Into<String>) -> Error {
        Error::BadValue { what: what.into() }
    }
}

/// Result alias for the BER runtime.
pub type Result<T> = std::result::Result<T, Error>;

/// Appends the identifier octets of `t` to `dst`.
pub fn append_tag(dst: &mut Vec<u8>, t: Tag) {
    let mut b = (t.class as u8) << 6;
    if t.constructed {
        b |= 0x20;
    }
    if t.number < 31 {
        dst.push(b | t.number as u8);
        return;
    }
    dst.push(b | 0x1f);
    // Base-128, big-endian, high bit set on all but the last octet.
    let mut tmp = [0u8; 5];
    let mut i = tmp.len();
    let mut n = t.number;
    loop {
        i -= 1;
        tmp[i] = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    let last = tmp.len() - 1;
    for slot in tmp.iter_mut().take(last).skip(i) {
        *slot |= 0x80;
    }
    dst.extend_from_slice(&tmp[i..]);
}

/// Appends definite-form length octets for content length `n`.
pub fn append_length(dst: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        dst.push(n as u8);
    } else if n <= 0xff {
        dst.extend_from_slice(&[0x81, n as u8]);
    } else if n <= 0xffff {
        dst.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    } else if n <= 0xff_ffff {
        dst.extend_from_slice(&[0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
    } else {
        dst.extend_from_slice(&[
            0x84,
            (n >> 24) as u8,
            (n >> 16) as u8,
            (n >> 8) as u8,
            n as u8,
        ]);
    }
}

/// Returns the encoded size of the identifier octets of `t`.
pub fn tag_size(t: Tag) -> usize {
    match t.number {
        0..=30 => 1,
        n if n < 1 << 7 => 2,
        n if n < 1 << 14 => 3,
        n if n < 1 << 21 => 4,
        _ => 5,
    }
}

/// Returns the encoded size of the length octets for content length `n`.
pub fn length_size(n: usize) -> usize {
    match n {
        0..=0x7f => 1,
        0x80..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xff_ffff => 4,
        _ => 5,
    }
}

/// Returns the total encoded size of an element with tag `t` and content
/// length `n`.
pub fn tlv_size(t: Tag, n: usize) -> usize {
    tag_size(t) + length_size(n) + n
}

/// Appends a complete element with the given content.
pub fn append_tlv(dst: &mut Vec<u8>, t: Tag, content: &[u8]) {
    append_tag(dst, t);
    append_length(dst, content.len());
    dst.extend_from_slice(content);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_round_trip_low_and_high_numbers() {
        for t in [
            TAG_INTEGER,
            context_primitive(0),
            context_constructed(30),
            // High tag number form, as used by the MMS file services [72].
            context_constructed(72),
            application_constructed(1),
            Tag::new(Class::Private, false, 0x3fff),
        ] {
            let mut buf = Vec::new();
            append_tag(&mut buf, t);
            assert_eq!(buf.len(), tag_size(t), "tag_size disagrees for {t}");
            let d = Decoder::new(&buf);
            // A bare tag with no length is truncated, but peek only reads the tag.
            assert_eq!(d.peek().unwrap(), t);
        }
    }

    #[test]
    fn length_round_trip_across_forms() {
        for n in [0usize, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x1_0000] {
            let mut buf = Vec::new();
            append_tlv(&mut buf, TAG_OCTET_STRING, &vec![0u8; n]);
            assert_eq!(buf.len(), tlv_size(TAG_OCTET_STRING, n));
            let mut d = Decoder::new(&buf);
            let (tag, content) = d.read_tlv().unwrap();
            assert_eq!(tag, TAG_OCTET_STRING);
            assert_eq!(content.len(), n);
        }
    }
}
