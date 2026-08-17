use super::{Class, Error, Result, Tag, MAX_DEPTH};

/// A bounds-checked cursor over BER-encoded bytes.
///
/// The content slices it returns borrow from the input buffer, so the
/// decoder never copies. Indefinite lengths are accepted (the matching
/// end-of-contents octets are located by structural scanning) since BER
/// permits them, although all known IEC 61850 stacks emit definite lengths.
///
/// The decoder must never panic on hostile input; that property is checked
/// by the fuzz targets under `fuzz/`.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    data: &'a [u8],
    off: usize,
}

impl<'a> Decoder<'a> {
    /// Returns a decoder over `data`.
    pub fn new(data: &'a [u8]) -> Decoder<'a> {
        Decoder { data, off: 0 }
    }

    /// Reports whether unread bytes remain.
    pub fn more(&self) -> bool {
        self.off < self.data.len()
    }

    /// Returns the current byte offset, for error reporting.
    pub fn offset(&self) -> usize {
        self.off
    }

    /// Returns the unread remainder without consuming it.
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.off..]
    }

    /// Consumes and returns the identifier octets.
    fn read_tag(&mut self) -> Result<Tag> {
        if self.off >= self.data.len() {
            return Err(Error::Truncated {
                what: "reading tag",
                offset: self.off,
            });
        }
        let b = self.data[self.off];
        self.off += 1;
        let mut t = Tag {
            class: Class::from_bits(b >> 6),
            constructed: b & 0x20 != 0,
            number: u32::from(b & 0x1f),
        };
        if t.number != 0x1f {
            return Ok(t);
        }
        // High tag number form.
        t.number = 0;
        let mut i = 0;
        loop {
            if self.off >= self.data.len() {
                return Err(Error::Truncated {
                    what: "reading tag",
                    offset: self.off,
                });
            }
            if i >= 5 {
                return Err(Error::BadTag {
                    what: "tag number too large",
                    offset: self.off,
                });
            }
            let c = self.data[self.off];
            self.off += 1;
            t.number = (t.number << 7) | u32::from(c & 0x7f);
            if c & 0x80 == 0 {
                break;
            }
            i += 1;
        }
        Ok(t)
    }

    /// Consumes the length octets. The boolean is true for the indefinite
    /// form (`0x80`).
    fn read_length(&mut self) -> Result<(usize, bool)> {
        if self.off >= self.data.len() {
            return Err(Error::Truncated {
                what: "reading length",
                offset: self.off,
            });
        }
        let b = self.data[self.off];
        self.off += 1;
        if b < 0x80 {
            return Ok((usize::from(b), false));
        }
        if b == 0x80 {
            return Ok((0, true));
        }
        let num_octets = usize::from(b & 0x7f);
        if num_octets > 4 {
            return Err(Error::BadLength {
                what: "length overflows",
                offset: self.off,
            });
        }
        if self.off + num_octets > self.data.len() {
            return Err(Error::Truncated {
                what: "reading length",
                offset: self.off,
            });
        }
        let mut n: usize = 0;
        for _ in 0..num_octets {
            n = (n << 8) | usize::from(self.data[self.off]);
            self.off += 1;
        }
        Ok((n, false))
    }

    /// Returns the tag of the next element without consuming anything.
    pub fn peek(&self) -> Result<Tag> {
        let mut probe = Decoder {
            data: self.data,
            off: self.off,
        };
        probe.read_tag()
    }

    /// Reports whether the next element has tag `t`. False when no element
    /// remains or the tag is malformed.
    pub fn peek_is(&self, t: Tag) -> bool {
        matches!(self.peek(), Ok(got) if got == t)
    }

    /// Consumes the next element and returns its tag and content octets.
    ///
    /// For indefinite-length elements the content excludes the
    /// end-of-contents octets.
    pub fn read_tlv(&mut self) -> Result<(Tag, &'a [u8])> {
        self.read_tlv_at(0)
    }

    fn read_tlv_at(&mut self, depth: usize) -> Result<(Tag, &'a [u8])> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep { offset: self.off });
        }
        let t = self.read_tag()?;
        let (n, indefinite) = self.read_length()?;
        if !indefinite {
            if n > self.data.len() - self.off {
                return Err(Error::Truncated {
                    what: "reading content",
                    offset: self.off,
                });
            }
            let content = &self.data[self.off..self.off + n];
            self.off += n;
            return Ok((t, content));
        }
        if !t.constructed {
            return Err(Error::BadLength {
                what: "indefinite length on primitive",
                offset: self.off,
            });
        }
        // Indefinite: scan children until end-of-contents (00 00).
        let start = self.off;
        loop {
            if self.off + 2 <= self.data.len()
                && self.data[self.off] == 0
                && self.data[self.off + 1] == 0
            {
                let content = &self.data[start..self.off];
                self.off += 2;
                return Ok((t, content));
            }
            self.read_tlv_at(depth + 1)?;
        }
    }

    /// Consumes the next element, requiring tag `t`, and returns its content.
    pub fn expect(&mut self, t: Tag) -> Result<&'a [u8]> {
        let offset = self.off;
        let (got, content) = self.read_tlv()?;
        if got != t {
            return Err(Error::Unexpected {
                expected: t,
                got,
                offset,
            });
        }
        Ok(content)
    }

    /// Consumes the next element only if it has tag `t`, returning its
    /// content. Nothing is consumed when the tag does not match.
    pub fn optional(&mut self, t: Tag) -> Result<Option<&'a [u8]>> {
        if !self.more() {
            return Ok(None);
        }
        if self.peek()? != t {
            return Ok(None);
        }
        let (_, content) = self.read_tlv()?;
        Ok(Some(content))
    }

    /// Consumes and discards the next element.
    pub fn skip(&mut self) -> Result<()> {
        self.read_tlv()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn expect_reports_the_offset_of_the_mismatched_element() {
        let mut buf = Vec::new();
        append_tlv(&mut buf, TAG_NULL, &[]);
        append_tlv(&mut buf, TAG_INTEGER, &[7]);
        let mut d = Decoder::new(&buf);
        d.skip().unwrap();
        let err = d.expect(TAG_BOOLEAN).unwrap_err();
        match err {
            Error::Unexpected { got, offset, .. } => {
                assert_eq!(got, TAG_INTEGER);
                assert_eq!(offset, 2, "offset should point at the element, not past it");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn optional_does_not_consume_on_mismatch() {
        let mut buf = Vec::new();
        append_tlv(&mut buf, TAG_INTEGER, &[1]);
        let mut d = Decoder::new(&buf);
        assert!(d.optional(TAG_BOOLEAN).unwrap().is_none());
        assert_eq!(d.offset(), 0);
        assert_eq!(d.optional(TAG_INTEGER).unwrap(), Some(&[1u8][..]));
        assert!(!d.more());
    }

    #[test]
    fn indefinite_length_constructed_is_scanned_to_end_of_contents() {
        // SEQUENCE (indefinite) { INTEGER 1, NULL } EOC
        let buf = [0x30, 0x80, 0x02, 0x01, 0x01, 0x05, 0x00, 0x00, 0x00];
        let mut d = Decoder::new(&buf);
        let (tag, content) = d.read_tlv().unwrap();
        assert_eq!(tag, TAG_SEQUENCE);
        assert_eq!(content, &[0x02, 0x01, 0x01, 0x05, 0x00]);
        assert!(!d.more());
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        // Every prefix of a valid encoding must fail cleanly.
        let mut buf = Vec::new();
        append_tlv(&mut buf, TAG_SEQUENCE, &[0x02, 0x01, 0x01]);
        for n in 0..buf.len() {
            let mut d = Decoder::new(&buf[..n]);
            let _ = d.read_tlv();
        }
    }

    #[test]
    fn nesting_beyond_max_depth_is_rejected() {
        // Deeply nested indefinite-length elements must not blow the stack.
        let mut buf = Vec::new();
        for _ in 0..MAX_DEPTH + 8 {
            buf.extend_from_slice(&[0x30, 0x80]);
        }
        let mut d = Decoder::new(&buf);
        assert!(matches!(d.read_tlv(), Err(Error::TooDeep { .. })));
    }
}
