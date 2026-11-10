use super::{prim, Element, Error, Result, Tag};

/// An object identifier as a sequence of arcs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    pub fn new(arcs: impl Into<Vec<u32>>) -> Oid {
        Oid(arcs.into())
    }

    pub fn arcs(&self) -> &[u32] {
        &self.0
    }
}

impl From<Vec<u32>> for Oid {
    fn from(v: Vec<u32>) -> Oid {
        Oid(v)
    }
}

impl<const N: usize> From<[u32; N]> for Oid {
    fn from(v: [u32; N]) -> Oid {
        Oid(v.to_vec())
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, arc) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

/// Appends OID content octets (first two arcs combined, then base-128).
pub fn append_oid(dst: &mut Vec<u8>, o: &Oid) {
    if o.0.len() < 2 {
        return;
    }
    append_base128(dst, u64::from(o.0[0]) * 40 + u64::from(o.0[1]));
    for &arc in &o.0[2..] {
        append_base128(dst, u64::from(arc));
    }
}

fn append_base128(dst: &mut Vec<u8>, v: u64) {
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    let mut v = v;
    loop {
        i -= 1;
        tmp[i] = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    let last = tmp.len() - 1;
    for slot in tmp.iter_mut().take(last).skip(i) {
        *slot |= 0x80;
    }
    dst.extend_from_slice(&tmp[i..]);
}

/// Decodes OID content octets.
pub fn decode_oid(content: &[u8]) -> Result<Oid> {
    if content.is_empty() {
        return Err(Error::bad_value("empty OID"));
    }
    let mut arcs: Vec<u32> = Vec::new();
    let mut v: u64 = 0;
    let mut n = 0;
    for &b in content {
        if n >= 5 || v > ((u64::from(u32::MAX) + 80) >> 7) {
            return Err(Error::bad_value("OID arc too large"));
        }
        v = (v << 7) | u64::from(b & 0x7f);
        n += 1;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = (v / 40).min(2);
                arcs.push(first as u32);
                arcs.push(u32::try_from(v - first * 40).map_err(|_| Error::bad_value("OID arc too large"))?);
            } else {
                arcs.push(u32::try_from(v).map_err(|_| Error::bad_value("OID arc too large"))?);
            }
            v = 0;
            n = 0;
        }
    }
    if n != 0 {
        return Err(Error::bad_value("truncated OID arc"));
    }
    Ok(Oid(arcs))
}

/// Returns an OBJECT IDENTIFIER-content primitive element with tag `t`.
pub fn oid_elem(t: Tag, o: &Oid) -> Element {
    let mut buf = Vec::new();
    append_oid(&mut buf, o);
    prim(t, buf)
}

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn oids_round_trip_including_the_combined_first_arcs() {
        // The MMS abstract syntax OID, as sent in every presentation CP.
        for arcs in [
            vec![1u32, 0, 9506, 2, 1],
            vec![2, 2, 1, 0, 1],
            vec![1, 3, 6, 1, 4, 1, 99999],
            vec![0, 0],
        ] {
            let o = Oid::new(arcs.clone());
            let mut buf = Vec::new();
            append_oid(&mut buf, &o);
            assert_eq!(decode_oid(&buf).unwrap(), o, "round trip failed for {o}");
        }
    }

    #[test]
    fn joint_iso_itu_first_arc_above_79_is_clamped_correctly() {
        // First octet 0x81 0x34 = 180 -> arc 2, then 180 - 80 = 100.
        let o = Oid::new(vec![2u32, 100, 3]);
        let mut buf = Vec::new();
        append_oid(&mut buf, &o);
        assert_eq!(decode_oid(&buf).unwrap(), o);
    }

    #[test]
    fn display_uses_dotted_notation() {
        assert_eq!(Oid::new(vec![1u32, 0, 9506, 2, 1]).to_string(), "1.0.9506.2.1");
    }

    #[test]
    fn malformed_oids_are_rejected() {
        assert!(decode_oid(&[]).is_err());
        assert!(decode_oid(&[0x80]).is_err(), "truncated final arc");
        assert!(decode_oid(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00]).is_err());
    }

    #[test]
    fn oid_arcs_cannot_wrap_u32() {
        assert!(decode_oid(&[40, 0x90, 0x80, 0x80, 0x80, 0]).is_err());
        assert_eq!(decode_oid(&[40, 0x8f, 0xff, 0xff, 0xff, 0x7f]).unwrap().arcs(), &[1, 0, u32::MAX]);
    }

}
