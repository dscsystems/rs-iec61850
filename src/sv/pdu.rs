use std::time::SystemTime;

use crate::asn1::{
    application_constructed, cons, context_constructed, context_primitive, prim, uint_elem,
    Decoder, Element, Tag, TAG_SEQUENCE,
};
use crate::mms::{TimeQuality, Value};

use super::{Error, Result};

/// The fixed APDU header: APPID, Length, Reserved1, Reserved2.
pub(crate) const HEADER_LEN: usize = 8;

/// Frames the savPdu after the APDU header.
fn sav_pdu_tag() -> Tag {
    application_constructed(0) // 0x60
}

/// `SmpSynch` values (IEC 61850-9-2): how the merging unit's sample clock is
/// disciplined.
///
/// A subscriber combining streams from several merging units can only align
/// them when they are globally synchronised, so this is not a diagnostic but a
/// precondition.
pub const SMP_SYNCH_NONE: u8 = 0;
pub const SMP_SYNCH_LOCAL: u8 = 1;
pub const SMP_SYNCH_GLOBAL: u8 = 2;

/// One Application Service Data Unit within a sampled-value APDU.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Asdu {
    pub sv_id: String,
    pub dat_set: String,
    pub smp_cnt: u16,
    pub conf_rev: u32,
    /// The refresh time; `None` when the publisher omitted it.
    pub refr_tm: Option<SystemTime>,
    pub smp_synch: u8,
    /// Zero when absent.
    pub smp_rate: u16,
    /// The raw dataset payload; `phsMeas` for a 9-2LE stream.
    pub sample: Vec<u8>,
}

/// A sampled-value APDU carrying one or more ASDUs.
///
/// Several ASDUs in one frame is how a publisher amortises the Ethernet
/// overhead at high sample rates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pdu {
    pub app_id: u16,
    pub asdus: Vec<Asdu>,
}

impl Asdu {
    fn element(&self) -> Element {
        let mut el = cons(
            TAG_SEQUENCE,
            [prim(context_primitive(0), self.sv_id.as_bytes().to_vec())],
        );
        if !self.dat_set.is_empty() {
            el.push(prim(context_primitive(1), self.dat_set.as_bytes().to_vec()));
        }
        // smpCnt [2] is a two-octet OCTET STRING, big-endian, per 9-2LE; it is
        // not an INTEGER, so it never loses its leading zero.
        el.push(prim(
            context_primitive(2),
            self.smp_cnt.to_be_bytes().to_vec(),
        ));
        el.push(uint_elem(context_primitive(3), u64::from(self.conf_rev)));
        if let Some(t) = self.refr_tm {
            let v = Value::utc_time(t, TimeQuality::accuracy(10));
            el.push(prim(context_primitive(4), v.bytes().to_vec()));
        }
        el.push(prim(context_primitive(5), vec![self.smp_synch]));
        if self.smp_rate != 0 {
            el.push(prim(
                context_primitive(6),
                self.smp_rate.to_be_bytes().to_vec(),
            ));
        }
        el.push(prim(context_primitive(7), self.sample.clone()));
        el
    }
}

impl Pdu {
    /// Encodes the full APDU: APPID, Length, two reserved words, then the
    /// `[APPLICATION 0]` savPdu.
    pub fn marshal(&self) -> Vec<u8> {
        let seq_asdu = cons(
            context_constructed(2), // seqOfASDU [2]
            self.asdus.iter().map(Asdu::element),
        );
        let sav = cons(
            sav_pdu_tag(),
            [
                uint_elem(context_primitive(0), self.asdus.len() as u64), // noASDU [0]
                seq_asdu,
            ],
        );
        let length = HEADER_LEN + sav.size();
        let mut buf = Vec::with_capacity(length);
        buf.extend_from_slice(&self.app_id.to_be_bytes());
        buf.extend_from_slice(&(length as u16).to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]);
        sav.append(&mut buf);
        buf
    }
}

/// Decodes a sampled-value APDU, the Ethernet payload after the EtherType.
pub fn parse(apdu: &[u8]) -> Result<Pdu> {
    if apdu.len() < HEADER_LEN {
        return Err(Error::Codec(format!(
            "apdu of {} octets is truncated",
            apdu.len()
        )));
    }
    let mut p = Pdu {
        app_id: u16::from_be_bytes([apdu[0], apdu[1]]),
        asdus: Vec::new(),
    };
    let length = usize::from(u16::from_be_bytes([apdu[2], apdu[3]]));
    if length < HEADER_LEN || length > apdu.len() {
        return Err(Error::Codec(format!(
            "length field {length} in an apdu of {} octets",
            apdu.len()
        )));
    }
    let content = Decoder::new(&apdu[HEADER_LEN..length]).expect(sav_pdu_tag())?;
    let mut d = Decoder::new(content);
    // noASDU is read and discarded: the sequence that follows is
    // self-delimiting, and trusting a count against it would only add a way to
    // disagree.
    d.expect(context_primitive(0))
        .map_err(|e| Error::Codec(format!("noASDU: {e}")))?;
    let seq = d
        .expect(context_constructed(2))
        .map_err(|e| Error::Codec(format!("seqOfASDU: {e}")))?;

    let mut sd = Decoder::new(seq);
    while sd.more() {
        let content = sd
            .expect(TAG_SEQUENCE)
            .map_err(|e| Error::Codec(format!("ASDU: {e}")))?;
        p.asdus.push(parse_asdu(content)?);
    }
    Ok(p)
}

fn parse_asdu(content: &[u8]) -> Result<Asdu> {
    let mut d = Decoder::new(content);
    let mut a = Asdu::default();

    let b = d
        .expect(context_primitive(0))
        .map_err(|e| Error::Codec(format!("svID: {e}")))?;
    a.sv_id = String::from_utf8_lossy(b).into_owned();

    if let Some(b) = d.optional(context_primitive(1))? {
        a.dat_set = String::from_utf8_lossy(b).into_owned();
    }
    let b = d
        .expect(context_primitive(2))
        .map_err(|e| Error::Codec(format!("smpCnt: {e}")))?;
    a.smp_cnt = be_u16(b);

    let b = d
        .expect(context_primitive(3))
        .map_err(|e| Error::Codec(format!("confRev: {e}")))?;
    a.conf_rev = crate::asn1::decode_uint(b).unwrap_or(0) as u32;

    if let Some(b) = d.optional(context_primitive(4))? {
        a.refr_tm = Value::utc_time_raw(b).ok().and_then(|v| v.time());
    }
    if let Some(b) = d.optional(context_primitive(5))? {
        if let Some(last) = b.last() {
            a.smp_synch = *last;
        }
    }
    if let Some(b) = d.optional(context_primitive(6))? {
        a.smp_rate = be_u16(b);
    }
    let b = d
        .expect(context_primitive(7))
        .map_err(|e| Error::Codec(format!("sample: {e}")))?;
    a.sample = b.to_vec();
    Ok(a)
}

/// Reads a big-endian `u16` from however many octets a publisher chose to
/// send.
///
/// Merging units differ on whether these fields carry one or two octets, so
/// the low-order end is what counts.
fn be_u16(b: &[u8]) -> u16 {
    match b.len() {
        0 => 0,
        1 => u16::from(b[0]),
        n => u16::from(b[n - 2]) << 8 | u16::from(b[n - 1]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asdu(smp_cnt: u16) -> Asdu {
        Asdu {
            sv_id: "MU01".into(),
            dat_set: "MU01LD0/LLN0$PhsMeas1".into(),
            smp_cnt,
            conf_rev: 1,
            refr_tm: Some(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_786_838_400),
            ),
            smp_synch: SMP_SYNCH_GLOBAL,
            smp_rate: 80,
            sample: vec![0xaa; 64],
        }
    }

    #[test]
    fn a_pdu_round_trips_through_the_wire_format() {
        let p = Pdu {
            app_id: 0x4000,
            asdus: vec![asdu(7)],
        };
        let back = parse(&p.marshal()).expect("decodes");
        assert_eq!(back.app_id, 0x4000);
        assert_eq!(back.asdus.len(), 1);
        let a = &back.asdus[0];
        assert_eq!(a.sv_id, "MU01");
        assert_eq!(a.dat_set, "MU01LD0/LLN0$PhsMeas1");
        assert_eq!(a.smp_cnt, 7);
        assert_eq!(a.conf_rev, 1);
        assert_eq!(a.smp_synch, SMP_SYNCH_GLOBAL);
        assert_eq!(a.smp_rate, 80);
        assert_eq!(a.sample.len(), 64);
        assert!(a.refr_tm.is_some());
    }

    /// Several ASDUs per frame is how a publisher amortises Ethernet overhead
    /// at 4000 samples a second; losing any of them loses samples.
    #[test]
    fn several_asdus_in_one_frame_all_decode() {
        let p = Pdu {
            app_id: 0x4000,
            asdus: (0..8).map(asdu).collect(),
        };
        let back = parse(&p.marshal()).unwrap();
        assert_eq!(back.asdus.len(), 8);
        let counts: Vec<u16> = back.asdus.iter().map(|a| a.smp_cnt).collect();
        assert_eq!(counts, [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    /// smpCnt is an OCTET STRING, not an INTEGER: encoded as an integer, a
    /// count of 7 would be one octet and a subscriber expecting two would read
    /// the wrong sample number.
    #[test]
    fn the_sample_count_is_always_two_octets() {
        for smp_cnt in [0u16, 1, 7, 255, 256, 3999, 65535] {
            let p = Pdu {
                app_id: 0x4000,
                asdus: vec![Asdu {
                    smp_cnt,
                    ..asdu(smp_cnt)
                }],
            };
            let encoded = p.marshal();
            let back = parse(&encoded).unwrap();
            assert_eq!(back.asdus[0].smp_cnt, smp_cnt, "count {smp_cnt} was lost");
        }
        // The field itself is two octets on the wire.
        let el = asdu(7).element().encode();
        let mut d = Decoder::new(&el);
        let content = d.expect(TAG_SEQUENCE).unwrap();
        let mut inner = Decoder::new(content);
        inner.skip().unwrap(); // svID
        inner.skip().unwrap(); // datSet
        let smp = inner.expect(context_primitive(2)).unwrap();
        assert_eq!(smp.len(), 2, "smpCnt must occupy two octets");
    }

    #[test]
    fn optional_fields_may_be_absent() {
        let a = Asdu {
            sv_id: "MU01".into(),
            dat_set: String::new(),
            smp_cnt: 3,
            conf_rev: 1,
            refr_tm: None,
            smp_synch: SMP_SYNCH_NONE,
            smp_rate: 0,
            sample: vec![0; 64],
        };
        let p = Pdu {
            app_id: 0x4000,
            asdus: vec![a.clone()],
        };
        let back = parse(&p.marshal()).unwrap();
        assert_eq!(back.asdus[0], a);
        assert!(back.asdus[0].refr_tm.is_none());
        assert_eq!(back.asdus[0].smp_rate, 0);
        assert_eq!(back.asdus[0].dat_set, "");
    }

    #[test]
    fn the_apdu_header_carries_the_appid_and_length() {
        let p = Pdu {
            app_id: 0x4000,
            asdus: vec![asdu(1)],
        };
        let b = p.marshal();
        assert_eq!(&b[0..2], &[0x40, 0x00]);
        assert_eq!(usize::from(u16::from_be_bytes([b[2], b[3]])), b.len());
        assert_eq!(&b[4..8], &[0, 0, 0, 0]);
        assert_eq!(b[8], 0x60, "then the [APPLICATION 0] savPdu");
    }

    #[test]
    fn trailing_padding_beyond_the_length_field_is_ignored() {
        let p = Pdu {
            app_id: 0x4000,
            asdus: vec![asdu(5)],
        };
        let mut b = p.marshal();
        b.extend_from_slice(&[0u8; 32]);
        assert_eq!(parse(&b).unwrap().asdus[0].smp_cnt, 5);
    }

    #[test]
    fn malformed_apdus_are_rejected_rather_than_panicking() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0; 7]).is_err());

        let good = Pdu {
            app_id: 0x4000,
            asdus: vec![asdu(1)],
        }
        .marshal();
        for n in 0..good.len() {
            let _ = parse(&good[..n]);
        }
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = parse(&bad);
        }
    }

    /// Merging units differ on the width of these fields; taking the
    /// low-order end reads both correctly.
    #[test]
    fn short_and_long_integer_fields_read_the_same_value() {
        assert_eq!(be_u16(&[]), 0);
        assert_eq!(be_u16(&[0x07]), 7);
        assert_eq!(be_u16(&[0x00, 0x07]), 7);
        assert_eq!(be_u16(&[0x01, 0x00]), 256);
        // A publisher that pads gets the same answer.
        assert_eq!(be_u16(&[0x00, 0x00, 0x01, 0x00]), 256);
    }
}
