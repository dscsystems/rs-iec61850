use std::time::SystemTime;

use crate::asn1::{
    application_constructed, bool_elem, cons, context_constructed, context_primitive, prim,
    uint_elem, Decoder, Tag,
};
use crate::mms::{data_element, decode_data, TimeQuality, Value};

use super::{Anomalies, Error, Result};

/// The fixed APDU header: APPID, Length, Reserved1, Reserved2.
pub(crate) const HEADER_LEN: usize = 8;

/// Frames the goosePdu after the APDU header.
fn pdu_tag() -> Tag {
    application_constructed(1) // 0x61
}

/// One GOOSE APDU.
///
/// On publish the publisher owns `t`, `st_num`, `sq_num` and
/// `time_allowed_to_live`; on receive, `anomalies` carries the subscriber's
/// per-control-block sequence checks and is not part of the wire format.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Message {
    pub go_cb_ref: String,
    pub dat_set: String,
    pub go_id: String,
    /// Milliseconds until the subscriber should consider the value stale.
    pub time_allowed_to_live: u32,
    pub t: Option<SystemTime>,
    /// Increments on every state change.
    pub st_num: u32,
    /// Increments on every retransmission of one state, and restarts at zero
    /// when the state changes.
    pub sq_num: u32,
    pub conf_rev: u32,
    pub test: bool,
    pub nds_com: bool,
    pub num_dat_set_entries: u32,
    pub values: Vec<Value>,
    pub app_id: u16,

    pub anomalies: Anomalies,
}

impl Message {
    /// Encodes the full APDU: APPID, Length, two reserved words, then the
    /// `[APPLICATION 1]` goosePdu.
    pub fn marshal(&self) -> Vec<u8> {
        let all_data = cons(
            context_constructed(11),
            self.values.iter().filter_map(data_element),
        );
        let t = match self.t {
            Some(t) => Value::utc_time(t, TimeQuality::accuracy(10)),
            None => Value::UtcTime([0; 8]),
        };
        let pdu = cons(
            pdu_tag(),
            [
                prim(context_primitive(0), self.go_cb_ref.as_bytes().to_vec()),
                uint_elem(context_primitive(1), u64::from(self.time_allowed_to_live)),
                prim(context_primitive(2), self.dat_set.as_bytes().to_vec()),
                prim(context_primitive(3), self.go_id.as_bytes().to_vec()),
                prim(context_primitive(4), t.bytes().to_vec()),
                uint_elem(context_primitive(5), u64::from(self.st_num)),
                uint_elem(context_primitive(6), u64::from(self.sq_num)),
                bool_elem(context_primitive(7), self.test),
                uint_elem(context_primitive(8), u64::from(self.conf_rev)),
                bool_elem(context_primitive(9), self.nds_com),
                uint_elem(
                    context_primitive(10),
                    u64::from(self.num_dat_set_entries),
                ),
                all_data,
            ],
        );
        let length = HEADER_LEN + pdu.size();
        let mut buf = Vec::with_capacity(length);
        buf.extend_from_slice(&self.app_id.to_be_bytes());
        buf.extend_from_slice(&(length as u16).to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0, 0]); // the two reserved words
        pdu.append(&mut buf);
        buf
    }
}

/// Decodes a GOOSE APDU, the Ethernet payload after the EtherType.
pub fn parse(apdu: &[u8]) -> Result<Message> {
    if apdu.len() < HEADER_LEN {
        return Err(Error::Codec(format!(
            "apdu of {} octets is truncated",
            apdu.len()
        )));
    }
    let mut m = Message {
        app_id: u16::from_be_bytes([apdu[0], apdu[1]]),
        ..Default::default()
    };
    // The length field covers the header and the PDU, and a publisher may pad
    // the frame beyond it, so it bounds the decode rather than the buffer
    // doing so.
    let length = usize::from(u16::from_be_bytes([apdu[2], apdu[3]]));
    if length < HEADER_LEN || length > apdu.len() {
        return Err(Error::Codec(format!(
            "length field {length} in an apdu of {} octets",
            apdu.len()
        )));
    }

    let content = Decoder::new(&apdu[HEADER_LEN..length]).expect(pdu_tag())?;
    let mut d = Decoder::new(content);

    m.go_cb_ref = string_field(&mut d, 0, "gocbRef")?;
    m.time_allowed_to_live = uint32_field(&mut d, 1, "timeAllowedToLive")?;
    m.dat_set = string_field(&mut d, 2, "datSet")?;
    // goID is optional: some publishers omit it and the control block
    // reference identifies the stream on its own.
    if let Some(b) = d.optional(context_primitive(3))? {
        m.go_id = String::from_utf8_lossy(b).into_owned();
    }

    let b = d
        .expect(context_primitive(4))
        .map_err(|e| Error::Codec(format!("t: {e}")))?;
    m.t = Value::utc_time_raw(b)
        .map_err(|e| Error::Codec(format!("t: {e}")))?
        .time();

    m.st_num = uint32_field(&mut d, 5, "stNum")?;
    m.sq_num = uint32_field(&mut d, 6, "sqNum")?;
    if let Some(b) = d.optional(context_primitive(7))? {
        m.test = crate::asn1::decode_bool(b).map_err(|e| Error::Codec(format!("test: {e}")))?;
    }
    m.conf_rev = uint32_field(&mut d, 8, "confRev")?;
    if let Some(b) = d.optional(context_primitive(9))? {
        m.nds_com =
            crate::asn1::decode_bool(b).map_err(|e| Error::Codec(format!("ndsCom: {e}")))?;
    }
    m.num_dat_set_entries = uint32_field(&mut d, 10, "numDatSetEntries")?;

    let content = d
        .expect(context_constructed(11))
        .map_err(|e| Error::Codec(format!("allData: {e}")))?;
    let mut inner = Decoder::new(content);
    while inner.more() {
        let v = decode_data(&mut inner)
            .map_err(|e| Error::Codec(format!("allData member {}: {e}", m.values.len())))?;
        m.values.push(v);
    }
    // Trailing fields, for example [12] security, are ignored.
    Ok(m)
}

fn string_field(d: &mut Decoder<'_>, tag: u32, name: &str) -> Result<String> {
    let b = d
        .expect(context_primitive(tag))
        .map_err(|e| Error::Codec(format!("{name}: {e}")))?;
    Ok(String::from_utf8_lossy(b).into_owned())
}

/// Consumes a context-primitive unsigned INTEGER field.
fn uint32_field(d: &mut Decoder<'_>, tag: u32, name: &str) -> Result<u32> {
    let b = d
        .expect(context_primitive(tag))
        .map_err(|e| Error::Codec(format!("{name}: {e}")))?;
    let v = crate::asn1::decode_uint(b).map_err(|e| Error::Codec(format!("{name}: {e}")))?;
    if v > u64::from(u32::MAX) {
        return Err(Error::Codec(format!("{name} out of range")));
    }
    Ok(v as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Quality;

    fn sample() -> Message {
        Message {
            go_cb_ref: "IED1LD0/LLN0$GO$gcb01".into(),
            dat_set: "IED1LD0/LLN0$Events".into(),
            go_id: "events".into(),
            time_allowed_to_live: 2000,
            t: Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_786_838_400)),
            st_num: 7,
            sq_num: 3,
            conf_rev: 1,
            test: false,
            nds_com: false,
            num_dat_set_entries: 2,
            values: vec![Value::boolean(true), Quality::GOOD.value()],
            app_id: 0x1000,
            anomalies: Anomalies::default(),
        }
    }

    #[test]
    fn a_message_round_trips_through_the_wire_format() {
        let m = sample();
        let back = parse(&m.marshal()).expect("decodes");
        assert_eq!(back.go_cb_ref, m.go_cb_ref);
        assert_eq!(back.dat_set, m.dat_set);
        assert_eq!(back.go_id, m.go_id);
        assert_eq!(back.time_allowed_to_live, 2000);
        assert_eq!(back.st_num, 7);
        assert_eq!(back.sq_num, 3);
        assert_eq!(back.conf_rev, 1);
        assert_eq!(back.num_dat_set_entries, 2);
        assert_eq!(back.app_id, 0x1000);
        assert_eq!(back.values.len(), 2);
        assert!(back.values[0].as_bool());
        assert_eq!(back.values[1].bit_len(), 13);
    }

    /// The APPID and length live in the fixed header before the ASN.1, which
    /// is what lets a switch filter and a receiver frame the PDU.
    #[test]
    fn the_apdu_header_carries_the_appid_and_length() {
        let b = sample().marshal();
        assert_eq!(&b[0..2], &[0x10, 0x00], "APPID first");
        let length = usize::from(u16::from_be_bytes([b[2], b[3]]));
        assert_eq!(length, b.len(), "the length covers header and PDU");
        assert_eq!(&b[4..8], &[0, 0, 0, 0], "two reserved words");
        assert_eq!(b[8], 0x61, "then the [APPLICATION 1] goosePdu");
    }

    /// A publisher may pad the frame past the length field, and a subscriber
    /// that decoded to the end of the buffer would fail on the padding.
    #[test]
    fn trailing_padding_beyond_the_length_field_is_ignored() {
        let mut b = sample().marshal();
        b.extend_from_slice(&[0u8; 32]);
        let back = parse(&b).expect("padding must not break the decode");
        assert_eq!(back.st_num, 7);
    }

    #[test]
    fn a_length_field_past_the_buffer_is_rejected() {
        let mut b = sample().marshal();
        b[2] = 0xff;
        b[3] = 0xff;
        assert!(parse(&b).is_err());

        // And one that does not even cover the header.
        let mut b = sample().marshal();
        b[2] = 0;
        b[3] = 4;
        assert!(parse(&b).is_err());
    }

    #[test]
    fn a_truncated_apdu_is_rejected_rather_than_panicking() {
        let b = sample().marshal();
        for n in 0..b.len() {
            let _ = parse(&b[..n]);
        }
        assert!(parse(&[]).is_err());
        assert!(parse(&[0; 7]).is_err());
    }

    /// Some publishers omit goID; the control block reference identifies the
    /// stream on its own, so the message must still decode.
    #[test]
    fn an_absent_optional_field_still_decodes() {
        let mut m = sample();
        m.go_id = String::new();
        let back = parse(&m.marshal()).expect("decodes without a goID");
        assert_eq!(back.go_id, "");
        assert_eq!(back.st_num, 7);
    }

    #[test]
    fn the_test_and_nds_com_flags_survive() {
        let mut m = sample();
        m.test = true;
        m.nds_com = true;
        let back = parse(&m.marshal()).unwrap();
        assert!(back.test);
        assert!(back.nds_com);
    }

    #[test]
    fn every_value_type_in_a_dataset_round_trips() {
        let mut m = sample();
        m.values = vec![
            Value::boolean(true),
            Value::int32(-5),
            Value::uint32(230),
            Value::float32(230.4),
            Value::visible_string("text"),
            Value::bit_string_bits(&[0x80, 0x08], 13),
            Value::utc_time_parts(1_786_838_400, 0, TimeQuality::accuracy(10)),
            Value::structure(vec![Value::float32(1.0), Value::boolean(false)]),
        ];
        m.num_dat_set_entries = m.values.len() as u32;
        let back = parse(&m.marshal()).unwrap();
        assert_eq!(back.values, m.values);
    }

    #[test]
    fn an_empty_dataset_is_legal() {
        let mut m = sample();
        m.values.clear();
        m.num_dat_set_entries = 0;
        let back = parse(&m.marshal()).unwrap();
        assert!(back.values.is_empty());
        assert_eq!(back.num_dat_set_entries, 0);
    }

    /// A subscriber sees hostile input; every truncation of a valid message
    /// has to fail cleanly rather than panic.
    #[test]
    fn corrupted_payloads_never_panic() {
        let good = sample().marshal();
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xff;
            let _ = parse(&bad);
        }
    }
}
