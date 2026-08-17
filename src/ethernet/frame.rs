use super::{Error, Result, ETHER_TYPE_VLAN};

/// An IEEE 802.1Q tag.
///
/// GOOSE and SV are published with a priority tag so a switch can give them
/// precedence over station traffic; the VLAN identifier separates the process
/// bus from everything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VlanTag {
    /// The priority code point, 0..=7.
    pub priority: u8,
    /// The drop eligible indicator.
    pub dei: bool,
    /// The VLAN identifier, 0..=4095.
    pub vid: u16,
}

impl VlanTag {
    /// Returns a tag carrying only a priority, which is the common case: the
    /// frame is prioritised but stays on the native VLAN.
    pub fn priority(priority: u8) -> VlanTag {
        VlanTag {
            priority: priority & 7,
            dei: false,
            vid: 0,
        }
    }

    /// Packs the tag control information field.
    fn tci(self) -> u16 {
        let mut tci = u16::from(self.priority & 7) << 13;
        if self.dei {
            tci |= 1 << 12;
        }
        tci | (self.vid & 0x0fff)
    }

    fn from_tci(tci: u16) -> VlanTag {
        VlanTag {
            priority: (tci >> 13) as u8,
            dei: tci & (1 << 12) != 0,
            vid: tci & 0x0fff,
        }
    }
}

/// An Ethernet II frame with an optional single 802.1Q tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    pub src: [u8; 6],
    pub dst: [u8; 6],
    pub ether_type: u16,
    pub vlan: Option<VlanTag>,
    pub payload: Vec<u8>,
}

/// The length of an Ethernet II header with no tag.
const HEADER_LEN: usize = 14;
/// The length added by one 802.1Q tag.
const VLAN_LEN: usize = 4;

impl Frame {
    /// Returns the encoded size of the frame.
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.payload.len() + if self.vlan.is_some() { VLAN_LEN } else { 0 }
    }

    /// Serialises the frame, including the 802.1Q tag when present.
    pub fn marshal(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.encoded_len());
        b.extend_from_slice(&self.dst);
        b.extend_from_slice(&self.src);
        if let Some(v) = self.vlan {
            b.extend_from_slice(&ETHER_TYPE_VLAN.to_be_bytes());
            b.extend_from_slice(&v.tci().to_be_bytes());
        }
        b.extend_from_slice(&self.ether_type.to_be_bytes());
        b.extend_from_slice(&self.payload);
        b
    }
}

/// Parses an Ethernet II frame with an optional single 802.1Q tag.
pub fn parse_frame(b: &[u8]) -> Result<Frame> {
    if b.len() < HEADER_LEN {
        return Err(Error::Frame(format!(
            "frame of {} octets is too short",
            b.len()
        )));
    }
    let mut f = Frame {
        dst: b[0..6].try_into().expect("6 octets"),
        src: b[6..12].try_into().expect("6 octets"),
        ..Default::default()
    };
    let mut et = u16::from_be_bytes([b[12], b[13]]);
    let mut off = HEADER_LEN;
    if et == ETHER_TYPE_VLAN {
        if b.len() < HEADER_LEN + VLAN_LEN {
            return Err(Error::Frame(format!(
                "802.1Q frame of {} octets is too short",
                b.len()
            )));
        }
        f.vlan = Some(VlanTag::from_tci(u16::from_be_bytes([b[14], b[15]])));
        et = u16::from_be_bytes([b[16], b[17]]);
        off = HEADER_LEN + VLAN_LEN;
    }
    f.ether_type = et;
    f.payload = b[off..].to_vec();
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::super::{ETHER_TYPE_GOOSE, ETHER_TYPE_SV};
    use super::*;

    fn sample(vlan: Option<VlanTag>) -> Frame {
        Frame {
            dst: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01],
            src: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            ether_type: ETHER_TYPE_GOOSE,
            vlan,
            payload: vec![0x61, 0x03, 0x80, 0x01, 0x00],
        }
    }

    #[test]
    fn an_untagged_frame_round_trips() {
        let f = sample(None);
        let b = f.marshal();
        assert_eq!(b.len(), f.encoded_len());
        assert_eq!(b.len(), 14 + 5);
        assert_eq!(parse_frame(&b).unwrap(), f);
    }

    /// The tag sits between the source address and the EtherType, so a parser
    /// that ignores it reads the tag as the protocol and the payload from four
    /// octets too early.
    #[test]
    fn a_tagged_frame_round_trips_with_its_tag() {
        let f = sample(Some(VlanTag {
            priority: 4,
            dei: false,
            vid: 0x00a,
        }));
        let b = f.marshal();
        assert_eq!(b.len(), 14 + 4 + 5);
        // The tag protocol identifier is where the EtherType would be.
        assert_eq!(&b[12..14], &[0x81, 0x00]);
        // And the real EtherType follows the tag.
        assert_eq!(&b[16..18], &ETHER_TYPE_GOOSE.to_be_bytes());

        let back = parse_frame(&b).unwrap();
        assert_eq!(back, f);
        assert_eq!(back.ether_type, ETHER_TYPE_GOOSE, "the inner protocol wins");
        assert_eq!(back.payload, f.payload);
    }

    #[test]
    fn the_tag_control_field_packs_its_three_parts() {
        for (priority, dei, vid) in [(0u8, false, 0u16), (7, true, 4095), (4, false, 10)] {
            let tag = VlanTag { priority, dei, vid };
            let f = sample(Some(tag));
            let back = parse_frame(&f.marshal()).unwrap().vlan.unwrap();
            assert_eq!(back, tag, "tag round trip failed for {tag:?}");
        }
    }

    #[test]
    fn a_priority_only_tag_stays_on_the_native_vlan() {
        let tag = VlanTag::priority(4);
        assert_eq!(tag.priority, 4);
        assert_eq!(tag.vid, 0);
        assert!(!tag.dei);
        // A priority above 7 cannot be encoded and is masked rather than
        // corrupting the VLAN identifier beside it.
        assert_eq!(VlanTag::priority(9).priority, 1);
    }

    #[test]
    fn addresses_and_protocol_land_in_the_right_places() {
        let b = sample(None).marshal();
        assert_eq!(&b[0..6], &[0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01], "dst first");
        assert_eq!(&b[6..12], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55], "then src");
        assert_eq!(&b[12..14], &[0x88, 0xb8], "then the EtherType");
    }

    #[test]
    fn both_iec_61850_protocols_survive_the_round_trip() {
        for et in [ETHER_TYPE_GOOSE, ETHER_TYPE_SV] {
            let mut f = sample(None);
            f.ether_type = et;
            assert_eq!(parse_frame(&f.marshal()).unwrap().ether_type, et);
        }
    }

    #[test]
    fn runt_frames_are_rejected_rather_than_panicking() {
        assert!(parse_frame(&[]).is_err());
        assert!(parse_frame(&[0; 13]).is_err());
        // Exactly a header and nothing else is a valid, empty frame.
        assert!(parse_frame(&[0; 14]).is_ok());
        assert!(parse_frame(&parse_frame(&[0; 14]).unwrap().marshal()).is_ok());

        // A frame that announces a tag but is cut off inside it.
        let mut b = vec![0u8; 16];
        b[12] = 0x81;
        b[13] = 0x00;
        assert!(parse_frame(&b).is_err());
    }

    #[test]
    fn an_empty_payload_is_preserved() {
        let f = Frame {
            payload: Vec::new(),
            ether_type: ETHER_TYPE_GOOSE,
            ..Default::default()
        };
        let back = parse_frame(&f.marshal()).unwrap();
        assert!(back.payload.is_empty());
        assert_eq!(back, f);
    }
}
