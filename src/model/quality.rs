//! The IEC 61850-7-3 bit-string types: `Quality`, `Dbpos`, trigger options,
//! report optional fields and the per-entry reason code.
//!
//! Each maps to and from an [`mms::Value`] bit string of a fixed width, with
//! bit 0 being the first transmitted bit.

use crate::mms::Value;

/// Builds a fixed-width bit string from a bitmask, bit 0 first.
fn to_bits(mask: u32, width: usize) -> Value {
    let mut v = Value::bit_string(width);
    for i in 0..width {
        v.set_bit(i, mask & (1 << i) != 0);
    }
    v
}

/// Reads a bitmask from a bit-string value, taking at most `width` bits.
///
/// A shorter or absent value decodes to zero, which is the all-clear for every
/// type here.
fn from_bits(v: &Value, width: usize) -> u32 {
    let n = v.bit_len().min(width);
    let mut mask = 0u32;
    for i in 0..n {
        if v.bit(i) {
            mask |= 1 << i;
        }
    }
    mask
}

/// The validity field of a [`Quality`] (bits 0 and 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Validity {
    #[default]
    Good,
    Invalid,
    Reserved,
    Questionable,
}

impl Validity {
    pub fn from_bits(b: u16) -> Validity {
        match b & 3 {
            0 => Validity::Good,
            1 => Validity::Invalid,
            2 => Validity::Reserved,
            _ => Validity::Questionable,
        }
    }

    pub fn bits(self) -> u16 {
        match self {
            Validity::Good => 0,
            Validity::Invalid => 1,
            Validity::Reserved => 2,
            Validity::Questionable => 3,
        }
    }
}

impl std::fmt::Display for Validity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Validity::Good => "good",
            Validity::Invalid => "invalid",
            Validity::Reserved => "reserved",
            Validity::Questionable => "questionable",
        })
    }
}

/// The IEC 61850-7-3 `Quality` type: a 13-bit string.
///
/// Bit positions follow the standard, bit 0 being the first transmitted bit.
/// The detail flags combine with `|`, and the validity field occupies the low
/// two bits and is replaced with [`with_validity`](Quality::with_validity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct Quality(pub u16);

impl Quality {
    /// The all-clear quality.
    pub const GOOD: Quality = Quality(0);

    pub const OVERFLOW: Quality = Quality(1 << 2);
    pub const OUT_OF_RANGE: Quality = Quality(1 << 3);
    pub const BAD_REFERENCE: Quality = Quality(1 << 4);
    pub const OSCILLATORY: Quality = Quality(1 << 5);
    pub const FAILURE: Quality = Quality(1 << 6);
    pub const OLD_DATA: Quality = Quality(1 << 7);
    pub const INCONSISTENT: Quality = Quality(1 << 8);
    pub const INACCURATE: Quality = Quality(1 << 9);
    /// The source flag: clear for process, set for substituted.
    pub const SUBSTITUTED: Quality = Quality(1 << 10);
    pub const TEST: Quality = Quality(1 << 11);
    pub const OPERATOR_BLOCKED: Quality = Quality(1 << 12);

    /// The width of the bit string on the wire.
    pub const WIDTH: usize = 13;

    /// Returns the validity field.
    pub fn validity(self) -> Validity {
        Validity::from_bits(self.0)
    }

    /// Returns the quality with the validity field replaced.
    #[must_use]
    pub fn with_validity(self, v: Validity) -> Quality {
        Quality((self.0 & !3) | v.bits())
    }

    /// Reports whether every flag bit in `mask` is set.
    pub fn is(self, mask: Quality) -> bool {
        self.0 & mask.0 == mask.0
    }

    /// Converts the quality to a 13-bit MMS bit string.
    pub fn value(self) -> Value {
        to_bits(u32::from(self.0), Quality::WIDTH)
    }

    /// Converts a bit-string value back to a quality. Missing or short values
    /// decode as good.
    pub fn from_value(v: &Value) -> Quality {
        Quality(from_bits(v, 16) as u16)
    }
}

impl std::ops::BitOr for Quality {
    type Output = Quality;
    fn bitor(self, rhs: Quality) -> Quality {
        Quality(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for Quality {
    fn bitor_assign(&mut self, rhs: Quality) {
        self.0 |= rhs.0;
    }
}

impl std::fmt::Display for Quality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.validity())?;
        const FLAGS: [(Quality, &str); 11] = [
            (Quality::OVERFLOW, "overflow"),
            (Quality::OUT_OF_RANGE, "out-of-range"),
            (Quality::BAD_REFERENCE, "bad-reference"),
            (Quality::OSCILLATORY, "oscillatory"),
            (Quality::FAILURE, "failure"),
            (Quality::OLD_DATA, "old-data"),
            (Quality::INCONSISTENT, "inconsistent"),
            (Quality::INACCURATE, "inaccurate"),
            (Quality::SUBSTITUTED, "substituted"),
            (Quality::TEST, "test"),
            (Quality::OPERATOR_BLOCKED, "operator-blocked"),
        ];
        for (bit, name) in FLAGS {
            if self.is(bit) {
                write!(f, "|{name}")?;
            }
        }
        Ok(())
    }
}

/// The double-point position (IEC 61850-7-3), a 2-bit string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dbpos {
    #[default]
    Intermediate,
    Off,
    On,
    Bad,
}

impl Dbpos {
    pub fn bits(self) -> u8 {
        match self {
            Dbpos::Intermediate => 0,
            Dbpos::Off => 1,
            Dbpos::On => 2,
            Dbpos::Bad => 3,
        }
    }

    pub fn from_bits(b: u8) -> Dbpos {
        match b & 3 {
            0 => Dbpos::Intermediate,
            1 => Dbpos::Off,
            2 => Dbpos::On,
            _ => Dbpos::Bad,
        }
    }

    /// Converts to a 2-bit MMS bit string.
    ///
    /// The two bits are transmitted most-significant first, so bit 0 of the
    /// string carries the high bit of the value.
    pub fn value(self) -> Value {
        let b = self.bits();
        let mut v = Value::bit_string(2);
        v.set_bit(0, b & 2 != 0);
        v.set_bit(1, b & 1 != 0);
        v
    }

    /// Converts a 2-bit string back to a position.
    pub fn from_value(v: &Value) -> Dbpos {
        let mut b = 0u8;
        if v.bit(0) {
            b |= 2;
        }
        if v.bit(1) {
            b |= 1;
        }
        Dbpos::from_bits(b)
    }
}

impl std::fmt::Display for Dbpos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Dbpos::Intermediate => "intermediate",
            Dbpos::Off => "off",
            Dbpos::On => "on",
            Dbpos::Bad => "bad",
        })
    }
}

/// The report and log trigger-options bit string (6 bits; bit 0 is reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct TrgOps(pub u8);

impl TrgOps {
    pub const DATA_CHANGE: TrgOps = TrgOps(1 << 1);
    pub const QUALITY_CHANGE: TrgOps = TrgOps(1 << 2);
    pub const DATA_UPDATE: TrgOps = TrgOps(1 << 3);
    pub const INTEGRITY: TrgOps = TrgOps(1 << 4);
    pub const GI: TrgOps = TrgOps(1 << 5);

    pub const WIDTH: usize = 6;

    /// Reports whether any bit in `mask` is set.
    pub fn has(self, mask: TrgOps) -> bool {
        self.0 & mask.0 != 0
    }

    /// Converts to a 6-bit MMS bit string.
    pub fn value(self) -> Value {
        to_bits(u32::from(self.0), TrgOps::WIDTH)
    }

    /// Converts a bit string back to trigger options.
    pub fn from_value(v: &Value) -> TrgOps {
        TrgOps(from_bits(v, TrgOps::WIDTH) as u8)
    }
}

impl std::ops::BitOr for TrgOps {
    type Output = TrgOps;
    fn bitor(self, rhs: TrgOps) -> TrgOps {
        TrgOps(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for TrgOps {
    fn bitor_assign(&mut self, rhs: TrgOps) {
        self.0 |= rhs.0;
    }
}

impl std::fmt::Display for TrgOps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const FLAGS: [(TrgOps, &str); 5] = [
            (TrgOps::DATA_CHANGE, "dchg"),
            (TrgOps::QUALITY_CHANGE, "qchg"),
            (TrgOps::DATA_UPDATE, "dupd"),
            (TrgOps::INTEGRITY, "period"),
            (TrgOps::GI, "gi"),
        ];
        let mut wrote = false;
        for (bit, name) in FLAGS {
            if self.has(bit) {
                if wrote {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                wrote = true;
            }
        }
        if !wrote {
            f.write_str("none")?;
        }
        Ok(())
    }
}

/// The report optional-fields bit string (10 bits; bit 0 is reserved).
///
/// These bits drive the layout of every report on the wire: the encoder emits
/// exactly the fields they name and the decoder reads exactly those, so a
/// mismatch shifts every subsequent field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct OptFlds(pub u16);

impl OptFlds {
    pub const SEQ_NUM: OptFlds = OptFlds(1 << 1);
    pub const TIME_OF_ENTRY: OptFlds = OptFlds(1 << 2);
    pub const REASON_CODE: OptFlds = OptFlds(1 << 3);
    pub const DATA_SET_NAME: OptFlds = OptFlds(1 << 4);
    pub const DATA_REF: OptFlds = OptFlds(1 << 5);
    pub const BUF_OVFL: OptFlds = OptFlds(1 << 6);
    pub const ENTRY_ID: OptFlds = OptFlds(1 << 7);
    pub const CONF_REV: OptFlds = OptFlds(1 << 8);
    pub const SEGMENTATION: OptFlds = OptFlds(1 << 9);

    pub const WIDTH: usize = 10;

    /// What most clients enable.
    pub const DEFAULT: OptFlds = OptFlds(
        OptFlds::SEQ_NUM.0
            | OptFlds::TIME_OF_ENTRY.0
            | OptFlds::REASON_CODE.0
            | OptFlds::DATA_SET_NAME.0
            | OptFlds::CONF_REV.0,
    );

    /// Reports whether any bit in `mask` is set.
    pub fn has(self, mask: OptFlds) -> bool {
        self.0 & mask.0 != 0
    }

    /// Converts to a 10-bit MMS bit string.
    pub fn value(self) -> Value {
        to_bits(u32::from(self.0), OptFlds::WIDTH)
    }

    /// Converts a bit string back to optional fields.
    pub fn from_value(v: &Value) -> OptFlds {
        OptFlds(from_bits(v, OptFlds::WIDTH) as u16)
    }
}

impl std::ops::BitOr for OptFlds {
    type Output = OptFlds;
    fn bitor(self, rhs: OptFlds) -> OptFlds {
        OptFlds(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for OptFlds {
    fn bitor_assign(&mut self, rhs: OptFlds) {
        self.0 |= rhs.0;
    }
}

impl std::fmt::Display for OptFlds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const FLAGS: [(OptFlds, &str); 9] = [
            (OptFlds::SEQ_NUM, "seqnum"),
            (OptFlds::TIME_OF_ENTRY, "timestamp"),
            (OptFlds::REASON_CODE, "reason"),
            (OptFlds::DATA_SET_NAME, "dataset"),
            (OptFlds::DATA_REF, "dataref"),
            (OptFlds::BUF_OVFL, "bufovfl"),
            (OptFlds::ENTRY_ID, "entryid"),
            (OptFlds::CONF_REV, "confrev"),
            (OptFlds::SEGMENTATION, "segmentation"),
        ];
        let mut wrote = false;
        for (bit, name) in FLAGS {
            if self.has(bit) {
                if wrote {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                wrote = true;
            }
        }
        if !wrote {
            f.write_str("none")?;
        }
        Ok(())
    }
}

/// The per-entry inclusion reason in a report: a 7-bit string, bit 0 reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct ReasonCode(pub u8);

impl ReasonCode {
    pub const DATA_CHANGE: ReasonCode = ReasonCode(1 << 1);
    pub const QUALITY_CHANGE: ReasonCode = ReasonCode(1 << 2);
    pub const DATA_UPDATE: ReasonCode = ReasonCode(1 << 3);
    pub const INTEGRITY: ReasonCode = ReasonCode(1 << 4);
    pub const GI: ReasonCode = ReasonCode(1 << 5);
    pub const APPL_TRIGGER: ReasonCode = ReasonCode(1 << 6);

    pub const WIDTH: usize = 7;

    /// Reports whether any bit in `mask` is set.
    pub fn has(self, mask: ReasonCode) -> bool {
        self.0 & mask.0 != 0
    }

    /// Converts the reason to a 7-bit reason-for-inclusion bit string.
    pub fn value(self) -> Value {
        to_bits(u32::from(self.0), ReasonCode::WIDTH)
    }

    /// Converts a reason-for-inclusion bit string back to a reason.
    pub fn from_value(v: &Value) -> ReasonCode {
        ReasonCode(from_bits(v, ReasonCode::WIDTH) as u8)
    }
}

impl std::ops::BitOr for ReasonCode {
    type Output = ReasonCode;
    fn bitor(self, rhs: ReasonCode) -> ReasonCode {
        ReasonCode(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for ReasonCode {
    fn bitor_assign(&mut self, rhs: ReasonCode) {
        self.0 |= rhs.0;
    }
}

impl std::fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const FLAGS: [(ReasonCode, &str); 6] = [
            (ReasonCode::DATA_CHANGE, "dchg"),
            (ReasonCode::QUALITY_CHANGE, "qchg"),
            (ReasonCode::DATA_UPDATE, "dupd"),
            (ReasonCode::INTEGRITY, "integrity"),
            (ReasonCode::GI, "gi"),
            (ReasonCode::APPL_TRIGGER, "app-trigger"),
        ];
        let mut wrote = false;
        for (bit, name) in FLAGS {
            if self.has(bit) {
                if wrote {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                wrote = true;
            }
        }
        if !wrote {
            f.write_str("none")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_round_trips_through_its_bit_string() {
        let q = Quality::GOOD.with_validity(Validity::Questionable) | Quality::OLD_DATA;
        let v = q.value();
        assert_eq!(v.bit_len(), 13, "Quality is a 13-bit string");
        assert_eq!(Quality::from_value(&v), q);
        assert_eq!(q.validity(), Validity::Questionable);
        assert!(q.is(Quality::OLD_DATA));
        assert!(!q.is(Quality::TEST));
    }

    #[test]
    fn every_quality_flag_occupies_its_standard_bit() {
        // The bit positions are fixed by the standard; a shift here silently
        // corrupts quality on the wire.
        for (q, bit) in [
            (Quality::OVERFLOW, 2),
            (Quality::OUT_OF_RANGE, 3),
            (Quality::BAD_REFERENCE, 4),
            (Quality::OSCILLATORY, 5),
            (Quality::FAILURE, 6),
            (Quality::OLD_DATA, 7),
            (Quality::INCONSISTENT, 8),
            (Quality::INACCURATE, 9),
            (Quality::SUBSTITUTED, 10),
            (Quality::TEST, 11),
            (Quality::OPERATOR_BLOCKED, 12),
        ] {
            let v = q.value();
            assert!(v.bit(bit), "{q} should set bit {bit}");
            assert_eq!(v.to_string().chars().filter(|c| *c == '1').count(), 1);
        }
    }

    #[test]
    fn replacing_the_validity_leaves_the_detail_flags_alone() {
        let q = (Quality::GOOD | Quality::TEST | Quality::OLD_DATA)
            .with_validity(Validity::Invalid);
        assert_eq!(q.validity(), Validity::Invalid);
        assert!(q.is(Quality::TEST) && q.is(Quality::OLD_DATA));
        let q = q.with_validity(Validity::Good);
        assert_eq!(q.validity(), Validity::Good);
        assert!(q.is(Quality::TEST), "detail flags must survive");
    }

    #[test]
    fn quality_renders_its_validity_and_flags() {
        assert_eq!(Quality::GOOD.to_string(), "good");
        assert_eq!(
            (Quality::GOOD | Quality::OLD_DATA | Quality::TEST).to_string(),
            "good|old-data|test"
        );
        assert_eq!(
            Quality::GOOD.with_validity(Validity::Invalid).to_string(),
            "invalid"
        );
    }

    /// The two Dbpos bits are transmitted most-significant first, so a naive
    /// bit-0-is-the-low-bit mapping swaps "on" and "off".
    #[test]
    fn dbpos_maps_its_two_bits_most_significant_first() {
        let v = Dbpos::On.value();
        assert_eq!(v.bit_len(), 2);
        assert!(v.bit(0) && !v.bit(1), "on (10) sets the first bit only");

        let v = Dbpos::Off.value();
        assert!(!v.bit(0) && v.bit(1), "off (01) sets the second bit only");

        for d in [Dbpos::Intermediate, Dbpos::Off, Dbpos::On, Dbpos::Bad] {
            assert_eq!(Dbpos::from_value(&d.value()), d, "round trip failed for {d}");
        }
    }

    #[test]
    fn trigger_options_round_trip_and_render() {
        let t = TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE | TrgOps::GI;
        let v = t.value();
        assert_eq!(v.bit_len(), 6);
        assert_eq!(TrgOps::from_value(&v), t);
        assert_eq!(t.to_string(), "dchg|qchg|gi");
        assert_eq!(TrgOps::default().to_string(), "none");
        assert!(t.has(TrgOps::GI) && !t.has(TrgOps::INTEGRITY));
    }

    #[test]
    fn optional_fields_round_trip_and_render() {
        let o = OptFlds::DEFAULT;
        let v = o.value();
        assert_eq!(v.bit_len(), 10);
        assert_eq!(OptFlds::from_value(&v), o);
        assert_eq!(o.to_string(), "seqnum|timestamp|reason|dataset|confrev");
        assert!(o.has(OptFlds::SEQ_NUM));
        assert!(!o.has(OptFlds::ENTRY_ID));
    }

    #[test]
    fn reason_codes_round_trip_and_render() {
        let rc = ReasonCode::DATA_CHANGE | ReasonCode::GI;
        let v = rc.value();
        assert_eq!(v.bit_len(), 7);
        assert_eq!(ReasonCode::from_value(&v), rc);
        assert_eq!(rc.to_string(), "dchg|gi");
        assert_eq!(ReasonCode::default().to_string(), "none");
    }

    /// Devices differ on the width they send; a short or absent bit string
    /// must decode to the all-clear rather than to garbage.
    #[test]
    fn short_or_absent_bit_strings_decode_to_zero() {
        assert_eq!(Quality::from_value(&Value::None), Quality::GOOD);
        assert_eq!(TrgOps::from_value(&Value::None), TrgOps(0));
        assert_eq!(OptFlds::from_value(&Value::None), OptFlds(0));
        assert_eq!(ReasonCode::from_value(&Value::None), ReasonCode(0));
        assert_eq!(Dbpos::from_value(&Value::None), Dbpos::Intermediate);

        // A two-bit quality carries only the validity. Bit 0 is the low bit
        // of that field, so it alone is invalid(01) and bit 1 alone is
        // reserved(10).
        let mut short = Value::bit_string(2);
        short.set_bit(0, true);
        assert_eq!(Quality::from_value(&short).validity(), Validity::Invalid);

        let mut short = Value::bit_string(2);
        short.set_bit(1, true);
        assert_eq!(Quality::from_value(&short).validity(), Validity::Reserved);
    }
}
