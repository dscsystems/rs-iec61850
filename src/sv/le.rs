//! The IEC 61850-9-2LE profile: a fixed dataset of four currents and four
//! voltages, which is what makes a zero-allocation receive path possible.

use crate::model::Quality;

use super::{Asdu, Error, Result};

/// The byte length of a 9-2LE `phsMeas` payload: eight pairs of an `INT32`
/// value and a `UINT32` quality word.
pub const LE_SAMPLE_LEN: usize = 8 * 8;

/// A decoded 9-2LE dataset: four currents and four voltages, each an `INT32`
/// scaled value with a 32-bit quality word.
///
/// The 9-2LE `PhsMeas1` dataset lays these out as eight value-and-quality
/// pairs in the fixed order I_A, I_B, I_C, I_N, V_A, V_B, V_C, V_N. That fixed
/// layout is the whole point of the profile: a subscriber decodes it with
/// arithmetic rather than a BER walk, which is what keeps up with 4000 samples
/// a second.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LeSample {
    pub smp_cnt: u16,
    pub smp_synch: u8,
    /// The four current channels, in the order I_A, I_B, I_C, I_N.
    pub i: [i32; 4],
    /// The four voltage channels, in the order V_A, V_B, V_C, V_N.
    pub v: [i32; 4],
    /// Quality words: currents at 0..=3, then voltages at 4..=7.
    pub q: [u32; 8],
}

impl LeSample {
    /// Returns the quality of channel `i`: 0..=3 are currents, 4..=7 voltages.
    ///
    /// The quality word carries the 13-bit IEC 61850-7-3 quality in its low
    /// bits; the rest is reserved and masked off here.
    pub fn quality(&self, i: usize) -> Quality {
        match self.q.get(i) {
            Some(q) => Quality((*q & 0x1fff) as u16),
            None => Quality::GOOD,
        }
    }

    /// Sets the quality of channel `i`.
    pub fn set_quality(&mut self, i: usize, q: Quality) {
        if let Some(slot) = self.q.get_mut(i) {
            *slot = u32::from(q.0);
        }
    }
}

/// Serialises a 9-2LE dataset payload, 64 octets.
pub fn encode_le_sample(s: &LeSample) -> Vec<u8> {
    let mut b = vec![0u8; LE_SAMPLE_LEN];
    write_le_sample(s, &mut b);
    b
}

/// Serialises into a caller-provided buffer, for a publisher that reuses one.
///
/// Returns false when the buffer is too small.
pub fn write_le_sample(s: &LeSample, out: &mut [u8]) -> bool {
    if out.len() < LE_SAMPLE_LEN {
        return false;
    }
    for i in 0..4 {
        out[i * 8..i * 8 + 4].copy_from_slice(&(s.i[i] as u32).to_be_bytes());
        out[i * 8 + 4..i * 8 + 8].copy_from_slice(&s.q[i].to_be_bytes());
    }
    for i in 0..4 {
        let off = 32 + i * 8;
        out[off..off + 4].copy_from_slice(&(s.v[i] as u32).to_be_bytes());
        out[off + 4..off + 8].copy_from_slice(&s.q[4 + i].to_be_bytes());
    }
    true
}

/// Parses a 9-2LE dataset payload.
///
/// `smp_cnt` and `smp_synch` are left zero; they belong to the enclosing ASDU
/// and [`decode_le_into`] copies them across.
pub fn decode_le_sample(sample: &[u8]) -> Result<LeSample> {
    let mut s = LeSample::default();
    fill_from(&mut s, sample)?;
    Ok(s)
}

/// Decodes into a caller-provided sample, for the zero-allocation receive
/// path, taking the sample count and synchronisation state from the ASDU.
pub fn decode_le_into(a: &Asdu, s: &mut LeSample) -> Result<()> {
    fill_from(s, &a.sample)?;
    s.smp_cnt = a.smp_cnt;
    s.smp_synch = a.smp_synch;
    Ok(())
}

fn fill_from(s: &mut LeSample, sample: &[u8]) -> Result<()> {
    if sample.len() < LE_SAMPLE_LEN {
        return Err(Error::Codec(format!(
            "9-2LE sample of {} octets, want {LE_SAMPLE_LEN}",
            sample.len()
        )));
    }
    let word = |off: usize| -> u32 {
        u32::from_be_bytes([
            sample[off],
            sample[off + 1],
            sample[off + 2],
            sample[off + 3],
        ])
    };
    for i in 0..4 {
        s.i[i] = word(i * 8) as i32;
        s.q[i] = word(i * 8 + 4);
    }
    for i in 0..4 {
        let off = 32 + i * 8;
        s.v[i] = word(off) as i32;
        s.q[4 + i] = word(off + 4);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Validity;

    fn sample() -> LeSample {
        LeSample {
            smp_cnt: 1234,
            smp_synch: super::super::SMP_SYNCH_GLOBAL,
            i: [1000, -2000, 3000, -4],
            v: [230_000, -230_001, 230_002, 5],
            q: [0, 1, 2, 3, 4, 5, 6, 7],
        }
    }

    #[test]
    fn a_sample_round_trips_through_its_fixed_layout() {
        let s = sample();
        let encoded = encode_le_sample(&s);
        assert_eq!(encoded.len(), LE_SAMPLE_LEN);

        let back = decode_le_sample(&encoded).unwrap();
        assert_eq!(back.i, s.i);
        assert_eq!(back.v, s.v);
        assert_eq!(back.q, s.q);
        // The count and synchronisation belong to the ASDU, not the payload.
        assert_eq!(back.smp_cnt, 0);
        assert_eq!(back.smp_synch, 0);
    }

    /// Currents are signed: an instantaneous value is negative for half of
    /// every cycle, so reading them unsigned corrupts every other half-wave.
    #[test]
    fn negative_channel_values_survive() {
        let s = LeSample {
            i: [i32::MIN, -1, 0, i32::MAX],
            v: [-1, i32::MIN, i32::MAX, 0],
            ..Default::default()
        };
        let back = decode_le_sample(&encode_le_sample(&s)).unwrap();
        assert_eq!(back.i, s.i);
        assert_eq!(back.v, s.v);
    }

    /// The layout is fixed by the profile: currents then voltages, each value
    /// followed by its own quality word.
    #[test]
    fn the_channel_order_is_the_one_the_profile_fixes() {
        let s = LeSample {
            i: [0x0a0a0a0a, 0, 0, 0],
            v: [0x0b0b0b0b, 0, 0, 0],
            q: [0x0c0c0c0c, 0, 0, 0, 0x0d0d0d0d, 0, 0, 0],
            ..Default::default()
        };
        let b = encode_le_sample(&s);
        assert_eq!(&b[0..4], &[0x0a; 4], "I_A first");
        assert_eq!(&b[4..8], &[0x0c; 4], "then its quality");
        assert_eq!(&b[32..36], &[0x0b; 4], "voltages start at octet 32");
        assert_eq!(&b[36..40], &[0x0d; 4], "then its quality");
    }

    #[test]
    fn a_short_payload_is_rejected() {
        assert!(decode_le_sample(&[]).is_err());
        assert!(decode_le_sample(&[0; LE_SAMPLE_LEN - 1]).is_err());
        assert!(decode_le_sample(&[0; LE_SAMPLE_LEN]).is_ok());
        // A longer one is fine: a publisher may append its own extension.
        assert!(decode_le_sample(&[0; LE_SAMPLE_LEN + 16]).is_ok());
    }

    #[test]
    fn writing_into_a_short_buffer_is_refused_rather_than_truncating() {
        let mut buf = [0u8; LE_SAMPLE_LEN - 1];
        assert!(!write_le_sample(&sample(), &mut buf));

        let mut buf = [0u8; LE_SAMPLE_LEN];
        assert!(write_le_sample(&sample(), &mut buf));
        assert_eq!(buf.to_vec(), encode_le_sample(&sample()));
    }

    /// The 32-bit quality word carries the 13-bit quality in its low bits;
    /// taking the whole word would report reserved bits as quality flags.
    #[test]
    fn the_quality_word_masks_down_to_the_standard_thirteen_bits() {
        let mut s = LeSample::default();
        s.q[0] = 0xffff_ffff;
        let q = s.quality(0);
        assert_eq!(q.0, 0x1fff, "only the low 13 bits are quality");

        s.set_quality(1, Quality::GOOD | Quality::OLD_DATA);
        assert!(s.quality(1).is(Quality::OLD_DATA));
        assert_eq!(s.quality(1).validity(), Validity::Good);

        // An out-of-range channel reads as good rather than panicking.
        assert_eq!(s.quality(99), Quality::GOOD);
    }

    #[test]
    fn decoding_into_a_reused_sample_takes_the_count_from_the_asdu() {
        let a = Asdu {
            smp_cnt: 3999,
            smp_synch: super::super::SMP_SYNCH_GLOBAL,
            sample: encode_le_sample(&sample()),
            ..Default::default()
        };
        let mut s = LeSample::default();
        decode_le_into(&a, &mut s).unwrap();
        assert_eq!(s.smp_cnt, 3999);
        assert_eq!(s.smp_synch, super::super::SMP_SYNCH_GLOBAL);
        assert_eq!(s.i, sample().i);

        // Reusing the same sample overwrites every field, leaving nothing
        // stale from the previous decode.
        let a2 = Asdu {
            smp_cnt: 1,
            smp_synch: super::super::SMP_SYNCH_NONE,
            sample: encode_le_sample(&LeSample::default()),
            ..Default::default()
        };
        decode_le_into(&a2, &mut s).unwrap();
        assert_eq!(s.smp_cnt, 1);
        assert_eq!(s.i, [0; 4]);
        assert_eq!(s.q, [0; 8]);
    }

    #[test]
    fn a_short_sample_leaves_the_reused_buffer_untouched() {
        let mut s = sample();
        let before = s;
        let a = Asdu {
            sample: vec![0; 8],
            ..Default::default()
        };
        assert!(decode_le_into(&a, &mut s).is_err());
        assert_eq!(s, before, "a rejected decode must not half-fill the sample");
    }
}
