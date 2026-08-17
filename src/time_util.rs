//! Calendar and formatting helpers for the protocol timestamp types.
//!
//! IEC 61850 carries time as a count of seconds from the Unix epoch
//! (`UtcTime`) or of days from 1984-01-01 (`BinaryTime`), and SCL carries
//! ISO 8601 text. Converting between those and a civil date is the only
//! calendar arithmetic the crate needs, so it is done here rather than by
//! taking on a date-time dependency.
//!
//! The civil-date conversions are the standard proleptic-Gregorian
//! shift-the-epoch-to-March algorithms, valid across the whole `i64` range.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Days from 1970-01-01 to 1984-01-01, the `BinaryTime` epoch.
pub const BINARY_TIME_EPOCH_DAYS: i64 = 5113;

/// Splits a `SystemTime` into whole seconds and nanoseconds since the Unix
/// epoch. Times before the epoch yield a negative second count.
pub fn unix_parts(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let (secs, nanos) = (d.as_secs() as i64, d.subsec_nanos());
            if nanos == 0 {
                (-secs, 0)
            } else {
                // Borrow a second so the nanosecond part stays positive.
                (-secs - 1, 1_000_000_000 - nanos)
            }
        }
    }
}

/// Rebuilds a `SystemTime` from seconds and nanoseconds since the Unix epoch.
pub fn from_unix(secs: i64, nanos: u32) -> SystemTime {
    let base = if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    };
    base + Duration::from_nanos(u64::from(nanos))
}

/// Returns the number of days from 1970-01-01 to the given proleptic
/// Gregorian civil date.
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // March = 0
    let doy = (153 * i64::from(mp) + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Returns the proleptic Gregorian civil date for a count of days from
/// 1970-01-01.
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March = 0
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Splits seconds since the Unix epoch into a civil date and time of day.
pub fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    (
        y,
        mo,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

/// Formats seconds and nanoseconds since the Unix epoch as RFC 3339 in UTC.
///
/// The fractional part is omitted when zero, and otherwise printed to
/// millisecond, microsecond or nanosecond precision, whichever is exact.
pub fn format_rfc3339(secs: i64, nanos: u32) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    let mut out = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}");
    if nanos != 0 {
        if nanos % 1_000_000 == 0 {
            out.push_str(&format!(".{:03}", nanos / 1_000_000));
        } else if nanos % 1_000 == 0 {
            out.push_str(&format!(".{:06}", nanos / 1_000));
        } else {
            out.push_str(&format!(".{nanos:09}"));
        }
    }
    out.push('Z');
    out
}

/// Formats a `SystemTime` as RFC 3339 in UTC.
pub fn format_system_time(t: SystemTime) -> String {
    let (secs, nanos) = unix_parts(t);
    format_rfc3339(secs, nanos)
}

/// Parses an ISO 8601 / RFC 3339 timestamp into seconds and nanoseconds since
/// the Unix epoch.
///
/// Accepts `YYYY-MM-DD` optionally followed by `T`/space, a time of day, a
/// fractional part and either `Z` or a `+HH:MM` offset. This is what appears
/// in SCL `Header`/`History` attributes, which is the only place the crate
/// parses text timestamps.
pub fn parse_iso8601(s: &str) -> Option<(i64, u32)> {
    let s = s.trim();
    let bytes = s.as_bytes();
    if bytes.len() < 10 {
        return None;
    }
    let y: i64 = s.get(0..4)?.parse().ok()?;
    if bytes[4] != b'-' {
        return None;
    }
    let mo: u32 = s.get(5..7)?.parse().ok()?;
    if bytes[7] != b'-' {
        return None;
    }
    let d: u32 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let mut secs = days_from_civil(y, mo, d) * 86_400;
    let mut nanos = 0u32;

    let rest = &s[10..];
    if rest.is_empty() {
        return Some((secs, 0));
    }
    let rest = match rest.as_bytes()[0] {
        b'T' | b't' | b' ' => &rest[1..],
        _ => return None,
    };
    if rest.len() < 5 {
        return None;
    }
    let h: i64 = rest.get(0..2)?.parse().ok()?;
    let mi: i64 = rest.get(3..5)?.parse().ok()?;
    if rest.as_bytes()[2] != b':' || h > 23 || mi > 59 {
        return None;
    }
    secs += h * 3600 + mi * 60;
    let mut rest = &rest[5..];
    if rest.starts_with(':') {
        let sec: i64 = rest.get(1..3)?.parse().ok()?;
        if sec > 60 {
            return None;
        }
        secs += sec;
        rest = &rest[3..];
    }
    if rest.starts_with('.') || rest.starts_with(',') {
        let digits: String = rest[1..].chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        // Scale the fraction to nanoseconds, truncating beyond 9 digits.
        let mut frac = String::from(&digits[..digits.len().min(9)]);
        while frac.len() < 9 {
            frac.push('0');
        }
        nanos = frac.parse().ok()?;
        rest = &rest[1 + digits.len()..];
    }
    // Zone: Z, or an explicit offset to subtract back to UTC.
    match rest.as_bytes().first() {
        None | Some(b'Z') | Some(b'z') => {}
        Some(sign @ (b'+' | b'-')) => {
            let oh: i64 = rest.get(1..3)?.parse().ok()?;
            let om: i64 = if rest.len() >= 6 {
                rest.get(4..6)?.parse().ok()?
            } else if rest.len() >= 5 {
                rest.get(3..5)?.parse().ok()?
            } else {
                0
            };
            let offset = oh * 3600 + om * 60;
            secs += if *sign == b'+' { -offset } else { offset };
        }
        _ => return None,
    }
    Some((secs, nanos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_round_trip_across_leap_rules() {
        for &(y, m, d) in &[
            (1970, 1, 1),
            (1984, 1, 1),
            (1900, 3, 1), // not a leap year: divisible by 100, not 400
            (2000, 2, 29), // a leap year: divisible by 400
            (2024, 2, 29),
            (2026, 8, 16),
            (2100, 3, 1),
            (1600, 12, 31),
        ] {
            let days = days_from_civil(y, m, d);
            assert_eq!(
                civil_from_days(days),
                (y, m, d),
                "round trip failed for {y}-{m}-{d}"
            );
        }
    }

    #[test]
    fn the_epochs_land_where_the_standards_put_them() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(
            days_from_civil(1984, 1, 1),
            BINARY_TIME_EPOCH_DAYS,
            "the BinaryTime epoch must be 1984-01-01"
        );
    }

    #[test]
    fn rfc3339_formatting_scales_the_fraction_to_what_is_exact() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_755_302_400, 0), "2025-08-16T00:00:00Z");
        assert_eq!(format_rfc3339(0, 500_000_000), "1970-01-01T00:00:00.500Z");
        assert_eq!(format_rfc3339(0, 1_500_000), "1970-01-01T00:00:00.001500Z");
        assert_eq!(format_rfc3339(0, 1), "1970-01-01T00:00:00.000000001Z");
    }

    #[test]
    fn times_before_the_epoch_keep_a_positive_nanosecond_part() {
        let t = UNIX_EPOCH - Duration::from_nanos(1);
        let (secs, nanos) = unix_parts(t);
        assert_eq!((secs, nanos), (-1, 999_999_999));
        assert_eq!(from_unix(secs, nanos), t);
    }

    #[test]
    fn system_time_round_trips_through_unix_parts() {
        for t in [
            UNIX_EPOCH,
            UNIX_EPOCH + Duration::from_nanos(1_755_302_400_123_456_789),
            UNIX_EPOCH - Duration::from_secs(86_400),
        ] {
            let (s, n) = unix_parts(t);
            assert_eq!(from_unix(s, n), t);
        }
    }

    #[test]
    fn iso8601_parsing_covers_the_forms_scl_uses() {
        assert_eq!(parse_iso8601("2026-08-16"), Some((1_786_838_400, 0)));
        assert_eq!(
            parse_iso8601("2026-08-16T00:00:00Z"),
            Some((1_786_838_400, 0))
        );
        assert_eq!(
            parse_iso8601("2026-08-16T12:30:45.250Z"),
            Some((1_786_838_400 + 45_045, 250_000_000))
        );
        // An explicit offset is converted back to UTC.
        assert_eq!(
            parse_iso8601("2026-08-16T02:00:00+02:00"),
            Some((1_786_838_400, 0))
        );
        assert_eq!(
            parse_iso8601("2026-08-15T22:00:00-02:00"),
            Some((1_786_838_400, 0))
        );
    }

    #[test]
    fn malformed_timestamps_are_rejected() {
        for s in ["", "not-a-date", "2026-13-01", "2026-08-32", "2026/08/16"] {
            assert!(parse_iso8601(s).is_none(), "{s} should not parse");
        }
    }

    #[test]
    fn formatting_and_parsing_are_inverse() {
        for secs in [0i64, 1_755_302_400, 946_684_800, -86_400] {
            let text = format_rfc3339(secs, 0);
            assert_eq!(parse_iso8601(&text), Some((secs, 0)), "{text}");
        }
    }
}
