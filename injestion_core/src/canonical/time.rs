use std::fmt;

use chrono::{DateTime, Datelike, SecondsFormat, Utc};

const NANOS_PER_SECOND: i128 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExactTimeError {
    InvalidDecimal,
    UnsupportedPrecision,
    NegativeDuration,
    OutOfRange,
    InvalidCanonicalUtc,
}

impl fmt::Display for ExactTimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidDecimal => "value is not a plain decimal number",
            Self::UnsupportedPrecision => "fractional precision exceeds nanoseconds",
            Self::NegativeDuration => "duration is negative",
            Self::OutOfRange => "timestamp is outside canonical RFC3339 calendar range",
            Self::InvalidCanonicalUtc => "value is not canonical RFC3339 UTC with a Z suffix",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ExactTimeError {}

fn parse_decimal_nanoseconds(raw: &str) -> Result<i128, ExactTimeError> {
    let (negative, unsigned) = if let Some(value) = raw.strip_prefix('-') {
        (true, value)
    } else if let Some(value) = raw.strip_prefix('+') {
        (false, value)
    } else {
        (false, raw)
    };

    if unsigned.is_empty() {
        return Err(ExactTimeError::InvalidDecimal);
    }
    let mut parts = unsigned.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() || whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ExactTimeError::InvalidDecimal);
    }

    let whole: i128 = whole.parse().map_err(|_| ExactTimeError::OutOfRange)?;
    let mut nanos = 0_i128;
    if let Some(fraction) = fraction {
        if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ExactTimeError::InvalidDecimal);
        }
        let significant = if fraction.len() > 9 {
            if fraction.as_bytes()[9..].iter().any(|digit| *digit != b'0') {
                return Err(ExactTimeError::UnsupportedPrecision);
            }
            &fraction[..9]
        } else {
            fraction
        };
        let parsed: i128 = significant
            .parse()
            .map_err(|_| ExactTimeError::InvalidDecimal)?;
        nanos = parsed * 10_i128.pow((9 - significant.len()) as u32);
    }

    let total = whole
        .checked_mul(NANOS_PER_SECOND)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(ExactTimeError::OutOfRange)?;
    Ok(if negative { -total } else { total })
}

fn format_utc(total_nanoseconds: i128) -> Result<String, ExactTimeError> {
    let seconds = total_nanoseconds.div_euclid(NANOS_PER_SECOND);
    let nanos = total_nanoseconds.rem_euclid(NANOS_PER_SECOND) as u32;
    let seconds: i64 = seconds.try_into().map_err(|_| ExactTimeError::OutOfRange)?;
    let timestamp =
        DateTime::<Utc>::from_timestamp(seconds, nanos).ok_or(ExactTimeError::OutOfRange)?;
    if !(1..=9999).contains(&timestamp.year()) {
        return Err(ExactTimeError::OutOfRange);
    }
    Ok(timestamp.to_rfc3339_opts(SecondsFormat::AutoSi, true))
}

pub fn zeek_timestamp_to_rfc3339(raw: &str) -> Result<String, ExactTimeError> {
    format_utc(parse_decimal_nanoseconds(raw)?)
}

pub fn zeek_end_time_to_rfc3339(
    timestamp_raw: &str,
    duration_raw: &str,
) -> Result<String, ExactTimeError> {
    let timestamp = parse_decimal_nanoseconds(timestamp_raw)?;
    let duration = parse_decimal_nanoseconds(duration_raw)?;
    if duration < 0 {
        return Err(ExactTimeError::NegativeDuration);
    }
    let end = timestamp
        .checked_add(duration)
        .ok_or(ExactTimeError::OutOfRange)?;
    format_utc(end)
}

pub fn validate_canonical_utc(value: &str) -> Result<(), ExactTimeError> {
    let bytes = value.as_bytes();
    let separators_match = bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':');
    let digit_positions = [0_usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];
    if bytes.len() < 20
        || bytes.last() != Some(&b'Z')
        || !separators_match
        || !digit_positions
            .iter()
            .all(|position| bytes.get(*position).is_some_and(u8::is_ascii_digit))
    {
        return Err(ExactTimeError::InvalidCanonicalUtc);
    }

    let year: u16 = value[0..4]
        .parse()
        .map_err(|_| ExactTimeError::InvalidCanonicalUtc)?;
    let second: u8 = value[17..19]
        .parse()
        .map_err(|_| ExactTimeError::InvalidCanonicalUtc)?;
    if year == 0 || second > 59 {
        return Err(ExactTimeError::InvalidCanonicalUtc);
    }

    match bytes.get(19) {
        Some(b'Z') if bytes.len() == 20 => {}
        Some(b'.') if bytes.len() > 21 => {
            if !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit) {
                return Err(ExactTimeError::InvalidCanonicalUtc);
            }
        }
        _ => return Err(ExactTimeError::InvalidCanonicalUtc),
    }
    DateTime::parse_from_rfc3339(value).map_err(|_| ExactTimeError::InvalidCanonicalUtc)?;
    Ok(())
}
