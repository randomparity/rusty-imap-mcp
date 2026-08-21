//! Strongly-typed identifiers and timestamp newtype used throughout the
//! audit record schema. Keeping these distinct from raw integers and strings
//! prevents accidental argument-swap bugs when building records by hand.
//!
//! Unlike the payload structs in [`super`], these are deliberately **not**
//! `#[non_exhaustive]`. Each is a `#[serde(transparent)]` newtype whose single
//! field *is* its identity: there is no second field to add later, so the
//! attribute would guard against a change that cannot happen while costing
//! every caller the ability to write `Seq(1)`. A second field here would be a
//! redesign of the on-disk header, not an additive change, and would go
//! through the same review either way.

use core::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use ulid::Ulid;

/// Per-process monotonic sequence number. Starts at 1 on `process_start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Seq(pub u64);

impl Seq {
    /// First sequence number every process emits.
    pub const FIRST: Self = Self(1);

    /// Returns the next sequence number. Saturating on `u64::MAX`.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Underlying integer.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Stable identifier for a single process lifetime. Backed by a ULID so logs
/// from different processes interleave in a meaningful order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProcessId(pub Ulid);

impl ProcessId {
    /// Generate a fresh process ID from the current system time + randomness.
    #[must_use]
    pub fn new_now() -> Self {
        Self(Ulid::generate())
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Millisecond-precision UTC timestamp, serialized as RFC 3339.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    /// Current wall-clock time in UTC, truncated to millisecond precision.
    #[must_use]
    pub fn now() -> Self {
        Self::from_offset(OffsetDateTime::now_utc())
    }

    /// Construct from an [`OffsetDateTime`], truncating sub-millisecond
    /// precision so that the value round-trips cleanly through serde.
    #[must_use]
    #[expect(
        clippy::expect_used,
        clippy::missing_panics_doc,
        reason = "ms is always 0..=999_000_000, a valid nanosecond value"
    )]
    pub fn from_offset(dt: OffsetDateTime) -> Self {
        // `OffsetDateTime::nanosecond()` can return up to 1_999_999_999 during
        // a positive leap second; clamp to the `replace_nanosecond` input range
        // (0..=999_999_999) so the let-else never fires.
        let clamped_ns = dt.nanosecond().min(999_999_999);
        let ms = clamped_ns / 1_000_000 * 1_000_000;
        let truncated = dt
            .replace_nanosecond(ms)
            .expect("ms truncation produces a valid nanosecond value (0..=999_000_000)");
        Self(truncated)
    }

    /// Return the underlying [`OffsetDateTime`] (already millisecond-truncated).
    #[must_use]
    pub fn offset(self) -> OffsetDateTime {
        self.0
    }

    /// Format as RFC 3339 with millisecond precision, always ending in `Z`.
    /// Returns `None` if the underlying timestamp cannot be formatted (which,
    /// in practice, cannot happen for a well-formed `OffsetDateTime`).
    #[must_use]
    pub fn to_rfc3339_millis(self) -> Option<String> {
        self.0.format(&Rfc3339).ok()
    }
}

impl Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        // Format as RFC 3339 with exactly three fractional digits (milliseconds).
        // Manual formatting ensures zero millis are always emitted as `.000`
        // rather than being elided by the time crate's default formatter.
        let year = self.0.year();
        let month = self.0.month() as u8;
        let day = self.0.day();
        let hour = self.0.hour();
        let minute = self.0.minute();
        let second = self.0.second();
        let millisecond = self.0.millisecond();

        let s = format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millisecond:03}Z"
        );
        ser.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = <&str as Deserialize>::deserialize(de)?;
        let dt = OffsetDateTime::parse(s, &Rfc3339).map_err(serde::de::Error::custom)?;
        Ok(Self::from_offset(dt))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::record::ids::{ProcessId, Seq, Timestamp};

    #[test]
    fn seq_starts_at_one_and_increments() {
        let s = Seq::FIRST;
        assert_eq!(s.get(), 1);
        assert_eq!(s.next().get(), 2);
        assert_eq!(s.next().next().get(), 3);
    }

    #[test]
    fn seq_next_saturates() {
        let s = Seq(u64::MAX);
        assert_eq!(s.next().get(), u64::MAX);
    }

    #[test]
    fn seq_display_uses_integer() {
        assert_eq!(Seq(42).to_string(), "42");
    }

    #[test]
    fn process_id_is_unique_per_call() {
        let a = ProcessId::new_now();
        let b = ProcessId::new_now();
        assert_ne!(a, b);
    }

    #[test]
    fn process_id_display_is_ulid_encoded() {
        let id = ProcessId::new_now();
        let s = id.to_string();
        assert_eq!(s.len(), 26, "ULID canonical form is 26 chars: got {s}");
    }

    #[test]
    fn process_id_embeds_current_time_in_its_prefix() {
        // The ULID time prefix is what lets records from different processes
        // interleave in a meaningful order. A constructor that dropped the
        // wall-clock component would still produce unique 26-char values, so
        // neither test above would catch it — this one pins the ordering
        // property directly across future `ulid` bumps.
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let id = ProcessId::new_now();
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let embedded = u128::from(id.0.timestamp_ms());
        assert!(
            (before..=after).contains(&embedded),
            "ULID time prefix {embedded} outside [{before}, {after}]"
        );
    }

    #[test]
    fn timestamp_serializes_as_rfc3339_millis() {
        // Use a fixed timestamp with a non-zero millisecond component so the
        // serialized form is deterministic (no dependence on wall-clock).
        let dt = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap()
            .replace_nanosecond(234_000_000)
            .unwrap();
        let ts = Timestamp::from_offset(dt);
        let json = serde_json::to_string(&ts).unwrap();
        assert!(json.starts_with('"'));
        assert!(json.ends_with("Z\""));
        assert!(json.contains(".234"), "expected .234 ms suffix, got {json}",);
    }

    #[test]
    fn timestamp_round_trips_through_serde() {
        let ts = Timestamp::now();
        let json = serde_json::to_string(&ts).unwrap();
        let back: Timestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ts);
    }

    #[test]
    fn timestamp_deserialize_rejects_malformed_input() {
        let result: Result<Timestamp, _> = serde_json::from_str("\"not-a-date\"");
        assert!(
            result.is_err(),
            "expected parse error for malformed RFC 3339"
        );
        let result: Result<Timestamp, _> = serde_json::from_str("\"2026-04-07\"");
        assert!(
            result.is_err(),
            "date without time component should not parse"
        );
    }

    #[test]
    fn from_offset_clamps_leap_second_nanosecond() {
        // Build an OffsetDateTime with a nanosecond value at the upper edge
        // of the normal range (999_999_999). A true leap-second OffsetDateTime
        // with nanosecond > 999_999_999 cannot be constructed via the public
        // `time` API, but the clamp guard protects against any future platform
        // that returns such a value from `nanosecond()`.
        let dt = time::OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .unwrap()
            .replace_nanosecond(999_999_999)
            .unwrap();
        // This must not panic.
        let _ts = Timestamp::from_offset(dt);
    }
}
