//// A validated lifetime for short-lived OAuth flow sessions.
////
//// Session TTLs must be whole seconds between 1 and 3,600 inclusive. The
//// maximum limits the replay window for state stored during an OAuth flow.

import gleam/time/duration

/// The longest permitted session TTL, in seconds.
pub const maximum_seconds = 3600

/// The default lifetime for an OAuth flow session.
pub fn default() -> SessionTtl {
  SessionTtl(600)
}

/// A validated session lifetime.
pub opaque type SessionTtl {
  SessionTtl(seconds: Int)
}

/// Errors returned when constructing a session TTL.
pub type SessionTtlError {
  /// The TTL was zero or negative.
  NotPositive
  /// The TTL exceeded `maximum_seconds`.
  ExceedsMaximum
  /// The duration included a fraction of a second.
  FractionalSeconds
}

/// Construct a session TTL from whole seconds.
pub fn from_seconds(seconds: Int) -> Result(SessionTtl, SessionTtlError) {
  case seconds {
    seconds if seconds <= 0 -> Error(NotPositive)
    seconds if seconds > maximum_seconds -> Error(ExceedsMaximum)
    seconds -> Ok(SessionTtl(seconds))
  }
}

/// Construct a session TTL from a duration.
///
/// Durations with fractional seconds are rejected because storage and cookie
/// adapters use whole-second TTLs.
pub fn from_duration(
  value: duration.Duration,
) -> Result(SessionTtl, SessionTtlError) {
  case duration.to_seconds_and_nanoseconds(value) {
    #(seconds, 0) -> from_seconds(seconds)
    _ -> Error(FractionalSeconds)
  }
}

/// Return the validated TTL in whole seconds.
pub fn to_seconds(ttl: SessionTtl) -> Int {
  ttl.seconds
}

/// Return the validated TTL as a duration.
pub fn to_duration(ttl: SessionTtl) -> duration.Duration {
  duration.seconds(ttl.seconds)
}
