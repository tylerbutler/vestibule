import gleam/time/duration
import vestibule/session_ttl

pub fn from_seconds_accepts_bounds_test() -> Nil {
  let assert Ok(minimum) = session_ttl.from_seconds(1)
  let assert Ok(maximum) = session_ttl.from_seconds(session_ttl.maximum_seconds)

  assert session_ttl.to_seconds(minimum) == 1
  assert session_ttl.to_seconds(maximum) == session_ttl.maximum_seconds
}

pub fn from_seconds_rejects_non_positive_values_test() -> Nil {
  assert session_ttl.from_seconds(0) == Error(session_ttl.NotPositive)
  assert session_ttl.from_seconds(-1) == Error(session_ttl.NotPositive)
}

pub fn from_seconds_rejects_values_above_maximum_test() -> Nil {
  assert session_ttl.from_seconds(session_ttl.maximum_seconds + 1)
    == Error(session_ttl.ExceedsMaximum)
}

pub fn from_duration_accepts_whole_seconds_test() -> Nil {
  let assert Ok(ttl) = session_ttl.from_duration(duration.seconds(600))

  assert session_ttl.to_seconds(ttl) == 600
  assert session_ttl.to_duration(ttl) == duration.seconds(600)
}

pub fn from_duration_rejects_invalid_values_test() -> Nil {
  assert session_ttl.from_duration(duration.seconds(0))
    == Error(session_ttl.NotPositive)
  assert session_ttl.from_duration(duration.seconds(-1))
    == Error(session_ttl.NotPositive)
  assert session_ttl.from_duration(duration.seconds(3601))
    == Error(session_ttl.ExceedsMaximum)
  assert session_ttl.from_duration(duration.nanoseconds(1))
    == Error(session_ttl.FractionalSeconds)
}
