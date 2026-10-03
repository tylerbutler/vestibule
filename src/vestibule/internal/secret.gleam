//// Wrapper for sensitive strings that must not appear in `string.inspect` or
//// Erlang `~p` formatting.
////
//// The secret value is captured inside a closure. On the Erlang target a
//// function is rendered without its captured environment, so inspecting a
//// value that holds a `Secret` redacts the underlying string. This reduces
//// accidental disclosure through ordinary term rendering; it does not erase
//// process memory or guarantee secrecy in VM dumps. Callers must opt in to the
//// raw value through `expose`.

/// An opaque holder for a sensitive string. Its `inspect`/debug rendering never
/// reveals the wrapped value.
pub opaque type Secret {
  Secret(reveal: fn() -> String)
}

/// Wrap a sensitive string so it is hidden from inspect/debug output.
pub fn from_string(value: String) -> Secret {
  Secret(reveal: fn() { value })
}

/// Reveal the wrapped string. This is the only way to read the raw value, so
/// every leak point is explicit at the call site.
pub fn expose(secret: Secret) -> String {
  secret.reveal()
}
