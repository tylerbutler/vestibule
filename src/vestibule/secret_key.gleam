//// Opaque wrapper for cookie-signing key material.

import gleam/bit_array

/// A cookie-signing key that does not reveal its bytes during inspection or
/// Erlang term formatting.
pub opaque type SecretKey {
  SecretKey(reveal: fn() -> BitArray)
}

/// Wrap cookie-signing key bytes before passing them to middleware.
pub fn from_bit_array(value: BitArray) -> SecretKey {
  SecretKey(reveal: fn() { value })
}

/// Return the key length without exposing the key bytes to callers.
pub fn byte_size(key: SecretKey) -> Int {
  bit_array.byte_size(key.reveal())
}

/// Reveal the key only at the cryptographic call boundary.
pub fn expose(key: SecretKey) -> BitArray {
  key.reveal()
}
