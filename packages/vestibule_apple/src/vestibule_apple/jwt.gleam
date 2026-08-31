//// JWT verification using ywt_core with a custom Erlang FFI backend.
////
//// This replaces ywt_erlang to avoid an OTP 27 compatibility issue in
//// its EC key generation. We only need RS256 verification in production;
//// the RSA signing counterpart used by tests lives
//// in `test/vestibule_apple/jwt_signing.gleam`.

import gleam/bit_array
import gleam/dynamic/decode.{type Decoder}
import gleam/json
import gleam/result
import gleam/string
import gleam/time/timestamp
import ywt/claim.{type Claim}
import ywt/internal/core
import ywt/internal/jwt
import ywt/verify_key.{type VerifyKey}

/// Detailed error information for JWT parsing failures.
pub type ParseError {
  MalformedToken
  InvalidHeaderEncoding
  InvalidPayloadEncoding
  InvalidSignatureEncoding
  InvalidHeaderJson(json.DecodeError)
  InvalidPayloadJson(json.DecodeError)
  UnsupportedAlgorithm(actual: String)
  NoMatchingKey
  InvalidSignature
  TokenExpired(expired_at: timestamp.Timestamp)
  TokenNotYetValid(not_before: timestamp.Timestamp)
  InvalidIssuer(expected: List(String), actual: String)
  InvalidAudience(expected: List(String), actual: String)
  InvalidSubject(expected: List(String), actual: String)
  InvalidId(expected: List(String), actual: String)
  MissingClaim(claim_name: String)
  ClaimDecodingError(claim_name: String, error: List(decode.DecodeError))
  InvalidCustomClaim(claim_name: String)
  PayloadDecodingError(List(decode.DecodeError))
}

/// Verify a JWT signature and validate claims.
pub fn decode(
  jwt jwt: String,
  using decoder: Decoder(payload),
  claims claims: List(Claim),
  keys keys: List(VerifyKey),
) -> Result(payload, ParseError) {
  use Nil <- result.try(validate_rs256_header(jwt))
  let verify = fn(message, signature, key, next) {
    next(verify_bits(message, signature, key))
  }
  let resolve = result.map_error(_, from_core_error)
  jwt.decode(jwt:, using: decoder, claims:, keys:, verify:, resolve:)
}

@external(erlang, "vestibule_apple_jwt_ffi", "verify")
fn verify_bits(message: BitArray, signature: BitArray, key: VerifyKey) -> Bool

fn validate_rs256_header(token: String) -> Result(Nil, ParseError) {
  use raw_header <- result.try(case string.split(token, on: ".") {
    [header, _, _] -> Ok(header)
    _ -> Error(MalformedToken)
  })
  use header_bits <- result.try(
    bit_array.base64_url_decode(raw_header)
    |> result.replace_error(InvalidHeaderEncoding),
  )
  let header_decoder = {
    use algorithm <- decode.field("alg", decode.string)
    decode.success(algorithm)
  }
  use algorithm <- result.try(
    json.parse_bits(header_bits, header_decoder)
    |> result.map_error(InvalidHeaderJson),
  )
  case algorithm {
    "RS256" -> Ok(Nil)
    actual -> Error(UnsupportedAlgorithm(actual:))
  }
}

fn from_core_error(error: core.ParseError) -> ParseError {
  case error {
    core.ClaimDecodingError(claim_name:, error:) ->
      ClaimDecodingError(claim_name:, error:)
    core.InvalidAudience(expected:, actual:) ->
      InvalidAudience(expected:, actual:)
    core.InvalidCustomClaim(claim_name:) -> InvalidCustomClaim(claim_name:)
    core.InvalidHeaderEncoding -> InvalidHeaderEncoding
    core.InvalidHeaderJson(error) -> InvalidHeaderJson(error)
    core.InvalidId(expected:, actual:) -> InvalidId(expected:, actual:)
    core.InvalidIssuer(expected:, actual:) -> InvalidIssuer(expected:, actual:)
    core.InvalidPayloadEncoding -> InvalidPayloadEncoding
    core.InvalidPayloadJson(error) -> InvalidPayloadJson(error)
    core.InvalidSignature -> InvalidSignature
    core.InvalidSignatureEncoding -> InvalidSignatureEncoding
    core.InvalidSubject(expected:, actual:) ->
      InvalidSubject(expected:, actual:)
    core.MalformedToken -> MalformedToken
    core.MissingClaim(claim_name:) -> MissingClaim(claim_name:)
    core.NoMatchingKey -> NoMatchingKey
    core.PayloadDecodingError(error) -> PayloadDecodingError(error)
    core.TokenExpired(expired_at:) -> TokenExpired(expired_at:)
    core.TokenNotYetValid(not_before:) -> TokenNotYetValid(not_before:)
  }
}
