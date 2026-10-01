//// Shared OpenID Connect ID-token verification.
////
//// This module verifies RS256 signatures and the identity claims used by
//// OIDC provider strategies. It does not fetch keys or retain tokens.

import gleam/bit_array
import gleam/dict
import gleam/dynamic/decode.{type Decoder}
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import ywt
import ywt/claim
import ywt/verify_key.{type VerifyKey}

/// A validated set of RS256 RSA signing keys.
pub opaque type Jwks {
  Jwks(keys: List(VerifyKey))
}

type RawJwk {
  RawJwk(
    key_type: String,
    key_id: Option(String),
    algorithm: Option(String),
    usage: String,
    modulus: Option(String),
    exponent: Option(String),
  )
}

/// Claims from a verified OIDC ID token.
pub opaque type VerifiedIdToken {
  VerifiedIdToken(
    subject: String,
    audiences: List(String),
    authorized_party: Option(String),
    nonce: Option(String),
  )
}

/// A token-free ID-token verification failure.
pub type VerificationError {
  InvalidJwks
  MalformedToken
  UnsupportedAlgorithm
  UnknownKey
  InvalidSignature
  InvalidIssuer
  InvalidAudience
  InvalidAuthorizedParty
  Expired
  NotYetValid
  InvalidIssuedAt
  InvalidNonce
  MissingClaim(name: String)
  InvalidClaim(name: String)
}

/// Parse a JWKS document, retaining only RSA signing keys pinned to RS256.
///
/// Vestibule limits the document to 16 keys, accepts only RSA signing keys
/// whose `alg` is absent or `RS256`, and requires unique non-empty key IDs when
/// the set contains multiple eligible keys.
///
/// RSA integer decoding and signature verification are delegated to `ywt` so
/// Vestibule does not maintain cryptographic key parsing. `ywt` validates the
/// JWK encoding, but it does not enforce a minimum or maximum RSA modulus size
/// or restrict the public exponent. Applications that require those key-strength
/// policies must validate the provider JWKS separately.
pub fn parse_jwks(body: String) -> Result(Jwks, VerificationError) {
  let decoder = {
    use keys <- decode.field("keys", decode.list(jwk_decoder()))
    decode.success(keys)
  }
  use raw_keys <- result.try(
    json.parse(body, decoder)
    |> result.replace_error(InvalidJwks),
  )
  case list.length(raw_keys) <= 16 {
    False -> Error(InvalidJwks)
    True -> {
      let eligible_keys = list.filter(raw_keys, is_eligible_jwk)
      case eligible_keys {
        [] -> Error(InvalidJwks)
        [_, ..] -> {
          use Nil <- result.try(validate_key_ids(eligible_keys))
          use keys <- result.try(
            list.try_map(eligible_keys, parse_jwk)
            |> result.replace_error(InvalidJwks),
          )
          Ok(Jwks(keys))
        }
      }
    }
  }
}

/// Verify an RS256 ID token and validate its OIDC identity claims.
///
/// `expected_nonce` can be `None` when the callback layer will compare the
/// nonce from this exact verified token before it accepts the identity.
/// Provider implementations should otherwise pass the nonce stored for the
/// authorization request.
pub fn verify_rs256(
  token token: String,
  using jwks: Jwks,
  issuer issuer: String,
  audience audience: String,
  expected_nonce expected_nonce: Option(String),
) -> Result(VerifiedIdToken, VerificationError) {
  use Nil <- result.try(validate_rs256_header(token))
  let leeway = duration.seconds(60)
  let claims = [
    claim.issuer(issuer, []),
    claim.custom(
      name: "aud",
      value: True,
      encode: json.bool,
      decoder: audience_match_decoder(audience),
    ),
    claim.expires_at(max_age: duration.hours(1), leeway: leeway),
    claim.not_before(timestamp.system_time(), leeway: leeway)
      |> claim.optional,
    claim.custom(
      name: "iat",
      value: True,
      encode: json.bool,
      decoder: issued_at_decoder(leeway),
    )
      |> claim.optional,
    ..nonce_claim(expected_nonce)
  ]
  use verified <- result.try(
    ywt.decode(
      jwt: token,
      using: verified_token_decoder(),
      claims: claims,
      keys: jwks.keys,
    )
    |> result.map_error(map_ywt_error),
  )
  use _ <- result.try(validate_verified_claims(verified, audience))
  Ok(verified)
}

/// Return the verified subject.
pub fn subject(token: VerifiedIdToken) -> String {
  token.subject
}

/// Return the verified audiences.
pub fn audiences(token: VerifiedIdToken) -> List(String) {
  token.audiences
}

/// Return the verified authorized party.
pub fn authorized_party(token: VerifiedIdToken) -> Option(String) {
  token.authorized_party
}

/// Return the verified nonce.
pub fn nonce(token: VerifiedIdToken) -> Option(String) {
  token.nonce
}

/// Return a short token-free description suitable for an authentication error.
pub fn error_message(error: VerificationError) -> String {
  case error {
    InvalidJwks -> "The provider JWKS is invalid"
    MalformedToken -> "The ID token is malformed"
    UnsupportedAlgorithm -> "The ID token does not use RS256"
    UnknownKey -> "The ID token signing key is unknown"
    InvalidSignature -> "The ID token signature is invalid"
    InvalidIssuer -> "The ID token issuer is invalid"
    InvalidAudience -> "The ID token audience is invalid"
    InvalidAuthorizedParty -> "The ID token authorized party is invalid"
    Expired -> "The ID token has expired"
    NotYetValid -> "The ID token is not yet valid"
    InvalidIssuedAt -> "The ID token issued-at time is invalid"
    InvalidNonce -> "The ID token nonce is invalid"
    MissingClaim(name) -> "The ID token is missing the " <> name <> " claim"
    InvalidClaim(name) -> "The ID token " <> name <> " claim is invalid"
  }
}

fn jwk_decoder() -> Decoder(RawJwk) {
  use key_type <- decode.field("kty", decode.string)
  use key_id <- decode.optional_field(
    "kid",
    None,
    decode.optional(decode.string),
  )
  use algorithm <- decode.optional_field(
    "alg",
    None,
    decode.optional(decode.string),
  )
  use usage <- decode.optional_field("use", "sig", decode.string)
  use modulus <- decode.optional_field(
    "n",
    None,
    decode.optional(decode.string),
  )
  use exponent <- decode.optional_field(
    "e",
    None,
    decode.optional(decode.string),
  )
  decode.success(RawJwk(
    key_type: key_type,
    key_id: key_id,
    algorithm: algorithm,
    usage: usage,
    modulus: modulus,
    exponent: exponent,
  ))
}

fn parse_jwk(raw: RawJwk) -> Result(VerifyKey, Nil) {
  case raw.modulus, raw.exponent {
    Some(modulus), Some(exponent) -> {
      // Keep RSA integer parsing inside ywt rather than duplicating crypto code.
      let fields = [
        #("kty", json.string("RSA")),
        #("alg", json.string("RS256")),
        #("n", json.string(modulus)),
        #("e", json.string(exponent)),
      ]
      let fields = case raw.key_id {
        Some(key_id) -> [#("kid", json.string(key_id)), ..fields]
        None -> fields
      }
      json.object(fields)
      |> json.to_string()
      |> json.parse(verify_key.decoder())
      |> result.replace_error(Nil)
    }
    _, _ -> Error(Nil)
  }
}

fn is_eligible_jwk(raw: RawJwk) -> Bool {
  case raw.key_type, raw.algorithm, raw.usage {
    "RSA", None, "sig" | "RSA", Some("RS256"), "sig" -> True
    _, _, _ -> False
  }
}

fn validate_key_ids(keys: List(RawJwk)) -> Result(Nil, VerificationError) {
  case keys {
    [_] -> Ok(Nil)
    [_, _, ..] -> {
      use ids <- result.try(
        list.try_map(keys, key_id)
        |> result.replace_error(InvalidJwks),
      )
      let unique = dict.from_list(list.map(ids, fn(id) { #(id, Nil) }))
      case dict.size(unique) == list.length(ids) {
        True -> Ok(Nil)
        False -> Error(InvalidJwks)
      }
    }
    [] -> Error(InvalidJwks)
  }
}

fn key_id(key: RawJwk) -> Result(String, Nil) {
  case key.key_id {
    Some(id) ->
      case string.trim(id) {
        "" -> Error(Nil)
        _ -> Ok(id)
      }
    None -> Error(Nil)
  }
}

fn validate_rs256_header(token: String) -> Result(Nil, VerificationError) {
  use raw_header <- result.try(case string.split(token, on: ".") {
    [header, _, _] -> Ok(header)
    _ -> Error(MalformedToken)
  })
  use header_bits <- result.try(
    bit_array.base64_url_decode(raw_header)
    |> result.replace_error(MalformedToken),
  )
  let decoder = {
    use algorithm <- decode.field("alg", decode.string)
    decode.success(algorithm)
  }
  case json.parse_bits(header_bits, decoder) {
    Ok("RS256") -> Ok(Nil)
    Ok(_) -> Error(UnsupportedAlgorithm)
    Error(_) -> Error(MalformedToken)
  }
}

fn nonce_claim(expected_nonce: Option(String)) -> List(claim.Claim) {
  case expected_nonce {
    Some(expected) -> [
      claim.custom(
        name: "nonce",
        value: expected,
        encode: json.string,
        decoder: decode.string,
      ),
    ]
    None -> []
  }
}

fn audience_decoder() -> Decoder(List(String)) {
  decode.one_of(decode.string |> decode.map(fn(value) { [value] }), or: [
    decode.list(decode.string),
  ])
}

fn audience_match_decoder(expected: String) -> Decoder(Bool) {
  audience_decoder()
  |> decode.map(list.contains(_, expected))
}

fn issued_at_decoder(leeway: duration.Duration) -> Decoder(Bool) {
  decode.int
  |> decode.map(fn(issued_at) {
    let latest =
      timestamp.system_time()
      |> timestamp.add(leeway)
      |> timestamp.to_unix_seconds_and_nanoseconds()
    issued_at <= latest.0
  })
}

fn verified_token_decoder() -> Decoder(VerifiedIdToken) {
  use subject <- decode.field("sub", decode.string)
  use audiences <- decode.field("aud", audience_decoder())
  use authorized_party <- decode.optional_field(
    "azp",
    None,
    decode.optional(decode.string),
  )
  use nonce <- decode.optional_field(
    "nonce",
    None,
    decode.optional(decode.string),
  )
  decode.success(VerifiedIdToken(
    subject: subject,
    audiences: audiences,
    authorized_party: authorized_party,
    nonce: nonce,
  ))
}

fn validate_verified_claims(
  token: VerifiedIdToken,
  audience: String,
) -> Result(Nil, VerificationError) {
  use Nil <- result.try(case string.trim(token.subject) {
    "" -> Error(InvalidClaim("sub"))
    _ -> Ok(Nil)
  })
  case list.length(token.audiences), token.authorized_party {
    count, None if count > 1 -> Error(MissingClaim("azp"))
    _, Some(authorized_party) if authorized_party != audience ->
      Error(InvalidAuthorizedParty)
    _, _ -> Ok(Nil)
  }
}

fn map_ywt_error(error: ywt.ParseError) -> VerificationError {
  case error {
    ywt.NoMatchingKey -> UnknownKey
    ywt.InvalidSignature -> InvalidSignature
    ywt.TokenExpired(..) -> Expired
    ywt.TokenNotYetValid(..) -> NotYetValid
    ywt.InvalidIssuer(..) -> InvalidIssuer
    ywt.InvalidAudience(..) -> InvalidAudience
    ywt.MissingClaim(name) -> MissingClaim(name)
    ywt.InvalidCustomClaim("nonce") -> InvalidNonce
    ywt.InvalidCustomClaim("iat") -> InvalidIssuedAt
    ywt.InvalidCustomClaim("aud") -> InvalidAudience
    ywt.InvalidCustomClaim(name) -> InvalidClaim(name)
    ywt.ClaimDecodingError("iat", ..) -> InvalidIssuedAt
    ywt.ClaimDecodingError("aud", ..) -> InvalidAudience
    ywt.ClaimDecodingError(name, ..) -> InvalidClaim(name)
    ywt.MalformedToken
    | ywt.InvalidHeaderEncoding
    | ywt.InvalidPayloadEncoding
    | ywt.InvalidSignatureEncoding
    | ywt.InvalidHeaderJson(..)
    | ywt.InvalidPayloadJson(..)
    | ywt.PayloadDecodingError(..) -> MalformedToken
    ywt.InvalidSubject(..) -> InvalidClaim("sub")
    ywt.InvalidId(..) -> InvalidClaim("jti")
  }
}
