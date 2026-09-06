//// Shared OpenID Connect ID-token verification.
////
//// This module verifies RS256 signatures and the identity claims used by
//// OIDC provider strategies. It does not fetch keys or retain tokens.

import gleam/bit_array
import gleam/dict
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode.{type Decoder}
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import ywt/claim
import ywt/internal/core
import ywt/internal/jwt
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
    hosted_domain: Option(String),
    tenant_id: Option(String),
    object_id: Option(String),
    payload: dict.Dict(String, Dynamic),
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
pub fn parse_jwks(body: String) -> Result(Jwks, VerificationError) {
  let decoder = {
    use keys <- decode.field("keys", decode.list(jwk_decoder()))
    decode.success(keys)
  }
  case json.parse(body, decoder) {
    Ok([first, ..rest]) -> {
      let raw_keys = [first, ..rest]
      use Nil <- result.try(case list.length(raw_keys) > 16 {
        True -> Error(InvalidJwks)
        False -> Ok(Nil)
      })
      let eligible_keys = list.filter(raw_keys, is_eligible_jwk)
      use first <- result.try(
        list.first(eligible_keys)
        |> result.replace_error(InvalidJwks),
      )
      let eligible_keys = [first, ..list.drop(eligible_keys, 1)]
      use Nil <- result.try(validate_key_ids(eligible_keys))
      use keys <- result.try(
        list.try_map(eligible_keys, parse_jwk)
        |> result.replace_error(InvalidJwks),
      )
      Ok(Jwks(keys))
    }
    Ok([]) | Error(_) -> Error(InvalidJwks)
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
  let verify = fn(message, signature, key, next) {
    next(verify_bits(message, signature, key))
  }
  let resolve = result.map_error(_, map_ywt_error)
  use verified <- result.try(jwt.decode(
    jwt: token,
    using: verified_token_decoder(),
    claims: claims,
    keys: jwks.keys,
    verify: verify,
    resolve: resolve,
  ))
  use verified <- result.try(populate_provider_claims(verified))
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

/// Return Google's verified hosted-domain claim, when present.
pub fn hosted_domain(token: VerifiedIdToken) -> Option(String) {
  token.hosted_domain
}

/// Return Microsoft's verified tenant identifier claim, when present.
pub fn tenant_id(token: VerifiedIdToken) -> Option(String) {
  token.tenant_id
}

/// Return Microsoft's verified object identifier claim, when present.
pub fn object_id(token: VerifiedIdToken) -> Option(String) {
  token.object_id
}

/// Return an optional string claim from the verified payload.
///
/// This is useful for provider-specific claims such as Google's `hd` or
/// Microsoft's `tid`. A present non-string claim is rejected.
pub fn optional_string_claim(
  token: VerifiedIdToken,
  name: String,
) -> Result(Option(String), VerificationError) {
  case dict.get(token.payload, name) {
    Error(_) -> Ok(None)
    Ok(value) ->
      decode.run(value, decode.string)
      |> result.map(Some)
      |> result.map_error(fn(_) { InvalidClaim(name) })
  }
}

/// Return a required string claim from the verified payload.
pub fn string_claim(
  token: VerifiedIdToken,
  name: String,
) -> Result(String, VerificationError) {
  use value <- result.try(optional_string_claim(token, name))
  value
  |> option.to_result(MissingClaim(name))
}

/// Return an optional boolean claim from the verified payload.
pub fn optional_bool_claim(
  token: VerifiedIdToken,
  name: String,
) -> Result(Option(Bool), VerificationError) {
  case dict.get(token.payload, name) {
    Error(_) -> Ok(None)
    Ok(value) ->
      decode.run(value, decode.bool)
      |> result.map(Some)
      |> result.map_error(fn(_) { InvalidClaim(name) })
  }
}

/// Return a required boolean claim from the verified payload.
pub fn bool_claim(
  token: VerifiedIdToken,
  name: String,
) -> Result(Bool, VerificationError) {
  use value <- result.try(optional_bool_claim(token, name))
  value
  |> option.to_result(MissingClaim(name))
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

@external(erlang, "vestibule_oidc_jwt_ffi", "verify")
fn verify_bits(message: BitArray, signature: BitArray, key: VerifyKey) -> Bool

@external(erlang, "vestibule_oidc_jwt_ffi", "make_rsa_key")
fn make_rsa_key(
  key_id: Option(String),
  modulus: String,
  exponent: String,
) -> Result(VerifyKey, Nil)

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
    Some(modulus), Some(exponent) -> make_rsa_key(raw.key_id, modulus, exponent)
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
  decode.dict(decode.string, decode.dynamic)
  |> decode.then(fn(payload) {
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
      hosted_domain: None,
      tenant_id: None,
      object_id: None,
      payload: payload,
    ))
  })
}

fn populate_provider_claims(
  token: VerifiedIdToken,
) -> Result(VerifiedIdToken, VerificationError) {
  use hosted_domain <- result.try(optional_nonempty_string_claim(token, "hd"))
  use tenant_id <- result.try(optional_nonempty_string_claim(token, "tid"))
  use object_id <- result.try(optional_nonempty_string_claim(token, "oid"))
  Ok(
    VerifiedIdToken(
      ..token,
      hosted_domain: hosted_domain,
      tenant_id: tenant_id,
      object_id: object_id,
    ),
  )
}

fn optional_nonempty_string_claim(
  token: VerifiedIdToken,
  name: String,
) -> Result(Option(String), VerificationError) {
  use value <- result.try(optional_string_claim(token, name))
  case value {
    Some(value) ->
      case string.trim(value) {
        "" -> Error(InvalidClaim(name))
        _ -> Ok(Some(value))
      }
    None -> Ok(None)
  }
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

fn map_ywt_error(error: core.ParseError) -> VerificationError {
  case error {
    core.NoMatchingKey -> UnknownKey
    core.InvalidSignature -> InvalidSignature
    core.TokenExpired(..) -> Expired
    core.TokenNotYetValid(..) -> NotYetValid
    core.InvalidIssuer(..) -> InvalidIssuer
    core.InvalidAudience(..) -> InvalidAudience
    core.MissingClaim(name) -> MissingClaim(name)
    core.InvalidCustomClaim("nonce") -> InvalidNonce
    core.InvalidCustomClaim("iat") -> InvalidIssuedAt
    core.InvalidCustomClaim("aud") -> InvalidAudience
    core.InvalidCustomClaim(name) -> InvalidClaim(name)
    core.ClaimDecodingError("iat", ..) -> InvalidIssuedAt
    core.ClaimDecodingError("aud", ..) -> InvalidAudience
    core.ClaimDecodingError(name, ..) -> InvalidClaim(name)
    core.MalformedToken
    | core.InvalidHeaderEncoding
    | core.InvalidPayloadEncoding
    | core.InvalidSignatureEncoding
    | core.InvalidHeaderJson(..)
    | core.InvalidPayloadJson(..)
    | core.PayloadDecodingError(..) -> MalformedToken
    core.InvalidSubject(..) -> InvalidClaim("sub")
    core.InvalidId(..) -> InvalidClaim("jti")
  }
}
