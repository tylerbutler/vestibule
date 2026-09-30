import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/string
import gleeunit/should
import vestibule_apple
import vestibule_apple/jwt_signing

pub fn build_client_secret_round_trips_es256_test() -> Nil {
  let private_key = jwt_signing.generate_es256_private_key()
  let assert Ok(token) =
    vestibule_apple.build_client_secret(
      team_id: "TEAMID1234",
      client_id: "com.example.demo",
      key_id: "KEYID12345",
      p8_pem: private_key,
      ttl: 3600,
    )
  let assert [header, claims, _] = string.split(token, on: ".")

  let assert Ok(header_bits) = bit_array.base64_url_decode(header)
  let assert Ok(#("ES256", "KEYID12345")) =
    json.parse_bits(header_bits, {
      use algorithm <- decode.field("alg", decode.string)
      use key_id <- decode.field("kid", decode.string)
      decode.success(#(algorithm, key_id))
    })
  let assert Ok(claim_bits) = bit_array.base64_url_decode(claims)
  let assert Ok(#(issuer, issued_at, expires_at, audience, subject)) =
    json.parse_bits(claim_bits, {
      use issuer <- decode.field("iss", decode.string)
      use issued_at <- decode.field("iat", decode.int)
      use expires_at <- decode.field("exp", decode.int)
      use audience <- decode.field("aud", decode.string)
      use subject <- decode.field("sub", decode.string)
      decode.success(#(issuer, issued_at, expires_at, audience, subject))
    })

  issuer |> should.equal("TEAMID1234")
  expires_at - issued_at |> should.equal(3600)
  audience |> should.equal("https://appleid.apple.com")
  subject |> should.equal("com.example.demo")
  jwt_signing.verify_es256(token, private_key) |> should.be_true()
}

pub fn build_client_secret_rejects_invalid_inputs_test() -> Nil {
  let private_key = jwt_signing.generate_es256_private_key()

  build("short", "com.example.demo", "KEYID12345", private_key, 3600)
  |> should.equal(Error(vestibule_apple.InvalidTeamId))
  build("TEAMID1234", "not valid", "KEYID12345", private_key, 3600)
  |> should.equal(Error(vestibule_apple.InvalidClientId))
  build("TEAMID1234", "com.example.demo", "short", private_key, 3600)
  |> should.equal(Error(vestibule_apple.InvalidKeyId))
  build("TEAMID1234", "com.example.demo", "KEYID12345", private_key, 0)
  |> should.equal(Error(vestibule_apple.InvalidTtl))
  build("TEAMID1234", "com.example.demo", "KEYID12345", private_key, 15_777_001)
  |> should.equal(Error(vestibule_apple.InvalidTtl))
  let assert Ok(_) =
    build(
      "TEAMID1234",
      "com.example.demo",
      "KEYID12345",
      private_key,
      15_777_000,
    )
  build("TEAMID1234", "com.example.demo", "KEYID12345", "not a PEM key", 3600)
  |> should.equal(Error(vestibule_apple.InvalidPrivateKey))
}

fn build(
  team_id: String,
  client_id: String,
  key_id: String,
  private_key: String,
  ttl: Int,
) {
  vestibule_apple.build_client_secret(
    team_id:,
    client_id:,
    key_id:,
    p8_pem: private_key,
    ttl:,
  )
}
