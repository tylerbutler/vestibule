import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/string
import gleeunit/should
import kryptos/ec
import vestibule_apple
import vestibule_apple/jwt_signing

const p256_order = <<
  0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9,
  0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
>>

pub fn build_client_secret_round_trips_es256_test() -> Nil {
  let #(private_key, public_key) = jwt_signing.generate_es256_key_pair()
  let assert Ok(token) =
    vestibule_apple.build_client_secret(
      team_id: "TEAMID1234",
      client_id: "com.example.demo",
      key_id: "KEYID12345",
      p8_pem: private_key,
      ttl: 3600,
    )
  let assert [header, claims, signature] = string.split(token, on: ".")
  let assert Ok(signature_bits) = bit_array.base64_url_decode(signature)
  bit_array.byte_size(signature_bits) |> should.equal(64)

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
  jwt_signing.verify_es256(token, public_key) |> should.be_true()
  jwt_signing.verify_es256(
    jwt_signing.with_algorithm(token, "ES384"),
    public_key,
  )
  |> should.be_false()
  jwt_signing.verify_es256(token <> "A", public_key) |> should.be_false()
  let #(_, other_public_key) = jwt_signing.generate_es256_key_pair()
  jwt_signing.verify_es256(token, other_public_key) |> should.be_false()
}

pub fn build_client_secret_rejects_invalid_inputs_test() -> Nil {
  let #(private_key, _) = jwt_signing.generate_es256_key_pair()

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

pub fn build_client_secret_rejects_non_p256_keys_test() -> Nil {
  list.each([ec.P384, ec.P521, ec.Secp256k1], fn(curve) {
    let #(private_key, _) = ec.generate_key_pair(curve)
    let assert Ok(pem) = ec.to_pem(private_key)
    build("TEAMID1234", "com.example.demo", "KEYID12345", pem, 3600)
    |> should.equal(Error(vestibule_apple.InvalidPrivateKey))
  })
}

pub fn build_client_secret_rejects_multiple_or_public_keys_test() -> Nil {
  let #(private_key, public_key) = jwt_signing.generate_es256_key_pair()
  build(
    "TEAMID1234",
    "com.example.demo",
    "KEYID12345",
    private_key <> private_key,
    3600,
  )
  |> should.equal(Error(vestibule_apple.InvalidPrivateKey))
  let assert Ok(public_pem) = ec.public_key_to_pem(public_key)
  build("TEAMID1234", "com.example.demo", "KEYID12345", public_pem, 3600)
  |> should.equal(Error(vestibule_apple.InvalidPrivateKey))
}

pub fn build_client_secret_rejects_invalid_private_scalars_test() -> Nil {
  list.each(
    [<<0:size(256)>>, <<-1:size(256)>>, p256_order, <<>>, <<1:size(264)>>],
    fn(scalar) {
      let pem = scalar_pem(scalar)
      let assert Ok(_) = ec.from_pem(pem)
      build("TEAMID1234", "com.example.demo", "KEYID12345", pem, 3600)
      |> should.equal(Error(vestibule_apple.InvalidPrivateKey))
    },
  )
}

pub fn build_client_secret_accepts_key_without_public_component_test() -> Nil {
  let assert <<prefix:bytes-size(31), last_byte>> = p256_order
  let maximum_scalar = <<prefix:bits, { last_byte - 1 }>>
  list.each([<<1:size(256)>>, maximum_scalar], fn(scalar) {
    let assert Ok(#(_, public_key)) = ec.from_bytes(ec.P256, scalar)
    let assert Ok(token) =
      build(
        "TEAMID1234",
        "com.example.demo",
        "KEYID12345",
        scalar_pem(scalar),
        3600,
      )
    jwt_signing.verify_es256(token, public_key) |> should.be_true()
  })
}

pub fn build_client_secret_rejects_non_ec_curve_oids_test() -> Nil {
  list.each([110, 111, 112, 113], fn(oid) {
    let der = <<
      0x30, 0x3C, 0x02, 0x01, 0x00, 0x30, 0x0E, 0x06, 0x07, 0x2A, 0x86, 0x48,
      0xCE, 0x3D, 0x02, 0x01, 0x06, 0x03, 0x2B, 0x65, oid, 0x04, 0x27, 0x30,
      0x25, 0x02, 0x01, 0x01, 0x04, 0x20, 1:size(256),
    >>
    let pem = pem_from_der(der)
    let assert Ok(_) = ec.from_pem(pem)
    build("TEAMID1234", "com.example.demo", "KEYID12345", pem, 3600)
    |> should.equal(Error(vestibule_apple.InvalidPrivateKey))
  })
}

fn scalar_pem(scalar: BitArray) -> String {
  let size = bit_array.byte_size(scalar)
  let outer_size = 0x21 + size
  let octet_size = 0x07 + size
  let sequence_size = 0x05 + size
  let der = <<
    0x30, outer_size, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
    0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
    0x07, 0x04, octet_size, 0x30, sequence_size, 0x02, 0x01, 0x01, 0x04, size,
    scalar:bits,
  >>
  pem_from_der(der)
}

fn pem_from_der(der: BitArray) -> String {
  "-----BEGIN PRIVATE KEY-----\n"
  <> bit_array.base64_encode(der, True)
  <> "\n-----END PRIVATE KEY-----\n"
}

fn build(
  team_id: String,
  client_id: String,
  key_id: String,
  private_key: String,
  ttl: Int,
) -> Result(String, vestibule_apple.ClientSecretError) {
  vestibule_apple.build_client_secret(
    team_id:,
    client_id:,
    key_id:,
    p8_pem: private_key,
    ttl:,
  )
}
