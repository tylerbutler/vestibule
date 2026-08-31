//// RSA JWT signing helpers and static test keys.
////
//// The fixed 2048-bit key is test-only. It lets the suite exercise the same
//// RS256 JWK and PKCS#1 v1.5 path used by Apple without depending on runtime
//// key generation.

import gleam/bit_array
import gleam/json
import gleam/string
import ywt/claim.{type Claim}
import ywt/internal/jwt
import ywt/sign_key.{type SignKey}
import ywt/verify_key.{type VerifyKey}

const private_jwk = "{\"kty\":\"RSA\",\"kid\":\"apple-test-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"7YayUS1XhvLBTpAUpYtLbqjfT7er5h2X1C8AMS6p4QZFGUy7bF7niXRZ6ljVFLEmqctz_yRDP56rcnZoAt5DBd7FNdY-UtgwjvNnvCT3nxRSagjr43a1J0dXgzBiUNFXOkvsYfCFqgvRP8MiY_UcxUFPdQSTukEOhS7pCeK3ZGYFaq7Yk2E1qkg8YaQJ5h0JyLGC3qzNIKEi_J7ZH4D7mXxZ-oqeyQiAJS1YDzeWGdk6OINHHdkw-4DjdpCteQDVaZK_MUwWqQArazXIjhHLSBOoShIEDaR62trJ7VRindA56AtuaJTq2gYnSbNgvENDPag6NVRRaOYdoGjVJokhbQ\",\"e\":\"AQAB\",\"d\":\"GeAwIdbKL7nXZDse_K_RjmMYPMN6Fw4HQcbDAxidyhVYRrrMujAWkitaNkTqJaBs4Vd4MgXdy5r5-3S5vQJAk-2iV0yZKoZBt_j9RopSbYKVvdZt-DAw6PAFMRX-x-YeVgv6WusMbKtv5r3Xy8LimPyV7t4KR-KZddnX6ktIBkg_MpAqeyThjeIEg5dNT7f9f2T-CUzENQ1hipNR4QDxrhuuDgCMMB2mQ1x7DPW2xrYbq9hagDofWDQuPQOqvcINzOaFRxokGLmfcYbspfShP3QurIwG2YPnSUfHA_qfxEsavzbecvYbpImgPzw3-9GcFaeQpZA8YwPhWfVL57EUIQ\",\"p\":\"_qYc4WMhvRjy3RCWEEqdPP0TbRhftRAg_Ktwet6SiGb2V8prKrjhkZozRNMNwUG5MMO1p2mZOiHmlCRSbuhIBlyR1qOiRWcnSWs-s9uitFM9LYG-M7ACLPqSOFlTZVOnIHfcnzv6rsMLWHRXy3sEKJHA41IBQeDFDgKixH4A_RE\",\"q\":\"7slTe8IQlL3iD3Wimu05Xo7AOSekQwJxCFw64kRYHRE8Q1ntpDHvYD6cZvsXdtkiHu-qdCvGNbIEEluNJ_pq1gI3kNfWDsGrRFBg_uZ89X-7WW1sTtA9yWDhvRA0_a_kG_2Uh4ChhyIILB6421XzUv4-WmpP0UHgQSiIzvynDp0\",\"dp\":\"xoaQm3Kief76UDg_FcJl5YdT3siSzOEfJn0tuszMpoTG5tiLRgpO6SmzcKOt5I2tqAPcGgFskPKfBb1vesGibTs8A38c4kiySz3N64B-z2DZoCG3PCqq94_98OpK5wMZl2l62bV0EU1EChjh3WQxcMN5AoALNOXcGrkZVmD5ulE\",\"dq\":\"ldrhOpTC5SX5few8XPAthcselX_sVWVt3GpNRfzQM4XChR4lxlrUOFlyvCouQpboE_Qiy_9AyCfs6DxubL16WM5RYuQhYWdnfVrYVH__we4kfG3wf9GuRPg5Evbd2quNA4fzs8olFPJloJKzPmtFZjtKlGGNr-yguSOgIA5tJP0\",\"qi\":\"NYoUJSG2ugJuf6T4bsg521zZsDngtVgAUXvQNMMtE88mrq8uHdWgdQr70jBomGdvTBOOYvVhyZaLV7ye6QpRTZOYh57G_T6hL-5w5OoW2Y0-eGu2QEElWusz8EyMvfhtlrs6R05_aXcEsxrnReCr2VY69QB8WgJaUPFG-EWBXjY\"}"

const other_public_jwks = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"apple-test-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"vxhq3KlIYLAAfTQNwrw4YmSX-LGxSMmp_IlCj5VHX7nqd4HBkHOup4ANFLBNqsZm4mB3f2xdRlaL5Yeo9J5wlZ3X6WszacYPd7nC46CjA8r_-SxqkJ_tYlA7nk_4U9KQg4aI-FnU8y4l0L7eDnxeU1zLE2lmZgiLyz3AHLXmgxWWbalatoBWfPkB_hR0_PlicO2F9gYqtGMonwISadvUo5DgNN5UuXJ4youKygiJ7xQ-Q27o8y1WVIPPqlnoPn6_9RwxlhkOQwJqi3xVrnE0x7VPonX-bG8CWmd7tWyprt_-1qkJ7u-lzB86yR5F8Dhu_ePhCc_PsHvuWpCdRN6gQQ\",\"e\":\"AQAB\"}]}"

/// Create an RS256-signed JWT.
pub fn encode(
  payload payload: List(#(String, json.Json)),
  claims claims: List(Claim),
  key key: SignKey,
) -> String {
  let sign = fn(message, key, next) { next(sign_bits(message, key)) }
  jwt.encode(payload:, claims:, key:, sign:)
}

/// The static RSA signing key used by Apple ID-token tests.
pub fn test_key() -> SignKey {
  let assert Ok(key) = json.parse(private_jwk, sign_key.decoder())
  key
}

/// The corresponding RS256 public verification key.
pub fn test_verify_key() -> VerifyKey {
  verify_key.derived(test_key())
}

/// A different RSA public key with the same algorithm.
pub fn other_key_jwks() -> String {
  other_public_jwks
}

/// Rewrite only the protected-header algorithm, invalidating the signature.
pub fn with_algorithm(token: String, algorithm: String) -> String {
  let assert [_, payload, signature] = string.split(token, on: ".")
  let header =
    json.object([
      #("alg", json.string(algorithm)),
      #("kid", json.string("apple-test-key")),
    ])
    |> json.to_string()
    |> bit_array.from_string()
    |> bit_array.base64_url_encode(False)
  header <> "." <> payload <> "." <> signature
}

fn sign_bits(message: BitArray, key: SignKey) -> BitArray {
  sign_key.match(
    key,
    fn(_, _, _, _, _) { <<>> },
    fn(_, _, _, _, _, _) { do_sign(message, key) },
    fn(_, _, _, _, _, _, _, _, _, _, _, _) { do_sign(message, key) },
    fn(_, _, _) { <<>> },
  )
}

@external(erlang, "vestibule_apple_jwt_ffi", "sign")
fn do_sign(message: BitArray, key: SignKey) -> BitArray
