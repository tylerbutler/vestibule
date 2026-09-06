import gleam/json
import gleam/string
import ywt/claim.{type Claim}
import ywt/internal/jwt
import ywt/sign_key.{type SignKey}

const private_jwk = "{\"kty\":\"RSA\",\"kid\":\"provider-test-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"7YayUS1XhvLBTpAUpYtLbqjfT7er5h2X1C8AMS6p4QZFGUy7bF7niXRZ6ljVFLEmqctz_yRDP56rcnZoAt5DBd7FNdY-UtgwjvNnvCT3nxRSagjr43a1J0dXgzBiUNFXOkvsYfCFqgvRP8MiY_UcxUFPdQSTukEOhS7pCeK3ZGYFaq7Yk2E1qkg8YaQJ5h0JyLGC3qzNIKEi_J7ZH4D7mXxZ-oqeyQiAJS1YDzeWGdk6OINHHdkw-4DjdpCteQDVaZK_MUwWqQArazXIjhHLSBOoShIEDaR62trJ7VRindA56AtuaJTq2gYnSbNgvENDPag6NVRRaOYdoGjVJokhbQ\",\"e\":\"AQAB\",\"d\":\"GeAwIdbKL7nXZDse_K_RjmMYPMN6Fw4HQcbDAxidyhVYRrrMujAWkitaNkTqJaBs4Vd4MgXdy5r5-3S5vQJAk-2iV0yZKoZBt_j9RopSbYKVvdZt-DAw6PAFMRX-x-YeVgv6WusMbKtv5r3Xy8LimPyV7t4KR-KZddnX6ktIBkg_MpAqeyThjeIEg5dNT7f9f2T-CUzENQ1hipNR4QDxrhuuDgCMMB2mQ1x7DPW2xrYbq9hagDofWDQuPQOqvcINzOaFRxokGLmfcYbspfShP3QurIwG2YPnSUfHA_qfxEsavzbecvYbpImgPzw3-9GcFaeQpZA8YwPhWfVL57EUIQ\",\"p\":\"_qYc4WMhvRjy3RCWEEqdPP0TbRhftRAg_Ktwet6SiGb2V8prKrjhkZozRNMNwUG5MMO1p2mZOiHmlCRSbuhIBlyR1qOiRWcnSWs-s9uitFM9LYG-M7ACLPqSOFlTZVOnIHfcnzv6rsMLWHRXy3sEKJHA41IBQeDFDgKixH4A_RE\",\"q\":\"7slTe8IQlL3iD3Wimu05Xo7AOSekQwJxCFw64kRYHRE8Q1ntpDHvYD6cZvsXdtkiHu-qdCvGNbIEEluNJ_pq1gI3kNfWDsGrRFBg_uZ89X-7WW1sTtA9yWDhvRA0_a_kG_2Uh4ChhyIILB6421XzUv4-WmpP0UHgQSiIzvynDp0\",\"dp\":\"xoaQm3Kief76UDg_FcJl5YdT3siSzOEfJn0tuszMpoTG5tiLRgpO6SmzcKOt5I2tqAPcGgFskPKfBb1vesGibTs8A38c4kiySz3N64B-z2DZoCG3PCqq94_98OpK5wMZl2l62bV0EU1EChjh3WQxcMN5AoALNOXcGrkZVmD5ulE\",\"dq\":\"ldrhOpTC5SX5few8XPAthcselX_sVWVt3GpNRfzQM4XChR4lxlrUOFlyvCouQpboE_Qiy_9AyCfs6DxubL16WM5RYuQhYWdnfVrYVH__we4kfG3wf9GuRPg5Evbd2quNA4fzs8olFPJloJKzPmtFZjtKlGGNr-yguSOgIA5tJP0\",\"qi\":\"NYoUJSG2ugJuf6T4bsg521zZsDngtVgAUXvQNMMtE88mrq8uHdWgdQr70jBomGdvTBOOYvVhyZaLV7ye6QpRTZOYh57G_T6hL-5w5OoW2Y0-eGu2QEElWusz8EyMvfhtlrs6R05_aXcEsxrnReCr2VY69QB8WgJaUPFG-EWBXjY\"}"

const public_jwks = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"provider-test-key\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"7YayUS1XhvLBTpAUpYtLbqjfT7er5h2X1C8AMS6p4QZFGUy7bF7niXRZ6ljVFLEmqctz_yRDP56rcnZoAt5DBd7FNdY-UtgwjvNnvCT3nxRSagjr43a1J0dXgzBiUNFXOkvsYfCFqgvRP8MiY_UcxUFPdQSTukEOhS7pCeK3ZGYFaq7Yk2E1qkg8YaQJ5h0JyLGC3qzNIKEi_J7ZH4D7mXxZ-oqeyQiAJS1YDzeWGdk6OINHHdkw-4DjdpCteQDVaZK_MUwWqQArazXIjhHLSBOoShIEDaR62trJ7VRindA56AtuaJTq2gYnSbNgvENDPag6NVRRaOYdoGjVJokhbQ\",\"e\":\"AQAB\"}]}"

pub fn encode(
  payload: List(#(String, json.Json)),
  claims: List(Claim),
) -> String {
  let assert Ok(key) = json.parse(private_jwk, sign_key.decoder())
  jwt.encode(
    payload: payload,
    claims: claims,
    key: key,
    sign: fn(message, key, next) { next(sign(message, key)) },
  )
}

pub fn jwks() -> String {
  public_jwks
}

pub fn tamper_signature(token: String) -> String {
  let assert [header, payload, signature] = string.split(token, on: ".")
  let replacement = case string.starts_with(signature, "A") {
    True -> "B"
    False -> "A"
  }
  header
  <> "."
  <> payload
  <> "."
  <> replacement
  <> string.drop_start(signature, 1)
}

@external(erlang, "vestibule_microsoft_test_jwt_ffi", "sign")
fn sign(message: BitArray, key: SignKey) -> BitArray
