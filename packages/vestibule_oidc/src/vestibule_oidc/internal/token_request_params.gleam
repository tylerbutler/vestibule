import gleam/list
import gleam/option.{type Option, None, Some}
import vestibule/config

const client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

pub fn authorization_code(
  cfg: config.ClientConfig,
  code code: String,
  redirect_uri redirect_uri: String,
  code_verifier code_verifier: Option(String),
) -> List(#(String, String)) {
  let base_params =
    [
      #("grant_type", "authorization_code"),
      #("code", code),
      #("redirect_uri", redirect_uri),
      #("client_id", config.client_id(cfg)),
    ]
    |> list.append(client_auth_params(cfg))

  case code_verifier {
    Some(verifier) -> list.append(base_params, [#("code_verifier", verifier)])
    None -> base_params
  }
}

pub fn refresh(
  cfg: config.ClientConfig,
  refresh_token refresh_token: String,
) -> List(#(String, String)) {
  [
    #("grant_type", "refresh_token"),
    #("refresh_token", refresh_token),
    #("client_id", config.client_id(cfg)),
  ]
  |> list.append(client_auth_params(cfg))
}

pub fn client_auth_params(cfg: config.ClientConfig) -> List(#(String, String)) {
  case config.client_auth(cfg) {
    config.ClientSecret(secret) -> [#("client_secret", secret)]
    config.PublicClient -> []
    config.ClientAssertion(assertion) -> [
      #("client_assertion_type", client_assertion_type),
      #("client_assertion", assertion),
    ]
  }
}
