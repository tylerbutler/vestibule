import gleam/list
import gleam/option.{type Option, None, Some}
import vestibule/config

const client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

pub fn authorization_code(
  client_config: config.ClientConfig,
  code code: String,
  redirect_uri redirect_uri: String,
  code_verifier code_verifier: Option(String),
) -> List(#(String, String)) {
  let base_parameters =
    [
      #("grant_type", "authorization_code"),
      #("code", code),
      #("redirect_uri", redirect_uri),
      #("client_id", config.client_id(client_config)),
    ]
    |> list.append(client_authentication_parameters(client_config))

  case code_verifier {
    Some(verifier) ->
      list.append(base_parameters, [#("code_verifier", verifier)])
    None -> base_parameters
  }
}

pub fn refresh(
  client_config: config.ClientConfig,
  refresh_token refresh_token: String,
) -> List(#(String, String)) {
  [
    #("grant_type", "refresh_token"),
    #("refresh_token", refresh_token),
    #("client_id", config.client_id(client_config)),
  ]
  |> list.append(client_authentication_parameters(client_config))
}

pub fn client_authentication_parameters(
  client_config: config.ClientConfig,
) -> List(#(String, String)) {
  case config.client_auth(client_config) {
    config.ClientSecret(secret) -> [#("client_secret", secret)]
    config.PublicClient -> []
    config.ClientAssertion(assertion) -> [
      #("client_assertion_type", client_assertion_type),
      #("client_assertion", assertion),
    ]
  }
}
