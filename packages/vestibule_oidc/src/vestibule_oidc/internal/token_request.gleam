import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import vestibule/config
import vestibule/error.{type AuthError}

const client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

pub fn authorization_code(
  client_config: config.ClientConfig,
  code code: String,
  redirect_uri redirect_uri: String,
  code_verifier code_verifier: Option(String),
) -> Result(List(#(String, String)), AuthError(e)) {
  use authentication_parameters <- result.try(client_authentication_parameters(
    client_config,
  ))
  let base_parameters =
    [
      #("grant_type", "authorization_code"),
      #("code", code),
      #("redirect_uri", redirect_uri),
      #("client_id", config.client_id(client_config)),
    ]
    |> list.append(authentication_parameters)

  case code_verifier {
    Some(verifier) ->
      Ok(list.append(base_parameters, [#("code_verifier", verifier)]))
    None -> Ok(base_parameters)
  }
}

pub fn refresh(
  client_config: config.ClientConfig,
  refresh_token refresh_token: String,
) -> Result(List(#(String, String)), AuthError(e)) {
  use authentication_parameters <- result.try(client_authentication_parameters(
    client_config,
  ))
  Ok([
    #("grant_type", "refresh_token"),
    #("refresh_token", refresh_token),
    #("client_id", config.client_id(client_config)),
    ..authentication_parameters
  ])
}

pub fn client_authentication_parameters(
  client_config: config.ClientConfig,
) -> Result(List(#(String, String)), AuthError(e)) {
  case config.client_auth_kind(config.client_auth(client_config)) {
    config.ClientSecretAuth -> {
      use secret <- result.try(config.client_secret(client_config))
      Ok([#("client_secret", secret)])
    }
    config.PublicClientAuth -> Ok([])
    config.ClientAssertionAuth -> {
      use assertion <- result.try(config.client_assertion(client_config))
      Ok([
        #("client_assertion_type", client_assertion_type),
        #("client_assertion", assertion),
      ])
    }
  }
}
