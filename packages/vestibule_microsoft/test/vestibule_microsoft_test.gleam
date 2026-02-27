import gleam/option.{None, Some}
import gleam/string as gleam_string
import startest
import startest/expect
import vestibule/config
import vestibule/credentials.{Credentials}
import vestibule_microsoft

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn parse_token_response_success_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read profile openid email\",\"expires_in\":3736,\"ext_expires_in\":3736,\"access_token\":\"eyJ0eXAi_test_token\",\"refresh_token\":\"AwABAAAA_test_refresh\"}"
  vestibule_microsoft.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "eyJ0eXAi_test_token",
      refresh_token: Some("AwABAAAA_test_refresh"),
      token_type: "Bearer",
      expires_at: Some(3736),
      scopes: ["User.Read", "profile", "openid", "email"],
    ),
  )
}

pub fn parse_token_response_without_refresh_token_test() {
  let body =
    "{\"token_type\":\"Bearer\",\"scope\":\"User.Read\",\"expires_in\":3600,\"access_token\":\"test_token\"}"
  vestibule_microsoft.parse_token_response(body)
  |> expect.to_be_ok()
  |> expect.to_equal(
    Credentials(
      token: "test_token",
      refresh_token: None,
      token_type: "Bearer",
      expires_at: Some(3600),
      scopes: ["User.Read"],
    ),
  )
}

pub fn parse_token_response_error_test() {
  let body =
    "{\"error\":\"invalid_grant\",\"error_description\":\"AADSTS70000: The provided value for the input parameter 'code' is not valid.\"}"
  let _ =
    vestibule_microsoft.parse_token_response(body)
    |> expect.to_be_error()
  Nil
}

pub fn parse_user_response_full_test() {
  let body =
    "{\"id\":\"87d349ed-44d7-43e1-9a83-5f2406dee5bd\",\"displayName\":\"Adele Vance\",\"mail\":\"AdeleV@contoso.com\",\"userPrincipalName\":\"AdeleV@contoso.com\",\"jobTitle\":\"Retail Manager\"}"
  let assert Ok(#(uid, info)) = vestibule_microsoft.parse_user_response(body)
  uid |> expect.to_equal("87d349ed-44d7-43e1-9a83-5f2406dee5bd")
  info.name |> expect.to_equal(Some("Adele Vance"))
  info.email |> expect.to_equal(Some("AdeleV@contoso.com"))
  info.nickname |> expect.to_equal(Some("AdeleV@contoso.com"))
  info.description |> expect.to_equal(Some("Retail Manager"))
  // Gravatar URL from SHA-256 of lowercase email
  let assert Some(image_url) = info.image
  gleam_string.starts_with(image_url, "https://www.gravatar.com/avatar/")
  |> expect.to_be_true()
}

pub fn parse_user_response_minimal_test() {
  let body = "{\"id\":\"abc-123\",\"userPrincipalName\":\"user@example.com\"}"
  let assert Ok(#(uid, info)) = vestibule_microsoft.parse_user_response(body)
  uid |> expect.to_equal("abc-123")
  info.name |> expect.to_equal(None)
  // UPN is not a verified email, so email should be None
  info.email |> expect.to_equal(None)
  info.nickname |> expect.to_equal(Some("user@example.com"))
  info.description |> expect.to_equal(None)
  // No gravatar when no verified email
  info.image |> expect.to_equal(None)
}

pub fn parse_user_response_mail_preferred_over_upn_test() {
  let body =
    "{\"id\":\"abc\",\"mail\":\"real@example.com\",\"userPrincipalName\":\"upn@example.com\"}"
  let assert Ok(#(_uid, info)) = vestibule_microsoft.parse_user_response(body)
  info.email |> expect.to_equal(Some("real@example.com"))
}

pub fn authorize_url_invalid_redirect_uri_returns_error_test() {
  let strat = vestibule_microsoft.strategy()
  let conf = config.new("client-id", "secret", "not a uri")
  strat.authorize_url(conf, ["User.Read"], "state")
  |> expect.to_be_error()
}
