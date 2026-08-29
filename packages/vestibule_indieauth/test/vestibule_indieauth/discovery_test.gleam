import gleam/option.{None, Some}
import startest
import startest/expect

import vestibule/error
import vestibule_indieauth/discovery.{DiscoveredEndpoints}

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

// === parse_metadata ===

pub fn parse_metadata_full_test() -> Nil {
  let json =
    "{
    \"issuer\": \"https://indieauth.example.com/\",
    \"authorization_endpoint\": \"https://indieauth.example.com/auth\",
    \"token_endpoint\": \"https://indieauth.example.com/token\",
    \"userinfo_endpoint\": \"https://indieauth.example.com/userinfo\",
    \"code_challenge_methods_supported\": [\"S256\"]
  }"

  let result = discovery.parse_metadata(json)
  let assert Ok(endpoints) = result

  endpoints.authorization_endpoint
  |> expect.to_equal("https://indieauth.example.com/auth")

  endpoints.token_endpoint
  |> expect.to_equal("https://indieauth.example.com/token")

  endpoints.issuer
  |> expect.to_equal(Some("https://indieauth.example.com/"))

  endpoints.userinfo_endpoint
  |> expect.to_equal(Some("https://indieauth.example.com/userinfo"))
}

pub fn parse_metadata_minimal_test() -> Nil {
  let json =
    "{
    \"authorization_endpoint\": \"https://example.com/auth\",
    \"token_endpoint\": \"https://example.com/token\"
  }"

  let result = discovery.parse_metadata(json)
  let assert Ok(endpoints) = result

  endpoints.authorization_endpoint
  |> expect.to_equal("https://example.com/auth")

  endpoints.token_endpoint
  |> expect.to_equal("https://example.com/token")

  endpoints.issuer
  |> expect.to_equal(None)

  endpoints.userinfo_endpoint
  |> expect.to_equal(None)
}

pub fn parse_metadata_missing_auth_endpoint_test() -> Nil {
  let json = "{ \"token_endpoint\": \"https://example.com/token\" }"

  let _ =
    discovery.parse_metadata(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_metadata_missing_token_endpoint_test() -> Nil {
  let json = "{ \"authorization_endpoint\": \"https://example.com/auth\" }"

  let _ =
    discovery.parse_metadata(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_metadata_invalid_json_test() -> Nil {
  let _ =
    discovery.parse_metadata("not json")
    |> expect.to_be_error()
  Nil
}

// === find_link_header_rel ===

pub fn find_link_header_basic_test() -> Nil {
  let headers = [
    #(
      "Link",
      "<https://indieauth.example.com/.well-known/oauth-authorization-server>; rel=\"indieauth-metadata\"",
    ),
  ]

  discovery.find_link_header_rel(headers, "indieauth-metadata")
  |> expect.to_equal(Some(
    "https://indieauth.example.com/.well-known/oauth-authorization-server",
  ))
}

pub fn find_link_header_unquoted_rel_test() -> Nil {
  let headers = [
    #("Link", "<https://example.com/auth>; rel=authorization_endpoint"),
  ]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(Some("https://example.com/auth"))
}

pub fn find_link_header_case_insensitive_test() -> Nil {
  let headers = [
    #("link", "<https://example.com/auth>; rel=\"Authorization_Endpoint\""),
  ]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(Some("https://example.com/auth"))
}

pub fn find_link_header_multiple_entries_test() -> Nil {
  let headers = [
    #(
      "Link",
      "<https://example.com/micropub>; rel=\"micropub\", <https://example.com/auth>; rel=\"authorization_endpoint\"",
    ),
  ]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(Some("https://example.com/auth"))
}

pub fn find_link_header_not_found_test() -> Nil {
  let headers = [
    #("Link", "<https://example.com/micropub>; rel=\"micropub\""),
  ]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(None)
}

pub fn find_link_header_no_link_headers_test() -> Nil {
  let headers = [#("Content-Type", "text/html")]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(None)
}

// === find_html_link_rel ===

pub fn find_html_link_rel_basic_test() -> Nil {
  let html =
    "<html><head><link rel=\"authorization_endpoint\" href=\"https://example.com/auth\"></head></html>"

  discovery.find_html_link_rel(html, "authorization_endpoint")
  |> expect.to_equal(Some("https://example.com/auth"))
}

pub fn find_html_link_rel_metadata_test() -> Nil {
  let html =
    "<html><head>
    <link rel=\"indieauth-metadata\" href=\"https://example.com/.well-known/oauth-authorization-server\">
    </head></html>"

  discovery.find_html_link_rel(html, "indieauth-metadata")
  |> expect.to_equal(Some(
    "https://example.com/.well-known/oauth-authorization-server",
  ))
}

pub fn find_html_link_rel_relative_href_test() -> Nil {
  let html =
    "<html><head><link rel=\"token_endpoint\" href=\"/token\"></head></html>"

  discovery.find_html_link_rel(html, "token_endpoint")
  |> expect.to_equal(Some("/token"))
}

pub fn find_html_link_rel_not_found_test() -> Nil {
  let html =
    "<html><head><link rel=\"stylesheet\" href=\"/style.css\"></head></html>"

  discovery.find_html_link_rel(html, "authorization_endpoint")
  |> expect.to_equal(None)
}

pub fn find_html_link_rel_empty_html_test() -> Nil {
  discovery.find_html_link_rel("", "authorization_endpoint")
  |> expect.to_equal(None)
}

pub fn find_html_link_rel_multiple_links_first_wins_test() -> Nil {
  let html =
    "<html><head>
    <link rel=\"authorization_endpoint\" href=\"https://first.example.com/auth\">
    <link rel=\"authorization_endpoint\" href=\"https://second.example.com/auth\">
    </head></html>"

  discovery.find_html_link_rel(html, "authorization_endpoint")
  |> expect.to_equal(Some("https://first.example.com/auth"))
}

// === discovered endpoints must be public HTTPS ===

pub fn parse_metadata_rejects_http_token_endpoint_test() -> Nil {
  let json =
    "{
    \"authorization_endpoint\": \"https://auth.example.com/authorize\",
    \"token_endpoint\": \"http://auth.example.com/token\"
  }"
  let assert Error(err) = discovery.parse_metadata(json)
  error.kind(err) |> expect.to_equal(error.ConfigKind)
}

pub fn parse_metadata_rejects_private_userinfo_endpoint_test() -> Nil {
  let json =
    "{
    \"authorization_endpoint\": \"https://auth.example.com/authorize\",
    \"token_endpoint\": \"https://auth.example.com/token\",
    \"userinfo_endpoint\": \"https://169.254.169.254/latest/meta-data/\"
  }"
  let _ =
    discovery.parse_metadata(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_metadata_rejects_loopback_authorization_endpoint_test() -> Nil {
  let json =
    "{
    \"authorization_endpoint\": \"https://127.0.0.1/authorize\",
    \"token_endpoint\": \"https://auth.example.com/token\"
  }"
  let _ =
    discovery.parse_metadata(json)
    |> expect.to_be_error()
  Nil
}

pub fn validate_endpoints_accepts_public_https_test() -> Nil {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: Some("https://auth.example.com/"),
      userinfo_endpoint: Some("https://auth.example.com/userinfo"),
    )
  discovery.validate_endpoints(endpoints)
  |> expect.to_be_ok()
  |> expect.to_equal(endpoints)
}

pub fn validate_endpoints_rejects_private_issuer_test() -> Nil {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: Some("https://10.0.0.5/"),
      userinfo_endpoint: None,
    )
  let _ =
    discovery.validate_endpoints(endpoints)
    |> expect.to_be_error()
  Nil
}
