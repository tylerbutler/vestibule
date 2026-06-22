import gleam/option.{None, Some}
import startest
import startest/expect

import vestibule_indieauth/discovery

pub fn main() {
  startest.run(startest.default_config())
}

// === parse_metadata ===

pub fn parse_metadata_full_test() {
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

pub fn parse_metadata_minimal_test() {
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

pub fn parse_metadata_missing_auth_endpoint_test() {
  let json = "{ \"token_endpoint\": \"https://example.com/token\" }"

  let _ =
    discovery.parse_metadata(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_metadata_missing_token_endpoint_test() {
  let json = "{ \"authorization_endpoint\": \"https://example.com/auth\" }"

  let _ =
    discovery.parse_metadata(json)
    |> expect.to_be_error()
  Nil
}

pub fn parse_metadata_invalid_json_test() {
  let _ =
    discovery.parse_metadata("not json")
    |> expect.to_be_error()
  Nil
}

// === find_link_header_rel ===

pub fn find_link_header_basic_test() {
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

pub fn find_link_header_unquoted_rel_test() {
  let headers = [
    #("Link", "<https://example.com/auth>; rel=authorization_endpoint"),
  ]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(Some("https://example.com/auth"))
}

pub fn find_link_header_case_insensitive_test() {
  let headers = [
    #("link", "<https://example.com/auth>; rel=\"Authorization_Endpoint\""),
  ]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(Some("https://example.com/auth"))
}

pub fn find_link_header_multiple_entries_test() {
  let headers = [
    #(
      "Link",
      "<https://example.com/micropub>; rel=\"micropub\", <https://example.com/auth>; rel=\"authorization_endpoint\"",
    ),
  ]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(Some("https://example.com/auth"))
}

pub fn find_link_header_not_found_test() {
  let headers = [
    #("Link", "<https://example.com/micropub>; rel=\"micropub\""),
  ]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(None)
}

pub fn find_link_header_no_link_headers_test() {
  let headers = [#("Content-Type", "text/html")]

  discovery.find_link_header_rel(headers, "authorization_endpoint")
  |> expect.to_equal(None)
}

// === find_html_link_rel ===

pub fn find_html_link_rel_basic_test() {
  let html =
    "<html><head><link rel=\"authorization_endpoint\" href=\"https://example.com/auth\"></head></html>"

  discovery.find_html_link_rel(html, "authorization_endpoint")
  |> expect.to_equal(Some("https://example.com/auth"))
}

pub fn find_html_link_rel_metadata_test() {
  let html =
    "<html><head>
    <link rel=\"indieauth-metadata\" href=\"https://example.com/.well-known/oauth-authorization-server\">
    </head></html>"

  discovery.find_html_link_rel(html, "indieauth-metadata")
  |> expect.to_equal(Some(
    "https://example.com/.well-known/oauth-authorization-server",
  ))
}

pub fn find_html_link_rel_relative_href_test() {
  let html =
    "<html><head><link rel=\"token_endpoint\" href=\"/token\"></head></html>"

  discovery.find_html_link_rel(html, "token_endpoint")
  |> expect.to_equal(Some("/token"))
}

pub fn find_html_link_rel_not_found_test() {
  let html =
    "<html><head><link rel=\"stylesheet\" href=\"/style.css\"></head></html>"

  discovery.find_html_link_rel(html, "authorization_endpoint")
  |> expect.to_equal(None)
}

pub fn find_html_link_rel_empty_html_test() {
  discovery.find_html_link_rel("", "authorization_endpoint")
  |> expect.to_equal(None)
}

pub fn find_html_link_rel_multiple_links_first_wins_test() {
  let html =
    "<html><head>
    <link rel=\"authorization_endpoint\" href=\"https://first.example.com/auth\">
    <link rel=\"authorization_endpoint\" href=\"https://second.example.com/auth\">
    </head></html>"

  discovery.find_html_link_rel(html, "authorization_endpoint")
  |> expect.to_equal(Some("https://first.example.com/auth"))
}
