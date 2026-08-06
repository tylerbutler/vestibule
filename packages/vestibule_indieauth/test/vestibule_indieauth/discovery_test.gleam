import gleam/option.{None, Some}

import vestibule_indieauth/discovery

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

  assert endpoints.authorization_endpoint
    == "https://indieauth.example.com/auth"

  assert endpoints.token_endpoint == "https://indieauth.example.com/token"

  assert endpoints.issuer == Some("https://indieauth.example.com/")

  assert endpoints.userinfo_endpoint
    == Some("https://indieauth.example.com/userinfo")
}

pub fn parse_metadata_minimal_test() {
  let json =
    "{
    \"authorization_endpoint\": \"https://example.com/auth\",
    \"token_endpoint\": \"https://example.com/token\"
  }"

  let result = discovery.parse_metadata(json)
  let assert Ok(endpoints) = result

  assert endpoints.authorization_endpoint == "https://example.com/auth"

  assert endpoints.token_endpoint == "https://example.com/token"

  assert endpoints.issuer == None

  assert endpoints.userinfo_endpoint == None
}

pub fn parse_metadata_missing_auth_endpoint_test() {
  let json = "{ \"token_endpoint\": \"https://example.com/token\" }"

  let assert Error(_) = discovery.parse_metadata(json)
  Nil
}

pub fn parse_metadata_missing_token_endpoint_test() {
  let json = "{ \"authorization_endpoint\": \"https://example.com/auth\" }"

  let assert Error(_) = discovery.parse_metadata(json)
  Nil
}

pub fn parse_metadata_invalid_json_test() {
  let assert Error(_) = discovery.parse_metadata("not json")
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

  assert discovery.find_link_header_rel(headers, "indieauth-metadata")
    == Some(
      "https://indieauth.example.com/.well-known/oauth-authorization-server",
    )
}

pub fn find_link_header_unquoted_rel_test() {
  let headers = [
    #("Link", "<https://example.com/auth>; rel=authorization_endpoint"),
  ]

  assert discovery.find_link_header_rel(headers, "authorization_endpoint")
    == Some("https://example.com/auth")
}

pub fn find_link_header_case_insensitive_test() {
  let headers = [
    #("link", "<https://example.com/auth>; rel=\"Authorization_Endpoint\""),
  ]

  assert discovery.find_link_header_rel(headers, "authorization_endpoint")
    == Some("https://example.com/auth")
}

pub fn find_link_header_multiple_entries_test() {
  let headers = [
    #(
      "Link",
      "<https://example.com/micropub>; rel=\"micropub\", <https://example.com/auth>; rel=\"authorization_endpoint\"",
    ),
  ]

  assert discovery.find_link_header_rel(headers, "authorization_endpoint")
    == Some("https://example.com/auth")
}

pub fn find_link_header_not_found_test() {
  let headers = [
    #("Link", "<https://example.com/micropub>; rel=\"micropub\""),
  ]

  assert discovery.find_link_header_rel(headers, "authorization_endpoint")
    == None
}

pub fn find_link_header_no_link_headers_test() {
  let headers = [#("Content-Type", "text/html")]

  assert discovery.find_link_header_rel(headers, "authorization_endpoint")
    == None
}

// === find_html_link_rel ===

pub fn find_html_link_rel_basic_test() {
  let html =
    "<html><head><link rel=\"authorization_endpoint\" href=\"https://example.com/auth\"></head></html>"

  assert discovery.find_html_link_rel(html, "authorization_endpoint")
    == Some("https://example.com/auth")
}

pub fn find_html_link_rel_metadata_test() {
  let html =
    "<html><head>
    <link rel=\"indieauth-metadata\" href=\"https://example.com/.well-known/oauth-authorization-server\">
    </head></html>"

  assert discovery.find_html_link_rel(html, "indieauth-metadata")
    == Some("https://example.com/.well-known/oauth-authorization-server")
}

pub fn find_html_link_rel_relative_href_test() {
  let html =
    "<html><head><link rel=\"token_endpoint\" href=\"/token\"></head></html>"

  assert discovery.find_html_link_rel(html, "token_endpoint") == Some("/token")
}

pub fn find_html_link_rel_not_found_test() {
  let html =
    "<html><head><link rel=\"stylesheet\" href=\"/style.css\"></head></html>"

  assert discovery.find_html_link_rel(html, "authorization_endpoint") == None
}

pub fn find_html_link_rel_empty_html_test() {
  assert discovery.find_html_link_rel("", "authorization_endpoint") == None
}

pub fn find_html_link_rel_multiple_links_first_wins_test() {
  let html =
    "<html><head>
    <link rel=\"authorization_endpoint\" href=\"https://first.example.com/auth\">
    <link rel=\"authorization_endpoint\" href=\"https://second.example.com/auth\">
    </head></html>"

  assert discovery.find_html_link_rel(html, "authorization_endpoint")
    == Some("https://first.example.com/auth")
}
