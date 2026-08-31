import gleam/http/response
import gleam/option.{None, Some}

import vestibule/error
import vestibule/provider_support
import vestibule_indieauth/discovery.{DiscoveredEndpoints}

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
  |> fn(actual) {
    assert actual == "https://indieauth.example.com/auth"
  }

  endpoints.token_endpoint
  |> fn(actual) {
    assert actual == "https://indieauth.example.com/token"
  }

  endpoints.issuer
  |> fn(actual) {
    assert actual == Some("https://indieauth.example.com/")
  }

  endpoints.userinfo_endpoint
  |> fn(actual) {
    assert actual == Some("https://indieauth.example.com/userinfo")
  }
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
  |> fn(actual) {
    assert actual == "https://example.com/auth"
  }

  endpoints.token_endpoint
  |> fn(actual) {
    assert actual == "https://example.com/token"
  }

  endpoints.issuer
  |> fn(actual) {
    assert actual == None
  }

  endpoints.userinfo_endpoint
  |> fn(actual) {
    assert actual == None
  }
}

pub fn parse_metadata_missing_auth_endpoint_test() -> Nil {
  let json = "{ \"token_endpoint\": \"https://example.com/token\" }"

  let _ =
    discovery.parse_metadata(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_metadata_missing_token_endpoint_test() -> Nil {
  let json = "{ \"authorization_endpoint\": \"https://example.com/auth\" }"

  let _ =
    discovery.parse_metadata(json)
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_metadata_invalid_json_test() -> Nil {
  let _ =
    discovery.parse_metadata("not json")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

// === find_link_header_relation ===

pub fn find_link_header_basic_test() -> Nil {
  let headers = [
    #(
      "Link",
      "<https://indieauth.example.com/.well-known/oauth-authorization-server>; rel=\"indieauth-metadata\"",
    ),
  ]

  discovery.find_link_header_relation(headers, "indieauth-metadata")
  |> fn(actual) {
    assert actual
      == Some(
        "https://indieauth.example.com/.well-known/oauth-authorization-server",
      )
  }
}

pub fn find_link_header_unquoted_rel_test() -> Nil {
  let headers = [
    #("Link", "<https://example.com/auth>; rel=authorization_endpoint"),
  ]

  discovery.find_link_header_relation(headers, "authorization_endpoint")
  |> fn(actual) {
    assert actual == Some("https://example.com/auth")
  }
}

pub fn find_link_header_case_insensitive_test() -> Nil {
  let headers = [
    #("link", "<https://example.com/auth>; rel=\"Authorization_Endpoint\""),
  ]

  discovery.find_link_header_relation(headers, "authorization_endpoint")
  |> fn(actual) {
    assert actual == Some("https://example.com/auth")
  }
}

pub fn find_link_header_multiple_entries_test() -> Nil {
  let headers = [
    #(
      "Link",
      "<https://example.com/micropub>; rel=\"micropub\", <https://example.com/auth>; rel=\"authorization_endpoint\"",
    ),
  ]

  discovery.find_link_header_relation(headers, "authorization_endpoint")
  |> fn(actual) {
    assert actual == Some("https://example.com/auth")
  }
}

pub fn find_link_header_not_found_test() -> Nil {
  let headers = [
    #("Link", "<https://example.com/micropub>; rel=\"micropub\""),
  ]

  discovery.find_link_header_relation(headers, "authorization_endpoint")
  |> fn(actual) {
    assert actual == None
  }
}

pub fn find_link_header_no_link_headers_test() -> Nil {
  let headers = [#("Content-Type", "text/html")]

  discovery.find_link_header_relation(headers, "authorization_endpoint")
  |> fn(actual) {
    assert actual == None
  }
}

// === find_html_link_relation ===

pub fn find_html_link_rel_basic_test() -> Nil {
  let html =
    "<html><head><link rel=\"authorization_endpoint\" href=\"https://example.com/auth\"></head></html>"

  discovery.find_html_link_relation(html, "authorization_endpoint")
  |> fn(actual) {
    assert actual == Some("https://example.com/auth")
  }
}

pub fn find_html_link_rel_metadata_test() -> Nil {
  let html =
    "<html><head>
    <link rel=\"indieauth-metadata\" href=\"https://example.com/.well-known/oauth-authorization-server\">
    </head></html>"

  discovery.find_html_link_relation(html, "indieauth-metadata")
  |> fn(actual) {
    assert actual
      == Some("https://example.com/.well-known/oauth-authorization-server")
  }
}

pub fn find_html_link_rel_relative_href_test() -> Nil {
  let html =
    "<html><head><link rel=\"token_endpoint\" href=\"/token\"></head></html>"

  discovery.find_html_link_relation(html, "token_endpoint")
  |> fn(actual) {
    assert actual == Some("/token")
  }
}

pub fn find_html_link_rel_not_found_test() -> Nil {
  let html =
    "<html><head><link rel=\"stylesheet\" href=\"/style.css\"></head></html>"

  discovery.find_html_link_relation(html, "authorization_endpoint")
  |> fn(actual) {
    assert actual == None
  }
}

pub fn find_html_link_rel_empty_html_test() -> Nil {
  discovery.find_html_link_relation("", "authorization_endpoint")
  |> fn(actual) {
    assert actual == None
  }
}

pub fn find_html_link_rel_multiple_links_first_wins_test() -> Nil {
  let html =
    "<html><head>
    <link rel=\"authorization_endpoint\" href=\"https://first.example.com/auth\">
    <link rel=\"authorization_endpoint\" href=\"https://second.example.com/auth\">
    </head></html>"

  discovery.find_html_link_relation(html, "authorization_endpoint")
  |> fn(actual) {
    assert actual == Some("https://first.example.com/auth")
  }
}

// === discovered endpoints must be public HTTPS ===

pub fn parse_metadata_rejects_http_token_endpoint_test() -> Nil {
  let json =
    "{
    \"authorization_endpoint\": \"https://auth.example.com/authorize\",
    \"token_endpoint\": \"http://auth.example.com/token\"
  }"
  let assert Error(auth_error) = discovery.parse_metadata(json)
  error.kind(auth_error)
  |> fn(actual) {
    assert actual == error.ConfigKind
  }
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
    |> fn(result) {
      let assert Error(value) = result
      value
    }
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
    |> fn(result) {
      let assert Error(value) = result
      value
    }
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
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == endpoints
  }
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
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn sans_io_profile_and_metadata_discovery_test() -> Nil {
  let assert Ok(profile_request) =
    discovery.build_profile_request("https://user.example.com/")
  assert provider_support.secure_request_uri(profile_request).host
    == Some("user.example.com")
  assert provider_support.secure_request_header(profile_request, "accept")
    == Ok("text/html, application/xhtml+xml")
  assert provider_support.secure_request_response_limit(profile_request)
    == provider_support.ProfileHtmlResponse

  let profile_response =
    response.Response(
      status: 200,
      headers: [],
      body: "<html><head><link rel=\"indieauth-metadata\" href=\"https://auth.example.com/metadata\"></head></html>",
    )
  let assert Ok(discovery.MetadataRequired(metadata_url)) =
    discovery.parse_profile_response(
      "https://user.example.com/",
      profile_response,
    )
  assert metadata_url == "https://auth.example.com/metadata"

  let assert Ok(metadata_request) =
    discovery.build_metadata_request(metadata_url)
  assert provider_support.secure_request_uri(metadata_request).host
    == Some("auth.example.com")
  assert provider_support.secure_request_header(metadata_request, "accept")
    == Ok("application/json")
  assert provider_support.secure_request_response_limit(metadata_request)
    == provider_support.DiscoveryResponse

  let metadata_response =
    response.Response(
      status: 200,
      headers: [],
      body: "{\"authorization_endpoint\":\"https://auth.example.com/authorize\",\"token_endpoint\":\"https://auth.example.com/token\"}",
    )
  let assert Ok(endpoints) =
    discovery.parse_metadata_response(metadata_url, metadata_response)
  assert endpoints.token_endpoint == "https://auth.example.com/token"
}

pub fn profile_builder_rejects_http_identity_test() -> Nil {
  let assert Error(auth_error) =
    discovery.build_profile_request("http://user.example.com/")
  assert error.kind(auth_error) == error.ConfigKind
}

pub fn sans_io_profile_parser_rejects_private_metadata_url_test() -> Nil {
  let profile_response =
    response.Response(
      status: 200,
      headers: [],
      body: "<html><head><link rel=\"indieauth-metadata\" href=\"https://127.0.0.1/metadata\"></head></html>",
    )
  let assert Error(auth_error) =
    discovery.parse_profile_response(
      "https://user.example.com/",
      profile_response,
    )
  assert error.kind(auth_error) == error.ConfigKind
}
