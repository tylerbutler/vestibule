import gleam/option.{None, Some}

import vestibule_indieauth
import vestibule_indieauth/discovery.{DiscoveredEndpoints}

// === serialize_endpoints / parse_endpoints ===

pub fn serialize_parse_round_trip_test() -> Nil {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: Some("https://auth.example.com/"),
      userinfo_endpoint: Some("https://auth.example.com/userinfo"),
    )

  vestibule_indieauth.serialize_endpoints(endpoints, "https://me.example.com/")
  |> vestibule_indieauth.parse_endpoints()
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #(endpoints, "https://me.example.com/")
  }
}

pub fn serialize_parse_round_trip_with_none_test() -> Nil {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: None,
      userinfo_endpoint: None,
    )

  vestibule_indieauth.serialize_endpoints(endpoints, "https://me.example.com/")
  |> vestibule_indieauth.parse_endpoints()
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == #(endpoints, "https://me.example.com/")
  }
}

pub fn parse_rejects_garbage_test() -> Nil {
  let _ =
    vestibule_indieauth.parse_endpoints("not json")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_rejects_missing_fields_test() -> Nil {
  let _ =
    vestibule_indieauth.parse_endpoints("{\"me\":\"https://me.example.com/\"}")
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_rejects_non_public_endpoints_test() -> Nil {
  // Serialized endpoints normally come from a signed cookie, but the token
  // and userinfo requests must never be pointed at an internal host even if
  // that trust boundary is misconfigured.
  let _ =
    vestibule_indieauth.parse_endpoints(
      "{\"me\":\"https://me.example.com/\",\"authorization_endpoint\":\"https://auth.example.com/authorize\",\"token_endpoint\":\"http://10.0.0.5:8500/v1/kv/secret\",\"issuer\":null,\"userinfo_endpoint\":null}",
    )
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn parse_rejects_http_profile_identity_test() -> Nil {
  let assert Error(_) =
    vestibule_indieauth.parse_endpoints(
      "{\"me\":\"http://me.example.com/\",\"authorization_endpoint\":\"https://auth.example.com/authorize\",\"token_endpoint\":\"https://auth.example.com/token\",\"issuer\":null,\"userinfo_endpoint\":null}",
    )
  Nil
}
