import gleam/option.{None, Some}

import vestibule_indieauth
import vestibule_indieauth/discovery.{DiscoveredEndpoints}

// === serialize_endpoints / parse_endpoints ===

pub fn serialize_parse_round_trip_test() {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: Some("https://auth.example.com/"),
      userinfo_endpoint: Some("https://auth.example.com/userinfo"),
    )

  let result =
    vestibule_indieauth.serialize_endpoints(
      endpoints,
      "https://me.example.com/",
    )
    |> vestibule_indieauth.parse_endpoints()
  assert result == Ok(#(endpoints, "https://me.example.com/"))
}

pub fn serialize_parse_round_trip_with_none_test() {
  let endpoints =
    DiscoveredEndpoints(
      authorization_endpoint: "https://auth.example.com/authorize",
      token_endpoint: "https://auth.example.com/token",
      issuer: None,
      userinfo_endpoint: None,
    )

  let result =
    vestibule_indieauth.serialize_endpoints(
      endpoints,
      "https://me.example.com/",
    )
    |> vestibule_indieauth.parse_endpoints()
  assert result == Ok(#(endpoints, "https://me.example.com/"))
}

pub fn parse_rejects_garbage_test() {
  let assert Error(_) = vestibule_indieauth.parse_endpoints("not json")
  Nil
}

pub fn parse_rejects_missing_fields_test() {
  let assert Error(_) =
    vestibule_indieauth.parse_endpoints("{\"me\":\"https://me.example.com/\"}")
  Nil
}
