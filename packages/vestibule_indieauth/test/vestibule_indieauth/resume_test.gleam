import gleam/option.{None, Some}
import startest
import startest/expect

import vestibule_indieauth
import vestibule_indieauth/discovery.{DiscoveredEndpoints}

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

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
  |> expect.to_be_ok()
  |> expect.to_equal(#(endpoints, "https://me.example.com/"))
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
  |> expect.to_be_ok()
  |> expect.to_equal(#(endpoints, "https://me.example.com/"))
}

pub fn parse_rejects_garbage_test() -> Nil {
  let _ =
    vestibule_indieauth.parse_endpoints("not json")
    |> expect.to_be_error()
  Nil
}

pub fn parse_rejects_missing_fields_test() -> Nil {
  let _ =
    vestibule_indieauth.parse_endpoints("{\"me\":\"https://me.example.com/\"}")
    |> expect.to_be_error()
  Nil
}
