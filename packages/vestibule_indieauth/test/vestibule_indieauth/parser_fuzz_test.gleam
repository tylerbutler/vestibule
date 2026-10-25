import gleam/http/response
import gleam/list
import gleam/string
import vestibule_indieauth/discovery
import vestibule_indieauth/token

pub fn bounded_indieauth_parser_corpus_test() -> Nil {
  list.each(corpus(), fn(input) {
    let _ = discovery.parse_metadata(input)
    let _ =
      discovery.parse_profile_response(
        "https://example.com/",
        response.new(200) |> response.set_body(input),
      )
    let _ = token.parse_token_response(input)
    let _ = token.parse_profile_from_token_response(input)
    let _ = token.parse_userinfo_response(input)
    Nil
  })
}

pub fn malformed_html_link_is_rejected_test() {
  let assert Error(_) =
    discovery.parse_profile_response(
      "https://example.com/",
      response.new(200) |> response.set_body("<link"),
    )
}

pub fn empty_html_link_href_is_rejected_test() {
  let assert Error(_) =
    discovery.parse_profile_response(
      "https://example.com/",
      response.new(200)
        |> response.set_body("<link rel=indieauth-metadata href=>"),
    )
}

fn corpus() -> List(String) {
  [
    "",
    "<",
    "<link",
    "<link rel=indieauth-metadata href=>",
    "{",
    "[]",
    "null",
    "{\"me\":null}",
    "{\"authorization_endpoint\":[]}",
    "{\"access_token\":\"x\",\"token_type\":[],\"me\":\"https://example.com/\"}",
    string.repeat("<", 8192),
  ]
}
