import gleam/list
import gleam/string
import vestibule_oidc

pub fn bounded_oidc_parser_corpus_test() -> Nil {
  list.each(corpus(), fn(input) {
    let _ = vestibule_oidc.parse_discovery_document(input)
    let _ = vestibule_oidc.parse_token_response(input)
    let _ = vestibule_oidc.parse_userinfo_response(input)
    Nil
  })
}

fn corpus() -> List(String) {
  [
    "",
    "{",
    "[]",
    "null",
    "true",
    "{\"issuer\":null}",
    "{\"sub\":[]}",
    "{\"access_token\":{},\"token_type\":\"Bearer\"}",
    "{\"error\":\"invalid_request\",\"error_description\":[]}",
    string.repeat("{", 8192),
  ]
}
