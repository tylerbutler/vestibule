import gleam/list
import gleam/string
import gleam/uri
import vestibule/oidc
import vestibule/provider_support

pub fn bounded_core_parser_corpus_test() -> Nil {
  list.each(corpus(), fn(input) {
    let _ = uri.parse_query(input)
    let _ = provider_support.parse_redirect_uri(input)
    let _ =
      provider_support.parse_oauth_token_response(
        input,
        provider_support.OptionalScope(separator: " "),
      )
    let _ = oidc.parse_jwks(input)
    Nil
  })
}

fn corpus() -> List(String) {
  [
    "",
    ".",
    "..",
    "...",
    "%",
    "%00",
    "%ZZ",
    "a=b&a=c",
    "a",
    "=",
    "&",
    "{\"",
    "[]",
    "null",
    "true",
    "{\"access_token\":null}",
    "{\"access_token\":\"x\",\"token_type\":\"Bearer\",\"scope\":[]}",
    "{\"keys\":[null]}",
    "{\"keys\":[]}",
    "{\"keys\":\"not-a-list\"}",
    string.repeat("a", 8192),
  ]
}
