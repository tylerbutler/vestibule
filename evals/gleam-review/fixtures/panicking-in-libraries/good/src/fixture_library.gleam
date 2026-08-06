import gleam/string

pub type Identifier {
  Identifier(prefix: String, value: String)
}

pub type ParseError {
  InvalidIdentifier(input: String, expected_format: String)
}

pub fn parse_identifier(input: String) -> Result(Identifier, ParseError) {
  case string.split(input, ":") {
    [prefix, value] -> Ok(Identifier(prefix, value))
    _ -> Error(InvalidIdentifier(input, "prefix:value"))
  }
}
