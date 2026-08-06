import gleam/string

pub type Identifier {
  Identifier(prefix: String, value: String)
}

pub type ParseError {
  InvalidIdentifier(input: String, expected_format: String)
}

pub fn parse_identifier(input: String) -> Result(Identifier, ParseError) {
  let assert [prefix, value] = string.split(input, ":")
  Ok(Identifier(prefix, value))
}
