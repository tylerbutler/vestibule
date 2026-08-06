pub type Identifier {
  Identifier(value: String)
}

pub fn identifier_as_string(identifier: Identifier) -> String {
  case identifier {
    Identifier(value) -> value
  }
}
