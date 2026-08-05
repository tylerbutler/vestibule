pub type Identifier {
  Identifier(value: String)
}

pub fn to_string(identifier: Identifier) -> String {
  case identifier {
    Identifier(value) -> value
  }
}
