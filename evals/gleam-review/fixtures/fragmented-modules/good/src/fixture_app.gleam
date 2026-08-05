pub type User {
  User(name: String)
}

pub type LoadError {
  InvalidUser(input: String)
}

pub fn load_user(input: String) -> Result(User, LoadError) {
  let request_url = "https://example.com/users/" <> input
  case request_url {
    "https://example.com/users/" -> Error(InvalidUser(input))
    _ -> Ok(User(input))
  }
}
