import fixture_app/error.{type LoadError, InvalidUser}
import fixture_app/user.{type User, User}

pub fn user(input: String) -> Result(User, LoadError) {
  case input {
    "" -> Error(InvalidUser(input))
    _ -> Ok(User(input))
  }
}
