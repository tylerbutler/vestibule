pub type User {
  User(name: String)
}

pub fn greeting(user: User) -> String {
  case user {
    User(name) -> "Welcome, " <> name
  }
}
