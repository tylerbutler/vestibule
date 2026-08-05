pub type User {
  User(name: String)
}

pub fn new(name: String) -> User {
  User(name)
}

pub fn greeting(user: User) -> String {
  case user {
    User(name) -> "Welcome, " <> name
  }
}

pub fn rename(user: User, name: String) -> User {
  let User(_) = user
  User(name)
}
