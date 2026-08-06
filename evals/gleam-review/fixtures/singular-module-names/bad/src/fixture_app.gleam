import fixture_app/users.{type User}

pub fn welcome(user: User) -> String {
  users.greeting(user)
}
