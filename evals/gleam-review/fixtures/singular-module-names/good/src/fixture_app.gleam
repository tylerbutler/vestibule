import fixture_app/user

pub fn welcome(name: String) -> String {
  name
  |> user.new
  |> user.greeting
}
