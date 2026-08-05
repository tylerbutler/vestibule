pub fn first(items: List(value)) -> Result(value, Nil) {
  case items {
    [item, ..] -> Ok(item)
    [] -> Error(Nil)
  }
}
