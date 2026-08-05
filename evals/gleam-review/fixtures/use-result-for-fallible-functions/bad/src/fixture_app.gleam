import gleam/option

pub fn first(items: List(value)) -> option.Option(value) {
  case items {
    [item, ..] -> option.Some(item)
    [] -> option.None
  }
}
