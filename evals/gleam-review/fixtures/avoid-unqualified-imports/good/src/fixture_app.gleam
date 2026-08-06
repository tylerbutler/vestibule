import gleam/list
import gleam/string

pub fn reverse_text(input: String) -> String {
  input
  |> string.to_graphemes
  |> list.reverse
  |> string.concat
}
