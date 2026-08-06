import gleam/list.{reverse}
import gleam/string.{concat, to_graphemes}

pub fn reverse_text(input: String) -> String {
  input
  |> to_graphemes
  |> reverse
  |> concat
}
