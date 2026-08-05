import argv
import gleam/int
import gleam/io

pub fn main() -> Nil {
  case argv.load().arguments {
    [input, ..] ->
      case int.parse(input) {
        Ok(value) -> io.println(int.to_string(value * 2))
        Error(_) -> io.println("Expected an integer.")
      }
    [] -> io.println("Expected an integer.")
  }
}
