import argv
import gleam/int
import gleam/io
import gleam/result

pub fn main() -> Nil {
  case argv.load().arguments {
    [input, ..] -> {
      let parsed = int.parse(input)
      case result.is_ok(parsed) {
        True -> {
          let assert Ok(value) = parsed
          io.println(int.to_string(value * 2))
        }
        False -> io.println("Expected an integer.")
      }
    }
    [] -> io.println("Expected an integer.")
  }
}
