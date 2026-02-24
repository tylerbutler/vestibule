import startest
import startest/expect
import vestibule

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn hello_test() {
  vestibule.hello("World")
  |> expect.to_equal("Hello, World!")
}

pub fn hello_gleam_test() {
  vestibule.hello("Gleam")
  |> expect.to_equal("Hello, Gleam!")
}
