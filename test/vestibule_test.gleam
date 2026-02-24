import gleeunit
import gleeunit/should
import vestibule

pub fn main() -> Nil {
  gleeunit.main()
}

pub fn hello_test() {
  vestibule.hello("World")
  |> should.equal("Hello, World!")
}

pub fn hello_gleam_test() {
  vestibule.hello("Gleam")
  |> should.equal("Hello, Gleam!")
}
