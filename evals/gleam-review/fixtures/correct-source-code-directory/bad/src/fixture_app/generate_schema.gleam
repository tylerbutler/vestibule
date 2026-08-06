import simplifile

pub fn main() -> Nil {
  case
    simplifile.write(
      to: "src/generated_schema.gleam",
      contents: generated_schema(),
    )
  {
    Ok(_) -> Nil
    Error(_) -> Nil
  }
}

fn generated_schema() -> String {
  "pub type GeneratedSchema {\n  GeneratedSchema\n}\n"
}
