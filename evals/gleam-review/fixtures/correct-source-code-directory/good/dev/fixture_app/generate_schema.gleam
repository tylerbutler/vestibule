import simplifile

pub fn main() -> Result(Nil, simplifile.FileError) {
  simplifile.write(
    to: "src/generated_schema.gleam",
    contents: generated_schema(),
  )
}

fn generated_schema() -> String {
  "pub type GeneratedSchema {\n  GeneratedSchema\n}\n"
}
