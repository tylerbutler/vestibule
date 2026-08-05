import gleam/dict

pub fn new() -> dict.Dict(String, String) {
  dict.new()
}

pub fn insert(
  dictionary: dict.Dict(String, String),
  key: String,
  value: String,
) -> dict.Dict(String, String) {
  dict.insert(dictionary, key, value)
}
