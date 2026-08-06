pub type Json {
  Json(source: String)
}

pub fn build_json(input: String) -> Json {
  Json(input)
}
