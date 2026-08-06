import gleam/dynamic.{type Dynamic}

@external(erlang, "fixture_ffi", "byte_size")
pub fn byte_size(data: Dynamic) -> Int
