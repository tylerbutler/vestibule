import gleam/option.{type Option}

pub type Visitor {
  Visitor(id: Option(Int), email: Option(String))
}
