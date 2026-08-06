import gleam/list

pub type Monoid(value) {
  Monoid(identity: value, combine: fn(value, value) -> value)
}

pub fn combine_all(values: List(value), monoid: Monoid(value)) -> value {
  list.fold(values, monoid.identity, monoid.combine)
}
