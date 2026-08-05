import gleam/list

pub fn map(
  values: List(value),
  transform: fn(value) -> mapped,
) -> List(mapped) {
  list.map(values, transform)
}

pub fn try_map(
  values: List(value),
  transform: fn(value) -> Result(mapped, error),
) -> Result(List(mapped), error) {
  list.try_map(values, transform)
}
