import gleam/int

pub fn total_cost(costs: List(Int)) -> Int {
  int.sum(costs)
}
