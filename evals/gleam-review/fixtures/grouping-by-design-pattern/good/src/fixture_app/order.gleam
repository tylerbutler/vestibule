import gleam/int
import gleam/list

pub type Order {
  Order(id: String, item_prices: List(Int))
}

pub fn new(id: String, item_prices: List(Int)) -> Order {
  Order(id:, item_prices:)
}

pub fn total(order: Order) -> Int {
  let Order(item_prices:, ..) = order
  list.fold(item_prices, 0, fn(sum, price) { sum + price })
}

pub fn summary(order: Order) -> String {
  let Order(id:, ..) = order
  "Order " <> id <> " totals " <> int.to_string(total(order))
}
