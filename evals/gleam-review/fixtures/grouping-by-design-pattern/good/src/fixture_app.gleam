import fixture_app/order

pub fn order_summary(order_id: String, item_prices: List(Int)) -> String {
  order.new(order_id, item_prices)
  |> order.summary
}
