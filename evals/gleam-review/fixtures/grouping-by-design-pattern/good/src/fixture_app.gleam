import fixture_app/order

pub fn order_page(order_id: String) -> String {
  order.page(order_id)
}
