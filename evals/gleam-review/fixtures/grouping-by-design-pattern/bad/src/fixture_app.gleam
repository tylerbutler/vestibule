import fixture_app/controller/order_controller

pub fn order_page(order_id: String) -> String {
  order_controller.page(order_id)
}
