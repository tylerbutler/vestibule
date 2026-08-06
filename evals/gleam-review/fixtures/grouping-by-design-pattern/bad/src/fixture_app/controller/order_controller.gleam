import fixture_app/service/order_service
import fixture_app/view/order_view

pub fn page(order_id: String) -> String {
  order_id
  |> order_service.load
  |> order_view.render
}
