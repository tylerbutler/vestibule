import fixture_app/distribution
import fixture_app/inventory
import gleam/int

pub fn retail_fulfillment_summary(available: Int) -> String {
  let stock = inventory.new(available)

  distribution.label(distribution.Retail)
  <> ": "
  <> int.to_string(inventory.available(stock))
}
