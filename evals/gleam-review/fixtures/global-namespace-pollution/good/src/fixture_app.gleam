import fixture_app/distribution
import fixture_app/inventory

pub fn summary() -> #(String, Int) {
  #(distribution.channel(), inventory.count())
}
