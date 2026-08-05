import distribution
import inventory

pub fn summary() -> #(String, Int) {
  #(distribution.channel(), inventory.count())
}
