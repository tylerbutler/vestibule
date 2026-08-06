pub type Inventory {
  Inventory(available: Int)
}

pub fn new(available: Int) -> Inventory {
  Inventory(available:)
}

pub fn receive(inventory: Inventory, units: Int) -> Inventory {
  let Inventory(available:) = inventory
  Inventory(available: available + units)
}

pub fn available(inventory: Inventory) -> Int {
  let Inventory(available:) = inventory
  available
}
