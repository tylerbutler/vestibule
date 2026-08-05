pub type Channel {
  Retail
  Partner
}

pub fn label(channel: Channel) -> String {
  case channel {
    Retail -> "retail"
    Partner -> "partner"
  }
}
