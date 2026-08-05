pub type Kind {
  Primary
  Secondary
}

pub fn render(label: String, kind: Kind) -> String {
  case kind {
    Primary -> "[ " <> label <> " ]"
    Secondary -> label
  }
}

pub fn primary(label: String) -> String {
  render(label, Primary)
}
