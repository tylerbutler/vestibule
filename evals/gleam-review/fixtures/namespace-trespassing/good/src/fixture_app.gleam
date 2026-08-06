import fixture_app/widget

pub fn page(action: String) -> String {
  "Actions: " <> widget.primary(action)
}
