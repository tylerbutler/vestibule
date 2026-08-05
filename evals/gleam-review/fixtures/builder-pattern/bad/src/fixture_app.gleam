import gleam/option

pub type Button {
  Button(text: String, colour: String, size: Size, icon: option.Option(String))
}

pub type Size {
  Small
  Large
}

pub fn create_button(
  text: String,
  colour: String,
  size: Size,
  icon: option.Option(String),
) -> Button {
  Button(text, colour, size, icon)
}
