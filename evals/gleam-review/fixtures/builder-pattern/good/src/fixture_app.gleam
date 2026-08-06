import gleam/option

pub type Button {
  Button(text: String, colour: String, size: Size, icon: option.Option(String))
}

pub type Size {
  Small
  Large
}

pub fn new(text: String) -> Button {
  Button(text, "pink", Small, option.None)
}

pub fn colour(button: Button, value: String) -> Button {
  Button(..button, colour: value)
}

pub fn large(button: Button) -> Button {
  Button(..button, size: Large)
}

pub fn icon(button: Button, value: String) -> Button {
  Button(..button, icon: option.Some(value))
}
