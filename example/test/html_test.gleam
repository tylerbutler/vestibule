import gleam/option.{None, Some}

import vestibule_example/html

pub fn safe_image_url_allows_https_test() -> Nil {
  html.safe_image_url("https://example.com/avatar.png")
  |> fn(actual) {
    assert actual == Some("https://example.com/avatar.png")
  }
}

pub fn safe_image_url_escapes_attribute_test() -> Nil {
  html.safe_image_url("https://example.com/a.png\"><script>alert(1)</script>")
  |> fn(actual) {
    assert actual
      == Some(
        "https://example.com/a.png&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
      )
  }
}

pub fn safe_image_url_rejects_javascript_scheme_test() -> Nil {
  html.safe_image_url("javascript:alert(1)")
  |> fn(actual) {
    assert actual == None
  }
}

pub fn safe_image_url_rejects_data_scheme_test() -> Nil {
  html.safe_image_url("data:text/html,<script>alert(1)</script>")
  |> fn(actual) {
    assert actual == None
  }
}

pub fn safe_image_url_rejects_plain_http_test() -> Nil {
  html.safe_image_url("http://example.com/avatar.png")
  |> fn(actual) {
    assert actual == None
  }
}

pub fn safe_image_url_rejects_protocol_relative_test() -> Nil {
  html.safe_image_url("//evil.com/avatar.png")
  |> fn(actual) {
    assert actual == None
  }
}
