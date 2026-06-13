import gleam/option.{None, Some}
import startest/expect

import html

pub fn escape_replaces_html_special_chars_test() {
  html.escape("<script>alert('x')</script>")
  |> expect.to_equal("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;")
}

pub fn escape_replaces_ampersand_and_quotes_test() {
  html.escape("Tom & \"Jerry\"")
  |> expect.to_equal("Tom &amp; &quot;Jerry&quot;")
}

pub fn escape_leaves_plain_text_untouched_test() {
  html.escape("Ada Lovelace")
  |> expect.to_equal("Ada Lovelace")
}

pub fn escape_ampersand_is_applied_first_test() {
  // Ensures already-escaped entities are not double-decoded: a raw "&lt;"
  // becomes "&amp;lt;", not "&lt;".
  html.escape("&lt;")
  |> expect.to_equal("&amp;lt;")
}

pub fn safe_image_url_allows_https_test() {
  html.safe_image_url("https://example.com/avatar.png")
  |> expect.to_equal(Some("https://example.com/avatar.png"))
}

pub fn safe_image_url_escapes_attribute_test() {
  html.safe_image_url("https://example.com/a.png\"><script>alert(1)</script>")
  |> expect.to_equal(Some(
    "https://example.com/a.png&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
  ))
}

pub fn safe_image_url_rejects_javascript_scheme_test() {
  html.safe_image_url("javascript:alert(1)")
  |> expect.to_equal(None)
}

pub fn safe_image_url_rejects_data_scheme_test() {
  html.safe_image_url("data:text/html,<script>alert(1)</script>")
  |> expect.to_equal(None)
}

pub fn safe_image_url_rejects_plain_http_test() {
  html.safe_image_url("http://example.com/avatar.png")
  |> expect.to_equal(None)
}

pub fn safe_image_url_rejects_protocol_relative_test() {
  html.safe_image_url("//evil.com/avatar.png")
  |> expect.to_equal(None)
}
