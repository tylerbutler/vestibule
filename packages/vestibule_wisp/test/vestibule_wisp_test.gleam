import startest
import startest/expect
import vestibule_wisp
import vestibule_wisp/state_store

pub fn main() -> Nil {
  startest.run(startest.default_config())
}

pub fn store_and_retrieve_state_and_verifier_test() {
  let table = state_store.init_named("test_store_retrieve")
  let state = "test-csrf-state-value"
  let verifier = "test-pkce-code-verifier"
  let session_id = state_store.store(table, state, verifier)
  state_store.retrieve(table, session_id)
  |> expect.to_be_ok()
  |> expect.to_equal(#(state, verifier))
}

pub fn retrieve_deletes_after_use_test() {
  let table = state_store.init_named("test_delete_after_use")
  let session_id =
    state_store.store(table, "one-time-state", "one-time-verifier")
  let _ = state_store.retrieve(table, session_id)
  state_store.retrieve(table, session_id)
  |> expect.to_be_error()
}

pub fn retrieve_unknown_returns_error_test() {
  let table = state_store.init_named("test_unknown_returns_error")
  state_store.retrieve(table, "nonexistent-session-id")
  |> expect.to_be_error()
}

pub fn html_escape_ampersand_test() {
  vestibule_wisp.html_escape("foo & bar")
  |> expect.to_equal("foo &amp; bar")
}

pub fn html_escape_angle_brackets_test() {
  vestibule_wisp.html_escape("<script>alert(1)</script>")
  |> expect.to_equal("&lt;script&gt;alert(1)&lt;/script&gt;")
}

pub fn html_escape_double_quotes_test() {
  vestibule_wisp.html_escape("a \"quoted\" value")
  |> expect.to_equal("a &quot;quoted&quot; value")
}

pub fn html_escape_single_quotes_test() {
  vestibule_wisp.html_escape("it's dangerous")
  |> expect.to_equal("it&#x27;s dangerous")
}

pub fn html_escape_all_special_chars_test() {
  vestibule_wisp.html_escape("<b>\"Hello\" & 'world'</b>")
  |> expect.to_equal(
    "&lt;b&gt;&quot;Hello&quot; &amp; &#x27;world&#x27;&lt;/b&gt;",
  )
}

pub fn html_escape_no_special_chars_test() {
  vestibule_wisp.html_escape("plain text message")
  |> expect.to_equal("plain text message")
}

pub fn html_escape_empty_string_test() {
  vestibule_wisp.html_escape("")
  |> expect.to_equal("")
}

pub fn html_escape_xss_payload_test() {
  vestibule_wisp.html_escape("<img src=x onerror=\"alert('xss')\">")
  |> expect.to_equal(
    "&lt;img src=x onerror=&quot;alert(&#x27;xss&#x27;)&quot;&gt;",
  )
}
