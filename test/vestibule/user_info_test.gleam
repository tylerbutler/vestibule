import gleam/dict
import gleam/option.{None, Some}
import startest/expect
import vestibule/user_info

pub fn new_user_info_has_empty_defaults_test() {
  let info = user_info.new()

  user_info.name(info) |> expect.to_equal(None)
  user_info.email(info) |> expect.to_equal(None)
  user_info.nickname(info) |> expect.to_equal(None)
  user_info.image(info) |> expect.to_equal(None)
  user_info.description(info) |> expect.to_equal(None)
  user_info.urls(info) |> expect.to_equal(dict.new())
}

pub fn user_info_builders_update_individual_fields_test() {
  let info =
    user_info.new()
    |> user_info.with_name(Some("Test User"))
    |> user_info.with_email(Some("test@example.com"))
    |> user_info.with_nickname(Some("tester"))
    |> user_info.with_image(Some("https://example.com/avatar.png"))
    |> user_info.with_description(Some("Example account"))
    |> user_info.with_url("profile", "https://example.com/tester")

  user_info.name(info) |> expect.to_equal(Some("Test User"))
  user_info.email(info) |> expect.to_equal(Some("test@example.com"))
  user_info.nickname(info) |> expect.to_equal(Some("tester"))
  user_info.image(info)
  |> expect.to_equal(Some("https://example.com/avatar.png"))
  user_info.description(info) |> expect.to_equal(Some("Example account"))
  user_info.urls(info)
  |> expect.to_equal(
    dict.from_list([
      #("profile", "https://example.com/tester"),
    ]),
  )
}

pub fn with_urls_replaces_url_map_test() {
  let info =
    user_info.new()
    |> user_info.with_url("old", "https://old.example")
    |> user_info.with_urls(
      dict.from_list([
        #("new", "https://new.example"),
      ]),
    )

  user_info.urls(info)
  |> expect.to_equal(
    dict.from_list([
      #("new", "https://new.example"),
    ]),
  )
}
