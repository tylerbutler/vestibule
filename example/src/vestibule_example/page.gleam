import gleam/list
import gleam/option.{None, Some}
import gleam/string
import houdini
import wisp

import vestibule/auth.{type Auth}
import vestibule/user_info
import vestibule_example/html

/// Landing page with dynamic provider buttons.
pub fn landing(providers: List(String)) -> wisp.Response {
  let buttons =
    providers
    |> list.map(fn(provider) {
      "<a href=\"/auth/"
      <> provider
      <> "\"\n     style=\"display: inline-block; padding: 12px 24px; background: #24292e; color: white; text-decoration: none; border-radius: 6px; font-size: 16px; margin: 8px;\">\n    Sign in with "
      <> capitalize(provider)
      <> "\n  </a>"
    })
    |> string.join("\n  ")
  wisp.html_response("<html>
<head><title>Vestibule Demo</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; text-align: center;\">
  <h1>Vestibule Demo</h1>
  <p>OAuth2 authentication library for Gleam</p>
  " <> buttons <> "
</body>
</html>", 200)
}

fn capitalize(input: String) -> String {
  case string.pop_grapheme(input) {
    Ok(#(first, rest)) -> string.uppercase(first) <> rest
    Error(Nil) -> input
  }
}

/// Success page showing authenticated user info.
pub fn success(authentication: Auth) -> wisp.Response {
  let user_information = auth.info(authentication)
  let name =
    houdini.escape(option.unwrap(user_info.name(user_information), "—"))
  let email =
    houdini.escape(option.unwrap(user_info.email(user_information), "—"))
  let nickname =
    houdini.escape(option.unwrap(user_info.nickname(user_information), "—"))
  let provider = houdini.escape(auth.provider(authentication))
  let user_id = houdini.escape(auth.uid(authentication))
  let image_html = case user_info.image(user_information) {
    Some(url) ->
      case html.safe_image_url(url) {
        Ok(safe_url) ->
          "<img src=\""
          <> safe_url
          <> "\" width=\"80\" height=\"80\" style=\"border-radius: 50%;\" />"
        Error(Nil) -> ""
      }
    None -> ""
  }
  wisp.html_response("<html>
<head><title>Authenticated — Vestibule Demo</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto;\">
  <h1>Authenticated!</h1>
  " <> image_html <> "
  <table style=\"margin: 20px 0; border-collapse: collapse;\">
    <tr><td style=\"padding: 8px; font-weight: bold;\">Provider</td><td style=\"padding: 8px;\">" <> provider <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">UID</td><td style=\"padding: 8px;\">" <> user_id <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">Name</td><td style=\"padding: 8px;\">" <> name <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">Email</td><td style=\"padding: 8px;\">" <> email <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">Nickname</td><td style=\"padding: 8px;\">" <> nickname <> "</td></tr>
  </table>
  <a href=\"/\">Back to home</a>
</body>
</html>", 200)
}
