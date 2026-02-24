import gleam/option.{type Option, None, Some}
import wisp

import vestibule/auth.{type Auth}
import vestibule/error.{type AuthError}

/// Landing page with GitHub sign-in link.
pub fn landing() -> wisp.Response {
  wisp.html_response(
    "<html>
<head><title>Vestibule Demo</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto; text-align: center;\">
  <h1>Vestibule Demo</h1>
  <p>OAuth2 authentication library for Gleam</p>
  <a href=\"/auth/github\"
     style=\"display: inline-block; padding: 12px 24px; background: #24292e; color: white; text-decoration: none; border-radius: 6px; font-size: 16px;\">
    Sign in with GitHub
  </a>
</body>
</html>",
    200,
  )
}

/// Success page showing authenticated user info.
pub fn success(auth: Auth) -> wisp.Response {
  let name = option_or(auth.info.name, "—")
  let email = option_or(auth.info.email, "—")
  let nickname = option_or(auth.info.nickname, "—")
  let image_html = case auth.info.image {
    Some(url) ->
      "<img src=\""
      <> url
      <> "\" width=\"80\" height=\"80\" style=\"border-radius: 50%;\" />"
    None -> ""
  }
  wisp.html_response(
    "<html>
<head><title>Authenticated — Vestibule Demo</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto;\">
  <h1>Authenticated!</h1>
  "
      <> image_html
      <> "
  <table style=\"margin: 20px 0; border-collapse: collapse;\">
    <tr><td style=\"padding: 8px; font-weight: bold;\">Provider</td><td style=\"padding: 8px;\">"
      <> auth.provider
      <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">UID</td><td style=\"padding: 8px;\">"
      <> auth.uid
      <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">Name</td><td style=\"padding: 8px;\">"
      <> name
      <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">Email</td><td style=\"padding: 8px;\">"
      <> email
      <> "</td></tr>
    <tr><td style=\"padding: 8px; font-weight: bold;\">Nickname</td><td style=\"padding: 8px;\">"
      <> nickname
      <> "</td></tr>
  </table>
  <a href=\"/\">Back to home</a>
</body>
</html>",
    200,
  )
}

/// Error page.
pub fn error(err: AuthError) -> wisp.Response {
  let message = case err {
    error.StateMismatch -> "State mismatch — possible CSRF attack"
    error.CodeExchangeFailed(reason:) -> "Code exchange failed: " <> reason
    error.UserInfoFailed(reason:) -> "User info fetch failed: " <> reason
    error.ProviderError(code:, description:) ->
      "Provider error [" <> code <> "]: " <> description
    error.NetworkError(reason:) -> "Network error: " <> reason
    error.ConfigError(reason:) -> "Configuration error: " <> reason
  }
  wisp.html_response(
    "<html>
<head><title>Error — Vestibule Demo</title></head>
<body style=\"font-family: system-ui, sans-serif; max-width: 600px; margin: 80px auto;\">
  <h1>Authentication Failed</h1>
  <p style=\"color: #c0392b;\">"
      <> message
      <> "</p>
  <a href=\"/\">Try again</a>
</body>
</html>",
    400,
  )
}

fn option_or(opt: Option(String), default: String) -> String {
  case opt {
    Some(value) -> value
    None -> default
  }
}
