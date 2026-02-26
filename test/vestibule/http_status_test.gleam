/// Tests for HTTP response status checking before parsing.
///
/// Verifies that non-2xx HTTP responses produce meaningful HttpError
/// errors instead of confusing parse failures.
import startest/expect
import vestibule/error

// ===========================================================================
// check_http_status helper tests
// ===========================================================================

pub fn check_http_status_200_returns_ok_test() {
  error.check_http_status(200, "{\"ok\":true}")
  |> expect.to_be_ok()
  |> expect.to_equal("{\"ok\":true}")
}

pub fn check_http_status_201_returns_ok_test() {
  error.check_http_status(201, "created")
  |> expect.to_be_ok()
  |> expect.to_equal("created")
}

pub fn check_http_status_299_returns_ok_test() {
  error.check_http_status(299, "edge case")
  |> expect.to_be_ok()
  |> expect.to_equal("edge case")
}

pub fn check_http_status_500_returns_error_test() {
  error.check_http_status(
    500,
    "<html><body>Internal Server Error</body></html>",
  )
  |> expect.to_be_error()
  |> expect.to_equal(error.HttpError(
    status: 500,
    body: "<html><body>Internal Server Error</body></html>",
  ))
}

pub fn check_http_status_302_returns_error_test() {
  error.check_http_status(302, "Redirecting...")
  |> expect.to_be_error()
  |> expect.to_equal(error.HttpError(status: 302, body: "Redirecting..."))
}

pub fn check_http_status_401_returns_error_test() {
  error.check_http_status(401, "{\"error\":\"unauthorized\"}")
  |> expect.to_be_error()
  |> expect.to_equal(error.HttpError(
    status: 401,
    body: "{\"error\":\"unauthorized\"}",
  ))
}

pub fn check_http_status_403_returns_error_test() {
  error.check_http_status(403, "Forbidden")
  |> expect.to_be_error()
  |> expect.to_equal(error.HttpError(status: 403, body: "Forbidden"))
}

pub fn check_http_status_404_returns_error_test() {
  error.check_http_status(404, "Not Found")
  |> expect.to_be_error()
  |> expect.to_equal(error.HttpError(status: 404, body: "Not Found"))
}

pub fn check_http_status_199_returns_error_test() {
  error.check_http_status(199, "below range")
  |> expect.to_be_error()
  |> expect.to_equal(error.HttpError(status: 199, body: "below range"))
}

pub fn check_http_status_300_returns_error_test() {
  error.check_http_status(300, "above range")
  |> expect.to_be_error()
  |> expect.to_equal(error.HttpError(status: 300, body: "above range"))
}

pub fn check_http_status_503_service_unavailable_test() {
  let html_body =
    "<html><head><title>503 Service Temporarily Unavailable</title></head><body><h1>503</h1></body></html>"
  error.check_http_status(503, html_body)
  |> expect.to_be_error()
  |> expect.to_equal(error.HttpError(status: 503, body: html_body))
}

// ===========================================================================
// map_custom preserves HttpError
// ===========================================================================

pub fn map_custom_preserves_http_error_test() {
  let err: error.AuthError(Int) = error.HttpError(status: 500, body: "error")
  error.map_custom(err, fn(x) { x + 1 })
  |> expect.to_equal(error.HttpError(status: 500, body: "error"))
}
