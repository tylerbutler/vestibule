import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}

pub type ApiError {
  RequestFailed(status: Int)
}

pub fn create_user(
  client: fn(Request(String)) -> Response(String),
  name: String,
) -> Result(String, ApiError) {
  let outbound_request =
    request.new()
    |> request.set_method(http.Post)
    |> request.set_path("/users")
    |> request.set_body(name)
  let response = client(outbound_request)
  case response.status {
    201 -> Ok(response.body)
    status -> Error(RequestFailed(status))
  }
}
