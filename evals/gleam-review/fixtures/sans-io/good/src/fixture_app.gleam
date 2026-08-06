import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}

pub type ApiError {
  RequestFailed(status: Int)
}

pub fn create_user_request(name: String) -> Request(String) {
  request.new()
  |> request.set_method(http.Post)
  |> request.set_path("/users")
  |> request.set_body(name)
}

pub fn create_user_response(
  response: Response(String),
) -> Result(String, ApiError) {
  case response.status {
    201 -> Ok(response.body)
    status -> Error(RequestFailed(status))
  }
}
