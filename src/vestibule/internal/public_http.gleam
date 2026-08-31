import gleam/http/request.{type Request}
import gleam/http/response.{type Response}

pub type SendError {
  UnsafeTarget(reason: String)
  NetworkFailure(reason: String)
}

@external(erlang, "vestibule_public_http_ffi", "validate_host")
pub fn validate_host(host: String) -> Result(Nil, String)

@external(erlang, "vestibule_public_http_ffi", "send")
pub fn send(
  request: Request(String),
  response_body_limit: Int,
) -> Result(Response(String), SendError)

@external(erlang, "vestibule_public_http_ffi", "validate_host_format")
pub fn validate_host_format(host: String) -> Result(Nil, String)

@external(erlang, "vestibule_public_http_ffi", "address_is_global")
pub fn address_is_global(address: String) -> Bool

@external(erlang, "vestibule_public_http_ffi", "validate_addresses")
pub fn validate_addresses(
  host: String,
  addresses: List(String),
) -> Result(Nil, String)
