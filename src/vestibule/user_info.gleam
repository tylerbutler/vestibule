import gleam/dict.{type Dict}
import gleam/option.{type Option}

/// Normalized user information across all providers.
pub type UserInfo {
  UserInfo(
    name: Option(String),
    email: Option(String),
    nickname: Option(String),
    image: Option(String),
    description: Option(String),
    urls: Dict(String, String),
  )
}
