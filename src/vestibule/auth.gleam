import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import vestibule/credentials.{type Credentials}
import vestibule/user_info.{type UserInfo}

/// The normalized result of a successful authentication.
pub type Auth {
  Auth(
    /// Unique identifier from the provider (e.g., GitHub user ID).
    uid: String,
    /// Provider name matching the strategy.
    provider: String,
    /// Normalized user information.
    info: UserInfo,
    /// OAuth credentials (tokens, expiry).
    credentials: Credentials,
    /// Provider-specific extra data.
    extra: Dict(String, Dynamic),
  )
}
