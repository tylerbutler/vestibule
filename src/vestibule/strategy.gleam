import vestibule/config.{type Config}
import vestibule/credentials.{type Credentials}
import vestibule/error.{type AuthError}
import vestibule/user_info.{type UserInfo}

/// A strategy is a record containing the functions needed
/// to authenticate with a specific provider.
pub type Strategy {
  Strategy(
    /// Human-readable provider name (e.g., "github", "google").
    provider: String,
    /// Default scopes for this provider.
    default_scopes: List(String),
    /// Build the authorization URL to redirect the user to.
    /// Parameters: config, scopes, state.
    authorize_url: fn(Config, List(String), String) ->
      Result(String, AuthError),
    /// Exchange an authorization code for credentials.
    exchange_code: fn(Config, String) -> Result(Credentials, AuthError),
    /// Fetch user info using the obtained credentials.
    /// Returns #(uid, user_info).
    fetch_user: fn(Credentials) -> Result(#(String, UserInfo), AuthError),
  )
}
