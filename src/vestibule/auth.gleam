//// Authentication result types returned to the calling application after a
//// successful OAuth/OIDC flow.

import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import vestibule/credentials.{type Credentials}
import vestibule/user_info.{type UserInfo}

/// The normalized result of a successful authentication.
///
/// Opaque so future authentication metadata can be added without breaking
/// applications that construct or pattern-match callback results. Construct
/// with `new` and read fields with accessors.
pub opaque type Auth {
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

/// Build an authentication result.
pub fn new(
  uid uid: String,
  provider provider: String,
  info info: UserInfo,
  credentials credentials: Credentials,
  extra extra: Dict(String, Dynamic),
) -> Auth {
  Auth(
    uid: uid,
    provider: provider,
    info: info,
    credentials: credentials,
    extra: extra,
  )
}

/// Return the provider's unique user id.
pub fn uid(auth: Auth) -> String {
  auth.uid
}

/// Return the provider name that authenticated the user.
pub fn provider(auth: Auth) -> String {
  auth.provider
}

/// Return normalized user information.
pub fn info(auth: Auth) -> UserInfo {
  auth.info
}

/// Return OAuth credentials.
pub fn credentials(auth: Auth) -> Credentials {
  auth.credentials
}

/// Return provider-specific extra data.
pub fn extra(auth: Auth) -> Dict(String, Dynamic) {
  auth.extra
}
