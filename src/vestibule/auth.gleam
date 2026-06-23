//// Authentication result types returned to the calling application after a
//// successful OAuth/OIDC flow.

import gleam/dict.{type Dict}
import gleam/dynamic.{type Dynamic}
import vestibule/credentials.{type Credentials}
import vestibule/user_info.{type UserInfo}

/// The normalized result of a successful authentication.
///
/// Opaque so the field set can grow in future releases without breaking
/// callers that construct or pattern-match the value. Build instances with
/// `new` and read fields with the accessors.
pub opaque type Auth {
  Auth(
    uid: String,
    provider: String,
    info: UserInfo,
    credentials: Credentials,
    extra: Dict(String, Dynamic),
  )
}

/// Construct an authentication result.
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

/// Return the unique identifier from the provider (e.g., GitHub user ID).
pub fn uid(auth: Auth) -> String {
  auth.uid
}

/// Return the provider name matching the strategy.
pub fn provider(auth: Auth) -> String {
  auth.provider
}

/// Return the normalized user information.
pub fn info(auth: Auth) -> UserInfo {
  auth.info
}

/// Return the OAuth credentials (tokens, expiry).
pub fn credentials(auth: Auth) -> Credentials {
  auth.credentials
}

/// Return the provider-specific extra data.
pub fn extra(auth: Auth) -> Dict(String, Dynamic) {
  auth.extra
}
