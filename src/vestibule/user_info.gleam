//// Normalized user profile returned by a provider's userinfo endpoint or
//// extracted from an ID token. Provider-specific fields land in `extra`.

import gleam/dict.{type Dict}
import gleam/option.{type Option}

/// Normalized user information across all providers.
pub type UserInfo {
  UserInfo(
    name: Option(String),
    /// Email address accepted by the strategy for identity use.
    ///
    /// Strategies should only populate this field when the provider has
    /// verified the address. If a provider reports an unverified email, or
    /// does not provide enough verification information for the strategy to
    /// trust it, the strategy should return `None`.
    email: Option(String),
    nickname: Option(String),
    image: Option(String),
    description: Option(String),
    urls: Dict(String, String),
  )
}
