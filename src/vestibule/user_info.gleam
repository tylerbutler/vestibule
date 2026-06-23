//// Normalized user profile returned by a provider's userinfo endpoint or
//// extracted from an ID token. Provider-specific fields land in `extra`.

import gleam/dict.{type Dict}
import gleam/option.{type Option, None}

/// Normalized user information across all providers.
///
/// Opaque so the field set can grow in future releases without breaking
/// callers that construct or pattern-match the value. Build instances with
/// `new` plus the `with_*` helpers, and read fields with the accessors.
pub opaque type UserInfo {
  UserInfo(
    name: Option(String),
    /// Email address accepted by the strategy for identity use.
    ///
    /// Strategies should only populate this field when the provider has
    /// verified the address. If a provider reports an unverified email, or
    /// does not provide enough verification information for the strategy to
    /// trust it, the strategy should leave it as `None`.
    email: Option(String),
    nickname: Option(String),
    image: Option(String),
    description: Option(String),
    urls: Dict(String, String),
  )
}

/// Construct empty user information. Add fields with the `with_*` helpers.
pub fn new() -> UserInfo {
  UserInfo(
    name: None,
    email: None,
    nickname: None,
    image: None,
    description: None,
    urls: dict.new(),
  )
}

/// Set the display name.
pub fn with_name(info: UserInfo, name: Option(String)) -> UserInfo {
  UserInfo(..info, name: name)
}

/// Set the verified email address.
///
/// Strategies should only set this when the provider has verified the
/// address; otherwise leave it unset.
pub fn with_email(info: UserInfo, email: Option(String)) -> UserInfo {
  UserInfo(..info, email: email)
}

/// Set the nickname or handle.
pub fn with_nickname(info: UserInfo, nickname: Option(String)) -> UserInfo {
  UserInfo(..info, nickname: nickname)
}

/// Set the avatar image URL.
pub fn with_image(info: UserInfo, image: Option(String)) -> UserInfo {
  UserInfo(..info, image: image)
}

/// Set the profile description or bio.
pub fn with_description(
  info: UserInfo,
  description: Option(String),
) -> UserInfo {
  UserInfo(..info, description: description)
}

/// Set the map of named profile URLs.
pub fn with_urls(info: UserInfo, urls: Dict(String, String)) -> UserInfo {
  UserInfo(..info, urls: urls)
}

/// Return the display name, when the provider supplied one.
pub fn name(info: UserInfo) -> Option(String) {
  info.name
}

/// Return the verified email address, when one is available.
pub fn email(info: UserInfo) -> Option(String) {
  info.email
}

/// Return the nickname or handle, when the provider supplied one.
pub fn nickname(info: UserInfo) -> Option(String) {
  info.nickname
}

/// Return the avatar image URL, when the provider supplied one.
pub fn image(info: UserInfo) -> Option(String) {
  info.image
}

/// Return the profile description, when the provider supplied one.
pub fn description(info: UserInfo) -> Option(String) {
  info.description
}

/// Return the map of named profile URLs.
pub fn urls(info: UserInfo) -> Dict(String, String) {
  info.urls
}
