//// Normalized user profile returned by a provider's userinfo endpoint or
//// extracted from an ID token. Provider-specific fields land in `extra`.

import gleam/dict.{type Dict}
import gleam/option.{type Option, None}

/// Normalized user information across all providers.
///
/// Opaque so new optional profile fields can be added without breaking custom
/// strategies or applications that construct and pattern-match user info.
/// Construct with `new`, update with `with_*` builders, and read fields with
/// accessors.
pub opaque type UserInfo {
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

/// Create empty normalized user info.
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

/// Set the user's display name.
pub fn with_name(info: UserInfo, name: Option(String)) -> UserInfo {
  UserInfo(..info, name: name)
}

/// Set the verified email address.
///
/// Pass `None` when the provider did not supply a verified email.
pub fn with_email(info: UserInfo, email: Option(String)) -> UserInfo {
  UserInfo(..info, email: email)
}

/// Set the user's provider-specific nickname or handle.
pub fn with_nickname(info: UserInfo, nickname: Option(String)) -> UserInfo {
  UserInfo(..info, nickname: nickname)
}

/// Set the user's profile image URL.
pub fn with_image(info: UserInfo, image: Option(String)) -> UserInfo {
  UserInfo(..info, image: image)
}

/// Set the user's profile description or bio.
pub fn with_description(
  info: UserInfo,
  description: Option(String),
) -> UserInfo {
  UserInfo(..info, description: description)
}

/// Replace the provider-specific profile URL map.
pub fn with_urls(info: UserInfo, urls: Dict(String, String)) -> UserInfo {
  UserInfo(..info, urls: urls)
}

/// Add or replace one provider-specific profile URL.
pub fn with_url(info: UserInfo, key: String, value: String) -> UserInfo {
  UserInfo(..info, urls: dict.insert(info.urls, key, value))
}

/// Return the user's display name.
pub fn name(info: UserInfo) -> Option(String) {
  info.name
}

/// Return the verified email address.
pub fn email(info: UserInfo) -> Option(String) {
  info.email
}

/// Return the provider-specific nickname or handle.
pub fn nickname(info: UserInfo) -> Option(String) {
  info.nickname
}

/// Return the profile image URL.
pub fn image(info: UserInfo) -> Option(String) {
  info.image
}

/// Return the profile description or bio.
pub fn description(info: UserInfo) -> Option(String) {
  info.description
}

/// Return provider-specific profile URLs.
pub fn urls(info: UserInfo) -> Dict(String, String) {
  info.urls
}
