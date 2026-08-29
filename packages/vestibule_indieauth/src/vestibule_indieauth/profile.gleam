//// Profile URL confirmation for the IndieAuth callback phase.
////
//// The `me` a user types into the login form is only a *claim*. The identity
//// that must be trusted is the profile URL the authorization server returns
//// in the token response — and only after confirming that URL is really
//// served by the same authorization server the flow ran against (IndieAuth
//// §5.3.4, "Authorization Server Confirmation"). Without this check, any
//// token or userinfo endpoint could assert an arbitrary `me` and log the
//// caller in as somebody else.

import vestibule/error.{type AuthError}
import vestibule_indieauth/discovery.{type DiscoveredEndpoints}
import vestibule_indieauth/url

/// Confirm the profile URL returned by the authorization server.
///
/// - If `returned_me` canonicalizes to `expected_me`, it is accepted as-is.
/// - Otherwise the returned URL is re-discovered with `rediscover` and is
///   accepted only when it advertises exactly the same endpoint set that
///   this flow used. Comparing the full set (not just the authorization
///   endpoint) matters: an attacker whose metadata borrows a shared
///   authorization endpoint but supplies their own token endpoint must not be
///   able to assert a `me` that the shared server never authenticated.
///
/// Returns the canonical, confirmed profile URL to use as the user's identity.
pub fn confirm_profile_url(
  expected_me expected_me: String,
  returned_me returned_me: String,
  endpoints endpoints: DiscoveredEndpoints,
  rediscover rediscover: fn(String) -> Result(DiscoveredEndpoints, AuthError(e)),
) -> Result(String, AuthError(e)) {
  case url.validate_profile_url(returned_me) {
    Error(_) ->
      Error(error.user_info(
        reason: "Authorization server returned an invalid profile URL: "
        <> returned_me,
      ))
    Ok(canonical) if canonical == expected_me -> Ok(canonical)
    Ok(canonical) ->
      case rediscover(canonical) {
        Ok(discovered) if discovered == endpoints -> Ok(canonical)
        Ok(_) ->
          Error(error.user_info(
            reason: "Returned profile URL "
            <> canonical
            <> " is not served by the authorization server this flow used",
          ))
        Error(_) ->
          Error(error.user_info(
            reason: "Could not confirm the authorization server for returned profile URL "
            <> canonical,
          ))
      }
  }
}

/// Require `actual_me` to canonicalize to the already-confirmed
/// `expected_me`. Used for the userinfo endpoint, which is not permitted to
/// change the identity established during the token exchange.
pub fn require_same_profile_url(
  expected_me expected_me: String,
  actual_me actual_me: String,
) -> Result(String, AuthError(e)) {
  case url.validate_profile_url(actual_me) {
    Ok(canonical) if canonical == expected_me -> Ok(canonical)
    Ok(canonical) ->
      Error(error.user_info(
        reason: "Profile URL "
        <> canonical
        <> " does not match the confirmed identity "
        <> expected_me,
      ))
    Error(_) ->
      Error(error.user_info(reason: "Invalid profile URL: " <> actual_me))
  }
}
