import gleam/option.{None, Some}
import gleam/string

import vestibule/error
import vestibule_indieauth/discovery.{
  type DiscoveredEndpoints, DiscoveredEndpoints,
}
import vestibule_indieauth/profile

const me = "https://me.example.com/"

fn endpoints() -> DiscoveredEndpoints {
  DiscoveredEndpoints(
    authorization_endpoint: "https://auth.example.com/authorize",
    token_endpoint: "https://auth.example.com/token",
    issuer: Some("https://auth.example.com/"),
    userinfo_endpoint: Some("https://auth.example.com/userinfo"),
  )
}

fn never_rediscover(
  _url: String,
) -> Result(DiscoveredEndpoints, error.AuthError(e)) {
  panic as "rediscovery must not run when the returned me matches"
}

// === confirm_profile_url ===

pub fn identical_me_is_accepted_without_rediscovery_test() -> Nil {
  profile.confirm_profile_url(
    expected_me: me,
    returned_me: me,
    endpoints: endpoints(),
    rediscover: never_rediscover,
  )
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == me
  }
}

pub fn canonically_equal_me_is_accepted_without_rediscovery_test() -> Nil {
  // Host case and the trailing slash are normalised by canonicalization.
  profile.confirm_profile_url(
    expected_me: me,
    returned_me: "https://ME.example.com",
    endpoints: endpoints(),
    rediscover: never_rediscover,
  )
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == me
  }
}

pub fn different_me_on_same_server_is_accepted_test() -> Nil {
  // A multi-user authorization server may return the profile URL of the
  // account that actually authenticated (IndieAuth §5.3.4).
  let returned = "https://other.example.com/"
  profile.confirm_profile_url(
    expected_me: me,
    returned_me: returned,
    endpoints: endpoints(),
    rediscover: fn(url) {
      url
      |> fn(actual) {
        assert actual == returned
      }
      Ok(endpoints())
    },
  )
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == returned
  }
}

pub fn different_me_with_different_authorization_endpoint_is_rejected_test() -> Nil {
  let result =
    profile.confirm_profile_url(
      expected_me: me,
      returned_me: "https://victim.example.com/",
      endpoints: endpoints(),
      rediscover: fn(_) {
        Ok(
          DiscoveredEndpoints(
            ..endpoints(),
            authorization_endpoint: "https://victim-auth.example.com/authorize",
          ),
        )
      },
    )
  let assert Error(err) = result
  error.kind(err)
  |> fn(actual) {
    assert actual == error.UserInfoKind
  }
  error.message(err)
  |> string.contains("authorization server")
  |> fn(actual) {
    assert actual
  }
}

pub fn different_me_with_different_token_endpoint_is_rejected_test() -> Nil {
  // Matching only the authorization endpoint is not enough: an attacker whose
  // metadata points at a shared authorization endpoint but their own token
  // endpoint could otherwise assert any `me`.
  let result =
    profile.confirm_profile_url(
      expected_me: me,
      returned_me: "https://victim.example.com/",
      endpoints: endpoints(),
      rediscover: fn(_) {
        Ok(
          DiscoveredEndpoints(
            ..endpoints(),
            token_endpoint: "https://victim-auth.example.com/token",
          ),
        )
      },
    )
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn different_me_that_fails_rediscovery_is_rejected_test() -> Nil {
  let result =
    profile.confirm_profile_url(
      expected_me: me,
      returned_me: "https://victim.example.com/",
      endpoints: endpoints(),
      rediscover: fn(_) { Error(error.network(reason: "boom")) },
    )
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn invalid_returned_me_is_rejected_test() -> Nil {
  let result =
    profile.confirm_profile_url(
      expected_me: me,
      returned_me: "https://127.0.0.1/",
      endpoints: endpoints(),
      rediscover: fn(_) { Ok(endpoints()) },
    )
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

// === require_same_profile_url ===

pub fn require_same_profile_url_accepts_canonical_match_test() -> Nil {
  profile.require_same_profile_url(
    expected_me: me,
    actual_me: "https://ME.example.com",
  )
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == me
  }
}

pub fn require_same_profile_url_rejects_mismatch_test() -> Nil {
  let result =
    profile.require_same_profile_url(
      expected_me: me,
      actual_me: "https://victim.example.com/",
    )
  let assert Error(err) = result
  error.kind(err)
  |> fn(actual) {
    assert actual == error.UserInfoKind
  }
}

pub fn require_same_profile_url_rejects_invalid_test() -> Nil {
  let result =
    profile.require_same_profile_url(expected_me: me, actual_me: "not a url#x")
  let _ =
    result
    |> fn(result) {
      let assert Error(value) = result
      value
    }
  Nil
}

pub fn none_userinfo_is_fine_test() -> Nil {
  // Sanity check that the fixture with no userinfo endpoint still compares
  // equal to itself through the full-record comparison.
  let no_userinfo = DiscoveredEndpoints(..endpoints(), userinfo_endpoint: None)
  profile.confirm_profile_url(
    expected_me: me,
    returned_me: "https://other.example.com/",
    endpoints: no_userinfo,
    rediscover: fn(_) { Ok(no_userinfo) },
  )
  |> fn(result) {
    let assert Ok(value) = result
    value
  }
  |> fn(actual) {
    assert actual == "https://other.example.com/"
  }
}
