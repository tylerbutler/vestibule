---
title: "vestibule_indieauth/url"
description: "URL validation and canonicalization for IndieAuth."
nav:
  group: Reference
  groupOrder: 20
  order: 32
  label: "vestibule_indieauth/url"
toc:
  - href: "#functions"
    label: "Functions"
searchTerms:
  - api
  - reference
  - module
  - vestibule_indieauth/url
---

# `vestibule_indieauth/url`

URL validation and canonicalization for IndieAuth.

Implements the URL requirements from the IndieAuth specification:
- Section 3.2: User Profile URL
- Section 3.3: Client Identifier
- Section 3.4: URL Canonicalization

## Functions

### `canonicalize`

Canonicalize a URL per IndieAuth spec Section 3.4.

- If no scheme, prepend `https://`
- If no path, append `/`
- Lowercase the host

An explicitly supplied non-HTTPS scheme is preserved so validation can
reject it rather than silently changing the claimed identity.

```gleam
pub fn canonicalize(String) -> String
```

### `validate_profile_url`

Validate a user profile URL per IndieAuth spec Section 3.2.

Profile URLs MUST:
- Have an `https` scheme
- Contain a path component (`/` is valid)
- Not contain single-dot or double-dot path segments
- Not contain a fragment
- Not contain a username or password
- Not contain a port
- Have a domain name host (not an IP address)

Additionally, because the profile URL is fetched server-side during
discovery, `localhost`, `*.local`, and other non-public hosts are
rejected so the login form cannot be used to reach internal services.

```gleam
pub fn validate_profile_url(String) -> Result(String, error.AuthError(a))
```
