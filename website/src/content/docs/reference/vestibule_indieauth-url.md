---
title: "vestibule_indieauth/url"
description: "Reference for vestibule_indieauth/url."
nav:
  group: Reference
  groupOrder: 20
  order: 31
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

Reference for vestibule_indieauth/url.

## Functions

### `canonicalize`

Canonicalize a URL per IndieAuth spec Section 3.4.

- If no scheme, prepend `https://`
- If no path, append `/`
- Lowercase the host

```gleam
pub fn canonicalize(String) -> String
```

### `validate_profile_url`

Validate a user profile URL per IndieAuth spec Section 3.2.

Profile URLs MUST:
- Have `https` or `http` scheme
- Contain a path component (`/` is valid)
- Not contain single-dot or double-dot path segments
- Not contain a fragment
- Not contain a username or password
- Not contain a port
- Have a domain name host (not an IP address)

```gleam
pub fn validate_profile_url(String) -> Result(String, error.AuthError(a))
```
