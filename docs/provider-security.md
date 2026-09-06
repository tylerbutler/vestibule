# Provider security requirements

Vestibule is demo-ready OAuth sign-in for demos and prototypes. It has not
been security audited and is not production-ready.

This matrix records the protocol requirements used by the provider
implementations and tests. “Required” means that a callback must fail when the
evidence is absent or invalid.

| Provider | Normative requirement | Vestibule check |
| --- | --- | --- |
| Apple | Verify the ID-token signature with Apple’s current JWKS key selected by `kid`; require RSA/RS256; reject an unknown `kid`. Refresh JWKS once after a cached-key miss to support key rotation. | `vestibule_apple` pins RS256, validates the signature, refreshes cached keys after `NoMatchingKey`, then fails closed. |
| Apple | Require `iss=https://appleid.apple.com`, the configured client ID in `aud`, a current `exp`, a stable `sub`, and the request `nonce`. | ID-token verification requires issuer, audience, expiration, and subject. The core binds the nonce before it returns callback success. |
| Apple | Use `response_mode=form_post` when requesting scopes. | The authorization URL always includes `response_mode=form_post`. |
| Google | Validate the ID-token signature and require Google issuer, configured client ID audience, expiration, subject, and nonce. | Integration waits for the shared OIDC verifier. |
| Google | Use the verified ID-token `hd` claim for Workspace restrictions. The authorization request `hd` parameter is only a hint. | Integration waits for the shared OIDC verifier; userinfo `hd` is not sufficient. |
| Google | Userinfo may enrich a user but must not replace the identity established by the verified ID-token `sub`. Trust email only when `email_verified=true`. | Integration waits for verified-ID-token subject binding. Existing parsing omits unverified email. |
| Microsoft | Validate the ID-token signature, algorithm, issuer, audience, time claims, nonce, and tenant claim. A tenant-specific v2 token issuer is `https://login.microsoftonline.com/{tid}/v2.0`. | Integration waits for the shared OIDC verifier. The unsigned `verify_tenant` API must be removed during integration. |
| Microsoft | Bind Microsoft Graph `/me` to the verified token identity. `oid` is the tenant-stable object identifier and Graph `/me.id` must not change the authenticated identity. | Integration waits for verified-ID-token `oid` binding. |
| GitHub | Require a Bearer access token and confirm the granted scopes. `/user/emails` supplies a primary verified email when `user:email` or its parent `user` scope is granted. | Authorization-code responses require Bearer plus `user:email` or `user`. Callback user assembly fails without a primary verified email and keeps `/user.id` as the identity. |
| GitHub | Expiring access tokens can return rotating refresh tokens. A refresh response can omit `scope`; use the replacement refresh token when present. | Refresh parsing accepts an omitted scope, requires Bearer, and preserves the replacement refresh token. |
| IndieAuth | Clients must use PKCE and verify callback `state`. If server metadata supplied an issuer, callback `iss` must match it by exact string comparison. | The core requires PKCE and state. Callback issuer comparison needs a callback-validator hook and remains a blocking gap. |
| IndieAuth | The token response must contain the canonical `me`. If it differs from the entered URL, rediscover it and confirm the same authorization server. A later userinfo response must not replace that identity. | The strategy requires and canonicalizes `me`, confirms the discovered endpoint set, uses confirmed `me` as `uid`, and rejects a different userinfo `me`. |
| IndieAuth | Dynamically discovered token, metadata, issuer, and userinfo endpoints must use public HTTPS; redirects must not bypass this rule. | Discovery and request sending validate public HTTPS, DNS answers, redirect targets, and response limits. |

## Normative sources

- Apple: [Fetch Apple’s public key for verifying token signature](https://developer.apple.com/documentation/signinwithapplerestapi/fetch-apple-s-public-key-for-verifying-token-signature), [Sign in with Apple REST API](https://developer.apple.com/documentation/signinwithapplerestapi)
- Google: [OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect#validatinganidtoken)
- Microsoft: [ID tokens](https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens), [ID-token claims](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference)
- GitHub: [Authorizing OAuth apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps), [REST email endpoints](https://docs.github.com/en/rest/users/emails)
- IndieAuth: [IndieAuth specification, section 5](https://indieauth.spec.indieweb.org/#authorization)
