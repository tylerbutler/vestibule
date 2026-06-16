---
name: vestibule_github
navLabel: GitHub strategy
kind: Provider strategy
summary: GitHub OAuth strategy with normalized profile data and verified-primary-email lookup.
install:
  - gleam add vestibule_github
useWhen: Use GitHub when users sign in with GitHub accounts and your app needs profile data plus the user's verified primary email when available.
defaultScopes: "user:email"
setup:
  - Create a GitHub OAuth App.
  - Set the Authorization callback URL exactly for development and production.
  - Copy the Client ID and generate a client secret.
  - Request user:email when you need private verified primary email lookup.
highlights:
  - Requests user:email by default.
  - Token scopes are parsed from GitHub's comma-separated scope response.
  - UserInfo.email is populated from the verified primary email endpoint when available.
  - The GitHub profile URL is exposed under the html_url key in UserInfo.urls.
code: |
  import vestibule/config
  import vestibule_github

  let strategy = vestibule_github.strategy()
  let cfg =
    config.new(
      "github-client-id",
      "github-client-secret",
      "http://localhost:8000/auth/github/callback",
    )
notes:
  - GitHub may omit public email from /user; the strategy performs a best-effort /user/emails lookup.
  - If the email lookup fails, authentication can still succeed with UserInfo.email set to None.
navOrder: 35
searchTerms:
  - github oauth app
  - verified primary email
  - user email
  - html_url
---
