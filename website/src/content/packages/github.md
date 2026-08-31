---
name: vestibule_github
navLabel: GitHub strategy
kind: Provider strategy
summary: GitHub OAuth strategy with normalized profile data and verified-primary-email lookup.
install:
  - "[dependencies]"
  - 'vestibule_github = { git = "https://github.com/tylerbutler/vestibule.git", ref = "v0", path = "packages/vestibule_github" }'
useWhen: Use GitHub if users sign in with GitHub accounts. The strategy returns profile data and the verified primary email address when available.
defaultScopes: "user:email"
setup:
  - Create a GitHub OAuth App.
  - Set the exact authorization callback URL for each environment you demo from.
  - Copy the Client ID and generate a client secret.
  - Request user:email when you need private verified primary email lookup.
highlights:
  - Requests user:email by default.
  - Token scopes are parsed from GitHub's comma-separated scope response.
  - user_info.email is populated from the verified primary email endpoint when available.
  - The GitHub profile URL is exposed under the html_url key in user_info.urls.
code: |
  import vestibule/config
  import vestibule_github

  let strategy = vestibule_github.strategy()
  let client_config =
    config.new(
      client_id: "github-client-id",
      redirect_uri: "http://localhost:8000/auth/github/callback",
      auth: config.ClientSecret("github-client-secret"),
    )
notes:
  - GitHub can omit the public email address from /user. The strategy then tries the /user/emails endpoint.
  - Authentication can succeed if the email lookup fails. In this case, user_info.email returns None.
navOrder: 35
searchTerms:
  - github oauth app
  - verified primary email
  - user email
  - html_url
---
