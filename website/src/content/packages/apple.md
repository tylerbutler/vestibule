---
name: vestibule_apple
navLabel: Apple strategy
kind: Provider strategy
summary: Sign in with Apple strategy that verifies ID tokens with JWKS and supports form_post callbacks.
install:
  - "[dependencies]"
  - 'vestibule_apple = { git = "https://github.com/tylerbutler/vestibule.git", ref = "vestibule-v0.0", path = "packages/vestibule_apple" }'
useWhen: Use Apple if your web application needs Sign in with Apple and can generate a client-secret JWT.
defaultScopes: name email
setup:
  - Create an Apple App ID and enable Sign In with Apple.
  - Create a Services ID for the OAuth client_id.
  - Register an HTTPS return URL. Apple does not permit localhost callbacks.
  - Create a Sign in with Apple key and generate an ES256 client-secret JWT.
highlights:
  - init initializes the JWKS cache used to verify Apple ID tokens.
  - Use try_init to handle duplicate initialization explicitly.
  - Apple sends name and email only on first consent.
  - User info comes from the verified id_token, not a userinfo endpoint.
code: |
  import vestibule_apple

  let assert Ok(apple) = vestibule_apple.try_init()
  let strategy = vestibule_apple.strategy(apple)
notes:
  - Generate the client_secret JWT from the Team ID, Key ID, Services ID, and .p8 private key.
  - Do not commit the Apple private key. Generate the client-secret JWT in your app or deployment pipeline.
navOrder: 60
searchTerms:
  - sign in with apple
  - jwks
  - id token
  - form_post
  - client secret jwt
---
