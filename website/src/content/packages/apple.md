---
name: vestibule_apple
navLabel: Apple strategy
kind: Provider strategy
summary: Sign in with Apple strategy with JWKS-backed ID token verification and form_post callback support.
install:
  - gleam add vestibule_apple
useWhen: Use Apple when your application needs Sign in with Apple for web clients and can generate a client-secret JWT.
defaultScopes: name email
setup:
  - Create an Apple App ID and enable Sign In with Apple.
  - Create a Services ID for the OAuth client_id.
  - Register an HTTPS return URL; Apple does not allow localhost callbacks.
  - Create a Sign in with Apple key and generate an ES256 client-secret JWT.
highlights:
  - init initializes the JWKS cache used to verify Apple ID tokens.
  - try_init lets applications handle duplicate initialization explicitly.
  - Apple sends name and email only on first consent.
  - User info comes from the verified id_token, not a userinfo endpoint.
code: |
  import vestibule_apple

  let apple = vestibule_apple.init()
  let strategy = vestibule_apple.strategy(apple)

  let assert Ok(checked_apple) = vestibule_apple.try_init()
  let checked_strategy = vestibule_apple.strategy(checked_apple)
notes:
  - Apple client_secret values are JWTs generated from Team ID, Key ID, Services ID, and the .p8 private key.
  - Do not commit the Apple private key; generate the client-secret JWT in your app or deployment pipeline.
navOrder: 60
searchTerms:
  - sign in with apple
  - jwks
  - id token
  - form_post
  - client secret jwt
---
