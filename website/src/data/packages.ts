export type PackageDoc = {
  slug: string;
  name: string;
  kind: string;
  summary: string;
  install: string[];
  useWhen: string;
  defaultScopes?: string;
  setup: string[];
  highlights: string[];
  code: string;
  notes: string[];
};

export const packageDocs: PackageDoc[] = [
  {
    slug: "core",
    name: "vestibule",
    kind: "Core package",
    summary:
      "Core types, two-phase OAuth2 flow, PKCE, CSRF state, token refresh, OIDC discovery, shared state store, and built-in GitHub strategy.",
    install: ["gleam add vestibule"],
    useWhen:
      "Use the core package when you want direct control over request and callback phases, or when you are building your own transport integration.",
    defaultScopes: "GitHub uses user:email by default.",
    setup: [
      "Register a provider application and copy its client ID and secret.",
      "Create a config with the provider redirect URI.",
      "Store state and code_verifier server-side before redirecting.",
      "Delete state and code_verifier after a successful callback."
    ],
    highlights: [
      "PKCE is appended to every authorization URL.",
      "State validation happens before provider error details are surfaced.",
      "Strategies are values, not behaviours or macros.",
      "GitHub support ships in the core package."
    ],
    code: `import gleam/dict
import vestibule
import vestibule/config
import vestibule/strategy/github

let strategy = github.strategy()
let cfg =
  config.new(
    "client_id",
    "client_secret",
    "http://localhost:8000/auth/github/callback",
  )

let assert Ok(auth_request) = vestibule.authorize_url(strategy, cfg)
// Store auth_request.state and auth_request.code_verifier server-side.
// Redirect the user to auth_request.url.

let params =
  dict.from_list([
    #("state", "state from callback"),
    #("code", "authorization code from callback"),
  ])

let assert Ok(auth) =
  vestibule.handle_callback(
    strategy,
    cfg,
    params,
    "expected state from session",
    "code verifier from session",
  )`,
    notes: [
      "Production redirect URIs and OIDC issuers must use HTTPS.",
      "Redact Auth and Credentials values in logs; bearer tokens are secrets.",
      "OIDC nonce validation is currently left to the consuming app when it needs id_token replay protection beyond PKCE."
    ]
  },
  {
    slug: "wisp",
    name: "vestibule_wisp",
    kind: "Wisp middleware",
    summary:
      "Wisp request/callback routing for Vestibule, including signed session cookie handling and one-time ETS state storage.",
    install: [
      "gleam add vestibule",
      "gleam add vestibule_wisp",
      "gleam add wisp",
      "gleam add mist",
      "gleam add vestibule_google"
    ],
    useWhen:
      "Use Wisp middleware when your app already routes requests with Wisp and you want the request and callback phases handled for you.",
    setup: [
      "Configure Wisp with a strong, stable secret key base.",
      "Initialize the shared state store once per BEAM VM.",
      "Register one or more provider strategies in a registry.",
      "Route /auth/:provider and /auth/:provider/callback to the middleware."
    ],
    highlights: [
      "Handles both GET and POST callbacks; Apple uses response_mode=form_post.",
      "Default cookie name uses the __Host- prefix to defend against cookie tossing.",
      "Cookie TTL and server-side state-store TTL share the same value.",
      "Structured callback errors are available for custom handling."
    ],
    code: `import gleam/http
import wisp
import vestibule/config
import vestibule/registry
import vestibule/strategy/github
import vestibule/state_store
import vestibule_wisp

let assert Ok(reg) =
  registry.new()
  |> registry.register(
    github.strategy(),
    config.new(
      "client_id",
      "client_secret",
      "http://localhost:8000/auth/github/callback",
    ),
  )

let store = state_store.init()

case wisp.path_segments(req), req.method {
  ["auth", provider], http.Get ->
    vestibule_wisp.request_phase(req, reg, provider, store)

  ["auth", provider, "callback"], http.Get
  | ["auth", provider, "callback"], http.Post ->
    vestibule_wisp.callback_phase(req, reg, provider, store, on_success)

  _, _ ->
    wisp.not_found()
}`,
    notes: [
      "Keep the __Host- prefix on custom cookie names.",
      "Use callback_phase_auth_result when your app needs structured logging or custom user-facing error recovery."
    ]
  },
  {
    slug: "mist",
    name: "vestibule_mist",
    kind: "Mist middleware",
    summary:
      "Plain Mist request/callback routing with HMAC-SHA256 signed session cookies and the shared Vestibule state store.",
    install: [
      "gleam add vestibule",
      "gleam add vestibule_mist",
      "gleam add mist",
      "gleam add vestibule_google"
    ],
    useWhen:
      "Use Mist middleware when you run directly on Mist and want the same auth ergonomics without Wisp.",
    setup: [
      "Load a high-entropy secret key base from configuration or a secrets manager.",
      "Create Options with vestibule_mist.new_options(secret_key_base).",
      "Initialize the shared state store once per BEAM VM.",
      "Dispatch request and callback paths from your Mist handler."
    ],
    highlights: [
      "No unsafe default secret; applications must supply one.",
      "Sets HttpOnly, SameSite=Lax, Path=/, and Secure by default.",
      "Supports GET and application/x-www-form-urlencoded POST callbacks.",
      "Structured callback errors mirror the Wisp integration."
    ],
    code: `import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import mist.{type Connection, type ResponseData}
import vestibule/state_store
import vestibule_mist

let assert Ok(store) = state_store.try_init()
let options = vestibule_mist.new_options(secret_key_base)

fn handle_request(req: Request(Connection)) -> Response(ResponseData) {
  case request.path_segments(req), req.method {
    ["auth", provider], http.Get ->
      vestibule_mist.request_phase(req, reg, provider, store, options)

    ["auth", provider, "callback"], http.Get
    | ["auth", provider, "callback"], http.Post ->
      vestibule_mist.callback_phase(req, reg, provider, store, options, on_success)

    _, _ ->
      not_found()
  }
}`,
    notes: [
      "Set secure_cookie: False only for local HTTP development.",
      "Changing the cookie secret invalidates in-flight OAuth callbacks."
    ]
  },
  {
    slug: "google",
    name: "vestibule_google",
    kind: "Provider strategy",
    summary:
      "Google OAuth strategy with verified-email handling, hosted-domain enforcement, and refresh-token guidance.",
    install: ["gleam add vestibule_google"],
    useWhen:
      "Use Google when users sign in with Google or Google Workspace accounts and your app needs normalized profile data.",
    defaultScopes: "openid email profile",
    setup: [
      "Create a Google Cloud project.",
      "Configure OAuth consent screen with openid, email, and profile scopes.",
      "Create a Web application OAuth client ID.",
      "Add development and HTTPS production redirect URIs exactly."
    ],
    highlights: [
      "UserInfo.email is only populated when email_verified is true.",
      "config.with_extra_params can request offline access.",
      "strategy_for_hosted_domain validates the hd claim server-side.",
      "The hd authorization parameter alone is only an account-picker hint."
    ],
    code: `import vestibule/config
import vestibule_google

let strategy = vestibule_google.strategy()
let cfg =
  config.new(
    "google-client-id",
    "google-client-secret",
    "http://localhost:8000/auth/google/callback",
  )

let workspace_strategy =
  vestibule_google.strategy_for_hosted_domain("corp.example")`,
    notes: [
      "Google only returns a refresh token on first consent for a client/user/scope combination.",
      "Use access_type=offline and prompt=consent when requesting refresh tokens."
    ]
  },
  {
    slug: "microsoft",
    name: "vestibule_microsoft",
    kind: "Provider strategy",
    summary:
      "Microsoft OAuth strategy using Microsoft Graph /me, with helpers for tenant-specific sign-in.",
    install: ["gleam add vestibule_microsoft"],
    useWhen:
      "Use Microsoft when users authenticate with Microsoft personal, work, or school accounts.",
    defaultScopes: "User.Read by default; tenant validation also requests openid.",
    setup: [
      "Create a Microsoft Entra ID app registration.",
      "Choose supported account types that match your tenant behavior.",
      "Add Web redirect URIs for development and production.",
      "Copy the Application client ID and client secret value."
    ],
    highlights: [
      "The default strategy uses /common and performs no tenant validation.",
      "strategy_for_tenant targets tenant-specific endpoints.",
      "Tenant validation checks the tid claim in the returned ID token.",
      "userPrincipalName is exposed as nickname, not verified email."
    ],
    code: `import vestibule/config
import vestibule_microsoft

let strategy = vestibule_microsoft.strategy()

let tenant_strategy =
  vestibule_microsoft.strategy_for_tenant(
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
  )

let cfg =
  config.new(
    "microsoft-client-id",
    "microsoft-client-secret",
    "http://localhost:8000/auth/microsoft/callback",
  )`,
    notes: [
      "Pass the tenant GUID, not a verified domain, when restricting to one tenant.",
      "Microsoft Graph /me does not include profile photos; fetch photos separately if needed."
    ]
  },
  {
    slug: "apple",
    name: "vestibule_apple",
    kind: "Provider strategy",
    summary:
      "Sign in with Apple strategy with JWKS-backed ID token verification and form_post callback support.",
    install: ["gleam add vestibule_apple"],
    useWhen:
      "Use Apple when your application needs Sign in with Apple for web clients and can generate a client-secret JWT.",
    defaultScopes: "name email",
    setup: [
      "Create an Apple App ID and enable Sign In with Apple.",
      "Create a Services ID for the OAuth client_id.",
      "Register an HTTPS return URL; Apple does not allow localhost callbacks.",
      "Create a Sign in with Apple key and generate an ES256 client-secret JWT."
    ],
    highlights: [
      "init initializes the JWKS cache used to verify Apple ID tokens.",
      "try_init lets applications handle duplicate initialization explicitly.",
      "Apple sends name and email only on first consent.",
      "User info comes from the verified id_token, not a userinfo endpoint."
    ],
    code: `import vestibule_apple

let apple = vestibule_apple.init()
let strategy = vestibule_apple.strategy(apple)

let assert Ok(checked_apple) = vestibule_apple.try_init()
let checked_strategy = vestibule_apple.strategy(checked_apple)`,
    notes: [
      "Apple client_secret values are JWTs generated from Team ID, Key ID, Services ID, and the .p8 private key.",
      "Do not commit the Apple private key; generate the client-secret JWT in your app or deployment pipeline."
    ]
  }
];

export const packageDocBySlug = new Map(packageDocs.map((doc) => [doc.slug, doc]));
