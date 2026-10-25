import gleam/http
import gleam/option
import gleam/result
import wisp.{type Request, type Response}

import vestibule/config
import vestibule/error
import vestibule/registry.{type Registry}
import vestibule/state_store.{type StateStore}
import vestibule_example/page
import vestibule_wisp

/// Application context passed to the router.
pub type Context(e) {
  Context(
    registry: Registry(e),
    state_store: StateStore,
    auth_routes: vestibule_wisp.RouteMount(e),
  )
}

/// Configure the example's high-level auth mount once.
pub fn new_context(
  registry: Registry(e),
  state_store: StateStore,
) -> Result(Context(e), vestibule_wisp.RouteMountError) {
  vestibule_wisp.new_route_mount(
    "/auth",
    registry: registry,
    state_store: state_store,
    authorize_options: config.authorize_options(),
    middleware_options: local_http_options(),
    on_success: page.success,
    on_error: fn(_, recovery) {
      wisp.html_response(
        "Authentication failed ("
          <> error.recovery_code(recovery)
          <> "): "
          <> error.recovery_summary(recovery),
        error.recovery_http_status(recovery),
      )
    },
  )
  |> result.map(fn(auth_routes) {
    Context(
      registry: registry,
      state_store: state_store,
      auth_routes: auth_routes,
    )
  })
}

/// Route incoming requests.
pub fn handle_request(request: Request, context: Context(e)) -> Response {
  handle_request_for_client(request, context, client_key: "unidentified")
}

/// Route incoming requests using a trusted direct-client admission key.
pub fn handle_request_for_client(
  request: Request,
  context: Context(e),
  client_key client_key: String,
) -> Response {
  use <- wisp.log_request(request)

  case
    vestibule_wisp.route_for_client(request, context.auth_routes, client_key)
  {
    option.Some(response) -> response
    option.None -> handle_low_level_route(request, context, client_key)
  }
}

fn handle_low_level_route(
  request: Request,
  context: Context(e),
  client_key: String,
) -> Response {
  // The manual routes show the lower-level API for applications that need it.
  case wisp.path_segments(request), request.method {
    // Landing page
    [], http.Get -> page.landing(registry.providers(context.registry))

    // Phase 1: Redirect to provider
    ["manual-auth", provider], http.Get ->
      vestibule_wisp.request_phase_for_client_with_options(
        request,
        registry: context.registry,
        provider: provider,
        state_store: context.state_store,
        authorize_options: config.authorize_options(),
        middleware_options: local_http_options(),
        client_key: client_key,
      )

    // Phase 2: Handle callback (GET for most providers, POST for Apple form_post)
    ["manual-auth", provider, "callback"], http.Get
    | ["manual-auth", provider, "callback"], http.Post
    ->
      vestibule_wisp.callback_phase_with_options(
        request,
        registry: context.registry,
        provider: provider,
        state_store: context.state_store,
        on_success: fn(authentication) { page.success(authentication) },
        options: local_http_options(),
      )

    // Everything else
    _, http.Get
    | _, http.Post
    | _, http.Head
    | _, http.Put
    | _, http.Delete
    | _, http.Trace
    | _, http.Connect
    | _, http.Options
    | _, http.Patch
    | _, http.Other(_)
    -> wisp.not_found()
  }
}

fn local_http_options() -> vestibule_wisp.Options {
  vestibule_wisp.default_options()
  |> vestibule_wisp.with_cookie_security(vestibule_wisp.AllowInsecure)
}
