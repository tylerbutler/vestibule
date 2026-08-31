import gleam/http
import wisp.{type Request, type Response}

import vestibule/config
import vestibule/registry.{type Registry}
import vestibule/state_store.{type StateStore}
import vestibule_example/page
import vestibule_wisp

/// Application context passed to the router.
pub type Context(e) {
  Context(registry: Registry(e), state_store: StateStore)
}

/// Route incoming requests.
pub fn handle_request(request: Request, context: Context(e)) -> Response {
  use <- wisp.log_request(request)

  case wisp.path_segments(request), request.method {
    // Landing page
    [], http.Get -> page.landing(registry.providers(context.registry))

    // Phase 1: Redirect to provider
    ["auth", provider], http.Get ->
      vestibule_wisp.request_phase(
        request,
        registry: context.registry,
        provider: provider,
        state_store: context.state_store,
        authorize_options: config.authorize_options(),
      )

    // Phase 2: Handle callback (GET for most providers, POST for Apple form_post)
    ["auth", provider, "callback"], http.Get
    | ["auth", provider, "callback"], http.Post
    ->
      vestibule_wisp.callback_phase(
        request,
        registry: context.registry,
        provider: provider,
        state_store: context.state_store,
        on_success: fn(authentication) { page.success(authentication) },
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
