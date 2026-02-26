import gleam/http
import wisp.{type Request, type Response}

import pages
import vestibule/registry.{type Registry}
import vestibule_wisp
import vestibule_wisp/state_store.{type StateStore}

/// Application context passed to the router.
pub type Context(e) {
  Context(registry: Registry(e), state_store: StateStore)
}

/// Route incoming requests.
pub fn handle_request(req: Request, ctx: Context(e)) -> Response {
  use <- wisp.log_request(req)

  case wisp.path_segments(req), req.method {
    // Landing page
    [], http.Get -> pages.landing(registry.providers(ctx.registry))

    // Phase 1: Redirect to provider
    ["auth", provider], http.Get ->
      vestibule_wisp.request_phase(req, ctx.registry, provider, ctx.state_store)

    // Phase 2: Handle callback
    ["auth", provider, "callback"], http.Get ->
      vestibule_wisp.callback_phase(
        req,
        ctx.registry,
        provider,
        ctx.state_store,
        fn(auth) {
        pages.success(auth)
      })

    // Everything else
    _, _ -> wisp.not_found()
  }
}
