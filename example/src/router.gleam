import gleam/dict
import gleam/http
import wisp.{type Request, type Response}

import pages
import session
import vestibule
import vestibule/error
import vestibule/registry.{type Registry}

/// Application context passed to the router.
pub type Context {
  Context(registry: Registry)
}

/// Route incoming requests.
pub fn handle_request(req: Request, ctx: Context) -> Response {
  use <- wisp.log_request(req)

  case wisp.path_segments(req), req.method {
    // Landing page
    [], http.Get -> pages.landing(registry.providers(ctx.registry))

    // Phase 1: Redirect to provider
    ["auth", provider], http.Get -> begin_auth(req, ctx, provider)

    // Phase 2: Handle callback
    ["auth", provider, "callback"], http.Get ->
      handle_callback(req, ctx, provider)

    // Everything else
    _, _ -> wisp.not_found()
  }
}

fn begin_auth(req: Request, ctx: Context, provider: String) -> Response {
  case registry.get(ctx.registry, provider) {
    Error(Nil) -> wisp.not_found()
    Ok(#(strategy, config)) ->
      case vestibule.authorize_url(strategy, config) {
        Ok(#(url, state)) -> {
          let session_id = session.store_state(state)
          wisp.redirect(url)
          |> wisp.set_cookie(
            req,
            "vestibule_session",
            session_id,
            wisp.Signed,
            600,
          )
        }
        Error(err) -> pages.error(err)
      }
  }
}

fn handle_callback(req: Request, ctx: Context, provider: String) -> Response {
  case registry.get(ctx.registry, provider) {
    Error(Nil) -> wisp.not_found()
    Ok(#(strategy, config)) -> {
      let session_result =
        wisp.get_cookie(req, "vestibule_session", wisp.Signed)
      case session_result {
        Error(Nil) ->
          pages.error(error.ConfigError(reason: "Missing session cookie"))
        Ok(session_id) ->
          case session.get_state(session_id) {
            Error(Nil) ->
              pages.error(error.ConfigError(
                reason: "Session expired or already used",
              ))
            Ok(expected_state) -> {
              let params =
                wisp.get_query(req)
                |> dict.from_list()
              case
                vestibule.handle_callback(
                  strategy,
                  config,
                  params,
                  expected_state,
                )
              {
                Ok(auth) -> pages.success(auth)
                Error(err) -> pages.error(err)
              }
            }
          }
      }
    }
  }
}
