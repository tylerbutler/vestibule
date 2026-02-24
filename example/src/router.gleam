import gleam/dict
import gleam/http
import wisp.{type Request, type Response}

import pages
import session
import vestibule
import vestibule/config.{type Config}
import vestibule/error
import vestibule/strategy.{type Strategy}

/// Application context passed to the router.
pub type Context {
  Context(strategy: Strategy, config: Config)
}

/// Route incoming requests.
pub fn handle_request(req: Request, ctx: Context) -> Response {
  use <- wisp.log_request(req)

  case wisp.path_segments(req), req.method {
    // Landing page
    [], http.Get -> pages.landing()

    // Phase 1: Redirect to GitHub
    ["auth", "github"], http.Get -> begin_auth(req, ctx)

    // Phase 2: Handle callback
    ["auth", "github", "callback"], http.Get -> handle_callback(req, ctx)

    // Everything else
    _, _ -> wisp.not_found()
  }
}

fn begin_auth(req: Request, ctx: Context) -> Response {
  case vestibule.authorize_url(ctx.strategy, ctx.config) {
    Ok(#(url, state)) -> {
      let session_id = session.store_state(state)
      wisp.redirect(url)
      |> wisp.set_cookie(req, "vestibule_session", session_id, wisp.Signed, 600)
    }
    Error(err) -> pages.error(err)
  }
}

fn handle_callback(req: Request, ctx: Context) -> Response {
  let session_result = wisp.get_cookie(req, "vestibule_session", wisp.Signed)

  case session_result {
    Error(Nil) ->
      pages.error(error.ConfigError(reason: "Missing session cookie"))
    Ok(session_id) -> {
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
              ctx.strategy,
              ctx.config,
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
