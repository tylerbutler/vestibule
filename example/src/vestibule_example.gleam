import envoy
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/result
import mist
import wisp
import wisp/wisp_mist

import router.{Context}
import session
import vestibule/config
import vestibule/strategy/github

pub fn main() {
  // Read configuration from environment
  let assert Ok(client_id) = envoy.get("GITHUB_CLIENT_ID")
  let assert Ok(client_secret) = envoy.get("GITHUB_CLIENT_SECRET")
  let port =
    envoy.get("PORT")
    |> result.try(int.parse)
    |> result.unwrap(8000)
  let secret_key_base =
    envoy.get("SECRET_KEY_BASE")
    |> result.unwrap(
      "development-secret-key-base-change-in-production-please",
    )

  // Set up vestibule
  let strategy = github.strategy()
  let cfg =
    config.new(
      client_id,
      client_secret,
      "http://localhost:" <> int.to_string(port) <> "/auth/github/callback",
    )

  let ctx = Context(strategy: strategy, config: cfg)

  // Initialize session store
  session.create_table()

  // Configure Wisp logging
  wisp.configure_logger()

  // Start the server
  let handler = fn(req) { router.handle_request(req, ctx) }
  let assert Ok(_) =
    handler
    |> wisp_mist.handler(secret_key_base)
    |> mist.new
    |> mist.port(port)
    |> mist.start

  io.println(
    "Vestibule demo running on http://localhost:" <> int.to_string(port),
  )
  io.println(
    "Sign in at http://localhost:" <> int.to_string(port) <> "/auth/github",
  )

  process.sleep_forever()
}
