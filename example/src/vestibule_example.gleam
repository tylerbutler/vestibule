import envoy
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/result
import mist
import wisp
import wisp/wisp_mist

import router.{Context}
import vestibule/config
import vestibule/registry
import vestibule/strategy/github
import vestibule_google
import vestibule_microsoft
import vestibule_wisp/state_store

pub fn main() {
  let port =
    envoy.get("PORT")
    |> result.try(int.parse)
    |> result.unwrap(8000)
  let secret_key_base =
    envoy.get("SECRET_KEY_BASE")
    |> result.unwrap("development-secret-key-base-change-in-production-please")
  let callback_base = "http://localhost:" <> int.to_string(port)

  // Build registry with available providers
  let reg = registry.new()

  let reg = case
    envoy.get("GITHUB_CLIENT_ID"),
    envoy.get("GITHUB_CLIENT_SECRET")
  {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: github")
      registry.register(
        reg,
        github.strategy(),
        config.new(id, secret, callback_base <> "/auth/github/callback"),
      )
    }
    _, _ -> reg
  }

  let reg = case
    envoy.get("MICROSOFT_CLIENT_ID"),
    envoy.get("MICROSOFT_CLIENT_SECRET")
  {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: microsoft")
      registry.register(
        reg,
        vestibule_microsoft.strategy(),
        config.new(id, secret, callback_base <> "/auth/microsoft/callback"),
      )
    }
    _, _ -> reg
  }

  let reg = case
    envoy.get("GOOGLE_CLIENT_ID"),
    envoy.get("GOOGLE_CLIENT_SECRET")
  {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: google")
      registry.register(
        reg,
        vestibule_google.strategy(),
        config.new(id, secret, callback_base <> "/auth/google/callback"),
      )
    }
    _, _ -> reg
  }

  // Require at least one provider
  case registry.providers(reg) {
    [] -> {
      io.println("Error: No OAuth providers configured.")
      io.println("Set GITHUB_CLIENT_ID + GITHUB_CLIENT_SECRET,")
      io.println("MICROSOFT_CLIENT_ID + MICROSOFT_CLIENT_SECRET, and/or")
      io.println("GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET in your .env file.")
      panic as "No providers configured"
    }
    _ -> Nil
  }

  // Initialize state store
  let store = state_store.init()

  let ctx = Context(registry: reg, state_store: store)

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

  process.sleep_forever()
}
