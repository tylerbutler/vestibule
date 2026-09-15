import envoy
import gleam/bit_array
import gleam/bytes_tree
import gleam/crypto
import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/io
import gleam/result
import mist
import wisp
import wisp/wisp_mist

import vestibule/config
import vestibule/registry
import vestibule/state_store
import vestibule_example/router.{Context}
import vestibule_github
import vestibule_google
import vestibule_microsoft

pub fn main() -> Nil {
  let port =
    envoy.get("PORT")
    |> result.try(int.parse)
    |> result.unwrap(8000)
  let secret_key_base = case envoy.get("SECRET_KEY_BASE") {
    Ok(secret) -> secret
    Error(Nil) -> {
      io.println(
        "Warning: using an ephemeral SECRET_KEY_BASE; OAuth flow cookies become invalid when the server restarts.",
      )
      crypto.strong_random_bytes(32)
      |> bit_array.base64_url_encode(False)
    }
  }
  let callback_base = "http://localhost:" <> int.to_string(port)

  // Build registry with available providers
  let provider_registry = registry.new()

  let provider_registry = case
    envoy.get("GITHUB_CLIENT_ID"),
    envoy.get("GITHUB_CLIENT_SECRET")
  {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: github")
      let assert Ok(provider_registry) =
        registry.register(
          provider_registry,
          strategy: vestibule_github.strategy(),
          config: config.new(
            client_id: id,
            auth: config.client_secret_auth(secret),
            redirect_uri: callback_base <> "/auth/github/callback",
          ),
        )
      provider_registry
    }
    Error(Nil), Ok(_) | Ok(_), Error(Nil) | Error(Nil), Error(Nil) ->
      provider_registry
  }

  let provider_registry = case
    envoy.get("MICROSOFT_CLIENT_ID"),
    envoy.get("MICROSOFT_CLIENT_SECRET")
  {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: microsoft")
      let assert Ok(provider_registry) =
        registry.register(
          provider_registry,
          strategy: vestibule_microsoft.strategy(),
          config: config.new(
            client_id: id,
            auth: config.client_secret_auth(secret),
            redirect_uri: callback_base <> "/auth/microsoft/callback",
          ),
        )
      provider_registry
    }
    Error(Nil), Ok(_) | Ok(_), Error(Nil) | Error(Nil), Error(Nil) ->
      provider_registry
  }

  let provider_registry = case
    envoy.get("GOOGLE_CLIENT_ID"),
    envoy.get("GOOGLE_CLIENT_SECRET")
  {
    Ok(id), Ok(secret) -> {
      io.println("  Registered provider: google")
      let assert Ok(provider_registry) =
        registry.register(
          provider_registry,
          strategy: vestibule_google.strategy(),
          config: config.new(
            client_id: id,
            auth: config.client_secret_auth(secret),
            redirect_uri: callback_base <> "/auth/google/callback",
          ),
        )
      provider_registry
    }
    Error(Nil), Ok(_) | Ok(_), Error(Nil) | Error(Nil), Error(Nil) ->
      provider_registry
  }

  // Require at least one provider
  case registry.providers(provider_registry) {
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
  let assert Ok(store) = state_store.create()

  let context = Context(registry: provider_registry, state_store: store)

  // Configure Wisp logging
  wisp.configure_logger()

  // Start the server
  let handler = fn(request: request.Request(mist.Connection)) {
    case mist.get_connection_info(request.body) {
      Error(Nil) ->
        response.new(429)
        |> response.set_body(mist.Bytes(bytes_tree.new()))
      Ok(info) -> {
        let client_key = mist.ip_address_to_string(info.ip_address)
        wisp_mist.handler(
          fn(request) {
            router.handle_request_for_client(
              request,
              context,
              client_key: client_key,
            )
          },
          secret_key_base,
        )(request)
      }
    }
  }
  let assert Ok(_) =
    handler
    |> mist.new
    |> mist.bind("localhost")
    |> mist.port(port)
    |> mist.start

  io.println(
    "Vestibule demo running on http://localhost:" <> int.to_string(port),
  )

  process.sleep_forever()
}
