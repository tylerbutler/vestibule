import fixture_app/client
import fixture_app/config
import fixture_app/decode
import fixture_app/error
import fixture_app/parser
import fixture_app/url
import fixture_app/user.{type User}

pub fn load_user(input: String) -> Result(User, error.LoadError) {
  let request_url = url.build(config.base_url(), parser.path(input))
  request_url
  |> client.fetch
  |> decode.user
}
