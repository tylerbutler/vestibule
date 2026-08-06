import gleam/list
import gleam/result

pub type Recipient {
  Member
  Guest
}

pub fn welcome_all(recipients: List(Recipient)) -> List(String) {
  list.map(recipients, greeting)
}

pub fn try_welcome_all(
  recipients: List(Recipient),
  validate: fn(Recipient) -> Result(Recipient, error),
) -> Result(List(String), error) {
  use valid_recipients <- result.try(list.try_map(recipients, validate))
  Ok(list.map(valid_recipients, greeting))
}

fn greeting(recipient: Recipient) -> String {
  case recipient {
    Member -> "Welcome back"
    Guest -> "Welcome"
  }
}
