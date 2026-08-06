pub type NoteError {
  NoteAlreadyExists
  NoteCouldNotBeWritten
}

pub fn save(path: String) -> Result(Nil, NoteError) {
  case path {
    "" -> Error(NoteCouldNotBeWritten)
    _ -> Ok(Nil)
  }
}
