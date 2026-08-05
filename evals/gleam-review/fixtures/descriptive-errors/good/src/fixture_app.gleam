pub type NoteError {
  NoteAlreadyExists(path: String)
  NoteCouldNotBeWritten(path: String, reason: String)
}

pub fn save(path: String) -> Result(Nil, NoteError) {
  case path {
    "" -> Error(NoteCouldNotBeWritten(path, "path cannot be empty"))
    _ -> Ok(Nil)
  }
}
