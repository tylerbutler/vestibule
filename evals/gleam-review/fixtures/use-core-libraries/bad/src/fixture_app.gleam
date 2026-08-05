pub type StringDictionary {
  StringDictionary(entries: List(#(String, String)))
}

pub fn new() -> StringDictionary {
  StringDictionary([])
}

pub fn insert(
  dictionary: StringDictionary,
  key: String,
  value: String,
) -> StringDictionary {
  let StringDictionary(entries) = dictionary
  StringDictionary([#(key, value), ..entries])
}
