pub type Role {
  Student
  Teacher
}

pub fn label(role: Role) -> String {
  case role {
    Student -> "student"
    Teacher -> "teacher"
  }
}
