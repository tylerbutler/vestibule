import gleam/dict
import gleam/result

pub fn add_points(
  scores: dict.Dict(String, Int),
  player: String,
  points: Int,
) -> dict.Dict(String, Int) {
  let current_score =
    scores
    |> dict.get(player)
    |> result.unwrap(0)

  dict.insert(scores, player, current_score + points)
}
