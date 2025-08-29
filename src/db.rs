use serde::Serialize;

#[derive(Serialize)]
pub struct User {
    pub email: String,
    pub hashed_pass: String,
    pub linkedin: String,
    pub elo: i32,
}
