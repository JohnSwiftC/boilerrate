use serde::Serialize;

#[derive(Serialize)]
pub struct User {
    pub email: String,
    pub hashed_pass: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub profile: Option<String>,
    pub linkedin_conn: bool,
    pub elo: i32,
}
