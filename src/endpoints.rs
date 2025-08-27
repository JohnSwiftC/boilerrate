use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct CreateUserRequest {
    email: String,
    password: String,
    linkedin: String,
}

#[derive(Deserialize)]
pub struct ObtainJWTRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct VerifyJWTClaimsResponse {
    claims: HashMap<String, String>,
}

pub async fn get_root() -> &'static str {
    "API is up!"
}