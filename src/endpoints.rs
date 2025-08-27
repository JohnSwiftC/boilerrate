use jwt::VerifyWithKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    response::Json as ResponseJson,
};

use hmac::Hmac;
use sha2::Sha256;

type Claims = BTreeMap<String, String>;

#[derive(Serialize)]
struct JWT {
    token: String,
}

impl JWT {
    /// Consumes the JWT
    fn verify(self, key: &Hmac<Sha256>) -> Result<Claims, ()> {
        if let Ok(claims) = self.token.verify_with_key(key) {
            return Ok(claims);
        }

        Err(())
    }
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    email: String,
    password: String,
    linkedin: String,
}

pub struct CreateUserResponse {
    jwt: JWT,
}

#[derive(Deserialize)]
pub struct ObtainJWTRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct VerifyJWTClaimsResponse {
    claims: BTreeMap<String, String>,
    verified: bool,
}

pub async fn get_root() -> &'static str {
    "API is up!"
}

pub async fn post_new_user(
    Json(info): Json<CreateUserRequest>,
) -> Result<ResponseJson<JWT>, StatusCode> {
    Err(StatusCode::UNAUTHORIZED)
}
