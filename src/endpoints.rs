use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    extract::Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json as ResponseJson,
};

use hmac::Hmac;
use sha2::Sha384;

type Claims = BTreeMap<String, String>;

pub struct JWTState {
    pub private_key: Hmac<Sha384>,
}

#[derive(Serialize)]
struct JWT {
    token: String,
}

impl JWT {
    /// Consumes the JWT
    fn verify(self, key: &Hmac<Sha384>) -> Result<Claims, ()> {
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

#[derive(Serialize)]
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
    claims: Claims,
    verified: bool,
}

pub async fn get_root() -> &'static str {
    "API is up!"
}

#[axum::debug_handler]
pub async fn post_new_user(
    State(jwt_state): State<Arc<JWTState>>,
    Json(info): Json<CreateUserRequest>,
) -> Result<ResponseJson<CreateUserResponse>, StatusCode> {
    // Verify the following once I have supabase up
    // @purdue.edu email
    // new user is actually created
    // linkedin exists
    // otherwise throw a status

    let header = Header {
        algorithm: jwt::AlgorithmType::Hs384,
        ..Default::default()
    };

    let mut claims: Claims = BTreeMap::new();
    claims.insert("email".to_owned(), info.email);
    claims.insert("linkedin".to_owned(), info.linkedin);

    let jwt = Token::new(header, claims)
        .sign_with_key(&jwt_state.private_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(ResponseJson(CreateUserResponse {
        jwt: JWT {
            token: jwt.as_str().to_owned(),
        },
    }))
}
