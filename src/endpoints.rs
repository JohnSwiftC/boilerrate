use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::db;
use crate::oauth;

use axum::{
    extract::Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json as ResponseJson,
};

use hmac::Hmac;
use sha2::Sha384;

use supabase_rs::SupabaseClient;

pub type Claims = BTreeMap<String, String>;

pub struct AppState {
    pub private_key: Hmac<Sha384>,
    pub supabase_client: Arc<SupabaseClient>,
    pub l_config: Arc<oauth::LinkedInConfig>,
}

#[derive(Serialize)]
pub struct JWT {
    pub token: String,
}

impl JWT {
    /// Consumes the JWT
    pub fn verify(self, key: &Hmac<Sha384>) -> Result<Claims, ()> {
        if let Ok(claims) = self.token.verify_with_key(key) {
            return Ok(claims);
        }

        Err(())
    }
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

#[derive(Deserialize)]
pub struct CreateUserRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub enum CreateUserResponse {
    Success { jwt: JWT },
    Failure(String),
}

#[axum::debug_handler]
pub async fn post_new_user(
    State(app_state): State<Arc<AppState>>,
    Json(info): Json<CreateUserRequest>,
) -> Result<ResponseJson<CreateUserResponse>, StatusCode> {
    // Verify the following once I have supabase up
    // @purdue.edu email X
    // new user is actually created

    if !info.email.ends_with("@purdue.edu") {
        return Ok(ResponseJson(CreateUserResponse::Failure(String::from(
            "Email must be an @purdue.edu",
        ))));
    }

    // Ensure that I hash the passwords

    let user = db::User {
        email: info.email.clone(),
        hashed_pass: info.password.clone(),
        name: None,
        image: None,
        linkedin_conn: false,
        elo: 800,
    };

    let db_resp = app_state.supabase_client.insert("Users", user).await;

    if let Err(e) = db_resp {
        return Ok(ResponseJson(CreateUserResponse::Failure(e)));
    }

    let header = Header {
        algorithm: jwt::AlgorithmType::Hs384,
        ..Default::default()
    };

    let mut claims: Claims = BTreeMap::new();
    claims.insert("email".to_owned(), info.email);

    let jwt = Token::new(header, claims)
        .sign_with_key(&app_state.private_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(ResponseJson(CreateUserResponse::Success {
        jwt: JWT {
            token: jwt.as_str().to_owned(),
        },
    }))
}
