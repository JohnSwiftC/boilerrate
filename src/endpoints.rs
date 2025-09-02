use axum::extract::Query;
use axum::response::IntoResponse;
use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::db;
use crate::oauth;

use axum::{
    extract::Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json as ResponseJson,
    response::Html,
};

use hmac::Hmac;
use sha2::Sha384;

use serde_json::Value;
use supabase_rs::SupabaseClient;

pub type Claims = BTreeMap<String, String>;

pub struct AppState {
    pub private_key: Hmac<Sha384>,
    pub supabase_client: Arc<SupabaseClient>,
    pub l_config: Arc<oauth::LinkedInConfig>,
    pub mailer: SmtpTransport,
}

#[derive(Serialize)]
pub struct JWT {
    pub token: String,
}

impl JWT {
    pub fn new(claims: Claims, key: &Hmac<Sha384>) -> Result<Self, jwt::Error> {
        let header = Header {
            algorithm: jwt::AlgorithmType::Hs384,
            ..Default::default()
        };

        let jwt = Token::new(header, claims).sign_with_key(key)?;

        Ok(Self {
            token: jwt.as_str().to_owned(),
        })
    }
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
    Success(String),
    Failure(String),
}

use std::time::{SystemTime, UNIX_EPOCH};
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};

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

    let header = Header {
        algorithm: jwt::AlgorithmType::Hs384,
        ..Default::default()
    };

    let mut time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();

    time += Duration::from_secs(1800);

    let mut claims: Claims = BTreeMap::new();
    claims.insert("email".to_owned(), info.email);
    claims.insert("password".to_owned(), info.password);
    claims.insert("verification_ts".to_owned(), time.as_secs().to_string());

    let email = Message::builder()
        .from("verify@boilerrate.com".parse().unwrap())
        .to(claims["email"].parse().unwrap())
        .subject("BoilerRate Verification")
        .header(ContentType::TEXT_PLAIN);
    
    let jwt = Token::new(header, claims)
        .sign_with_key(&app_state.private_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let verification_link = format!("https://api.boilerrate.com/verify?token={}", jwt.as_str());

    let email = email.body(verification_link)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    app_state.mailer.send(&email).unwrap();

    Ok(ResponseJson(CreateUserResponse::Success("Email sent to user".to_owned())))
}

#[derive(Deserialize)]
pub struct VerificationRequest {
    token: String
}

pub async fn verify_registration(
    Query(params): Query<VerificationRequest>,
    State(app_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let jwt = JWT {
        token: params.token,
    };

    let claims = jwt.verify(&app_state.private_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Verify that the token is still valid for its timestamp
    let current_time: Duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();

    let stamp_time: Duration = Duration::from_secs(
        claims["verification_ts"].parse().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    );

    if current_time > stamp_time {
        return Ok(Html(format!(
            r#"
                <html>
                 <h1>
                 Your account creation request has expired. Please try again.
                 </h1>
                </html>
            "#
        )))
    }

    let user = db::User {
        email: claims["email"].clone(),
        hashed_pass: claims["password"].clone(),
        name: None,
        image: None,
        profile: None,
        linkedin_conn: false,
        ln_token: None,
        elo: 800,
    };

    let db_resp = app_state.supabase_client.insert("Users", user).await;

    if let Err(e) = db_resp {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Redirect user to frontend login page, maybe with a flag for a "email verified" notif
    Ok(Html(format!(
        r#"
            <html>
            <h1>
                Email verified, please login
            </h1>
            </html>
        "#
    )))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub enum LoginResponse {
    Success { jwt: JWT },
    Failure(String),
}

pub async fn login(
    State(app_state): State<Arc<AppState>>,
    Json(info): Json<LoginRequest>,
) -> Result<ResponseJson<LoginResponse>, StatusCode> {
    let user = app_state
        .supabase_client
        .select("Users")
        .eq("email", &info.email)
        .execute()
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let user = match user.get(0) {
        Some(u) => u,
        None => {
            return Ok(ResponseJson(LoginResponse::Failure(String::from(
                "User does not exist",
            ))));
        }
    };

    if info.password != user["hashed_pass"] {
        return Ok(ResponseJson(LoginResponse::Failure(String::from(
            "Incorrect password",
        ))));
    }

    let mut claims: Claims = BTreeMap::new();
    claims.insert("email".to_owned(), info.email);

    let jwt = JWT::new(claims, &app_state.private_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(ResponseJson(LoginResponse::Success { jwt }))
}
