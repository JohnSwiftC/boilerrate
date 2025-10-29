use axum::body::Body;
use axum::extract::Query;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::response::Response;
use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::db;
use crate::oauth;

use axum::{
    extract::Extension, extract::Form, extract::Json, extract::State, http::StatusCode,
    response::Html, response::Json as ResponseJson,
};

use hmac::Hmac;
use sha2::Sha384;

use supabase_rs::SupabaseClient;

use mailgun_rs::{EmailAddress, Mailgun, MailgunRegion, Message};

pub type Claims = BTreeMap<String, String>;

pub struct AppState {
    pub private_key: Hmac<Sha384>,
    pub supabase_client: Arc<SupabaseClient>,
    pub l_config: Arc<oauth::LinkedInConfig>,
    pub mailgun: Arc<Mailgun>,
    pub register_secret: &'static str,
}

#[derive(Debug)]
pub enum JWTError {
    VerificationFailure,
    FieldFailure(String),
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
    pub fn verify(self, key: &Hmac<Sha384>) -> Result<Claims, JWTError> {
        if let Ok(claims) = self.token.verify_with_key(key) {
            return Ok(claims);
        }

        Err(JWTError::VerificationFailure)
    }

    pub fn get_email(self, key: &Hmac<Sha384>) -> Result<String, JWTError> {
        let claims: Result<Claims, _> = self.token.verify_with_key(key);

        if let Ok(claims) = claims {
            if let Some(email) = claims.get::<String>(&"email".to_owned()) {
                return Ok(email.clone());
            } else {
                return Err(JWTError::FieldFailure(String::from("No email field found")));
            }
        } else {
            return Err(JWTError::VerificationFailure);
        }
    }
}

pub async fn get_root() -> &'static str {
    "API is up!"
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    email: String,
    password: String,
    secret: String,
}

#[derive(Serialize)]
pub enum CreateUserResponse {
    Success(String),
    Failure(String),
}

use std::time::{SystemTime, UNIX_EPOCH};

#[axum::debug_handler]
pub async fn post_new_user(
    State(app_state): State<Arc<AppState>>,
    Json(info): Json<CreateUserRequest>,
) -> Result<ResponseJson<CreateUserResponse>, StatusCode> {
    // Verify the following once I have supabase up
    // @purdue.edu email X
    // new user is actually created

    if info.secret != app_state.register_secret {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !info.email.ends_with("@purdue.edu") {
        return Ok(ResponseJson(CreateUserResponse::Failure(String::from(
            "Email must be an @purdue.edu",
        ))));
    }

    // Check to see if user is already registered

    // I love rust
    let registered = {
        app_state
            .supabase_client
            .select("Users")
            .eq("email", &info.email)
            .count()
            .execute()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .get(0)
            .map(|v| if v != 0 { true } else { false })
            .unwrap_or(false)
    };

    if registered {
        return Ok(ResponseJson(CreateUserResponse::Failure(String::from(
            "User already exists!",
        ))));
    }

    let mut time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    time += Duration::from_secs(1800);

    let mut claims: Claims = BTreeMap::new();
    claims.insert("email".to_owned(), info.email.clone());
    claims.insert("password".to_owned(), info.password);
    claims.insert("verification_ts".to_owned(), time.as_secs().to_string());

    let jwt =
        JWT::new(claims, &app_state.private_key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let verification_link = format!(
        "https://api.boilerrate.com/verify?token={}",
        jwt.token.as_str()
    );

    // Actually use postgun api for this, thanks railway

    let recip = EmailAddress::address(&info.email);

    let message = Message {
        to: vec![recip],
        subject: "BoilerRate Verification".to_owned(),
        html: format!(
            r#"
            <h3>Welcome to BoilerRate!</h3>
            <p>Please verify your account with the link below</p>
            <a href="{}">Verify</a>
        "#,
            verification_link
        ),
        ..Default::default()
    };

    let sender = EmailAddress::name_address("verify", "verify@mail.boilerrate.com");

    app_state
        .mailgun
        .async_send(MailgunRegion::US, &sender, message, None)
        .await
        .map_err(|e| {
            println!("{}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(ResponseJson(CreateUserResponse::Success(
        "Email sent to user".to_owned(),
    )))
}

#[derive(Deserialize)]
pub struct VerificationRequest {
    token: String,
}

pub async fn verify_registration(
    Query(params): Query<VerificationRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    // Show user a form to verify with
    // Had to do this because some email providers, like purdue, will scan links with a get request
    // would verify email under previous setup
    Ok(Html(format!(
        r#"
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>User Verification</title>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        max-width: 400px;
                        margin: 50px auto;
                        padding: 20px;
                        background-color: #f5f5f5;
                    }}
                    .verification-form {{
                        background: white;
                        padding: 30px;
                        border-radius: 8px;
                        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                        text-align: center;
                    }}
                    h2 {{
                        color: #333;
                        margin-bottom: 20px;
                    }}
                    .verify-btn {{
                        background-color: #007bff;
                        color: white;
                        padding: 12px 30px;
                        border: none;
                        border-radius: 4px;
                        font-size: 16px;
                        cursor: pointer;
                        transition: background-color 0.3s;
                    }}
                    .verify-btn:hover {{
                        background-color: #0056b3;
                    }}
                    .verify-btn:active {{
                        transform: translateY(1px);
                    }}
                </style>
            </head>
            <body>
                <div class="verification-form">
                    <h2>Click to Verify Your Email</h2>
                    <form action="/verify" method="POST">
                        <input type="hidden" name="token" value="{}">
                        <button type="submit" class="verify-btn">Verify</button>
                    </form>
                </div>
            </body>
            </html>
        "#,
        params.token
    )))
}

#[derive(Deserialize)]
pub struct VerifyFormRequest {
    token: String,
}

#[axum::debug_handler]
pub async fn verify_form(
    State(app_state): State<Arc<AppState>>,
    Form(req): Form<VerifyFormRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let jwt = JWT { token: req.token };

    let claims = jwt
        .verify(&app_state.private_key)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Verify that the token is still valid for its timestamp
    let current_time: Duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    let stamp_time: Duration = Duration::from_secs(
        claims["verification_ts"]
            .parse()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    if current_time > stamp_time {
        return Ok(Html(
            r#"
                    <html>
                        <p>
                            Sorry, the verification request has expired. Please create your account again.
                        </p>
                    </html>
                "#,
        ));
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

    if let Err(_) = db_resp {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Html(
        r#"
            <meta http-equiv="refresh" content="0; url=https://boilerrate.com/login">
        "#,
    ))
}

#[derive(Deserialize)]
pub struct PasswordResetRequest {
    email: String,
}

#[derive(Serialize)]
pub struct PasswordResetResponse {
    success: bool,
    message: String,
}

pub async fn reset(
    State(app_state): State<Arc<AppState>>,
    Json(req): Json<PasswordResetRequest>,
) -> Result<ResponseJson<PasswordResetResponse>, StatusCode> {
    // Send a link with the permision to do this to the users email

    let user = app_state
        .supabase_client
        .select("Users")
        .eq("email", &req.email)
        .execute()
        .await;

    if let Err(e) = user {
        return Ok(ResponseJson(PasswordResetResponse {
            success: false,
            message: e.to_string(),
        }));
    }

    // Construct token

    let mut claims: Claims = BTreeMap::new();
    let current_time: Duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let expiration_time: Duration = current_time + Duration::from_secs(1800);
    claims.insert(String::from("email"), req.email.to_owned());
    claims.insert(String::from("reset_ts"), expiration_time.as_secs().to_string());

    let token: JWT = JWT::new(claims, &app_state.private_key).map_err(|_| {
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let reset_link: String = format!("https://api.boilerrate.com/reset_password?token={}", token.token);

    let recip = EmailAddress::address(&req.email);

    let message = Message {
        to: vec![recip],
        subject: "BoilerRate Verification".to_owned(),
        html: format!(
            r#"
            <h3>BoilerRate Password Reset</h3>
            <p>Please reset your account with the link below</p>
            <a href="{}">Reset</a>
        "#,
            reset_link
        ),
        ..Default::default()
    };

    let sender = EmailAddress::name_address("reset", "reset@mail.boilerrate.com");

    app_state
        .mailgun
        .async_send(MailgunRegion::US, &sender, message, None)
        .await
        .map_err(|e| {
            println!("{}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    
    Ok(ResponseJson(PasswordResetResponse {
        success: true,
        message: "Password reset email sent!".to_owned(),
    }))
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

// need to include linkedin photo for login token
// photo field on jwt

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

    let jwt =
        JWT::new(claims, &app_state.private_key).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(ResponseJson(LoginResponse::Success { jwt }))
}

#[derive(Serialize)]
pub struct UserInfo {
    conn: bool,
    email: String,
    photo: Option<String>,
    name: Option<String>,
}

pub async fn get_user_data(
    Extension(email): Extension<String>,
    State(app_state): State<Arc<AppState>>,
) -> Result<ResponseJson<UserInfo>, StatusCode> {
    let user = app_state
        .supabase_client
        .select("Users")
        .eq("email", &email)
        .execute()
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let user = match user.get(0) {
        Some(u) => u,
        None => {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let user = UserInfo {
        conn: user["linkedin_conn"].as_bool().unwrap(),
        email: email,
        photo: user["image"].as_str().and_then(|s| Some(s.to_owned())),
        name: user["name"].as_str().and_then(|s| Some(s.to_owned())),
    };

    Ok(ResponseJson(user))
}

pub async fn auth_middleware(
    State(app_state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => &header[7..],
        _ => {
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let jwt: JWT = JWT {
        token: token.to_owned(),
    };

    let email: String = jwt
        .get_email(&app_state.private_key)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut request = request;
    request.extensions_mut().insert(email);

    Ok(next.run(request).await)
}
