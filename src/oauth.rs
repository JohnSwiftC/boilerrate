use serde::{Deserialize, Serialize};

use std::sync::Arc;

use axum::{
    extract::Query, extract::State, http::StatusCode, response::Html, response::IntoResponse,
    response::Json as ResponseJson,
};

use axum_extra::TypedHeader;
use headers::{Authorization, authorization::Bearer};

use crate::endpoints::{AppState, Claims, JWT};
use urlencoding;

pub struct LinkedInConfig {
    pub client_id: String,
    pub client_secret: String,
}

pub async fn get_linkedin_auth_url(
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    State(app_state): State<Arc<AppState>>,
) -> Result<ResponseJson<serde_json::Value>, StatusCode> {
    let jwt = JWT {
        token: auth.token().to_owned(),
    };

    let claims: Claims = jwt
        .verify(&app_state.private_key)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let redirect_url = format!(
        "http://localhost:3000/oauth/callback?email={}",
        claims["email"]
    );

    let auth_url = format!(
        "https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email",
        app_state.l_config.client_id, urlencoding::encode(&redirect_url),
    );

    Ok(ResponseJson(serde_json::json!({
        "auth_url": auth_url,
    })))
}

#[derive(Deserialize)]
pub struct LinkedInCallback {
    email: String,
    code: String,
    state: Option<String>,
}

#[derive(Deserialize)]
pub struct LinkedInTokenResponse {
    access_token: String,
    _expires_in: u64,
    _token_type: String,
}

#[derive(Deserialize)]
pub struct LinkedInUserInfo {
    pub sub: String,       
    pub name: String,          
    pub given_name: String,    
    pub family_name: String,
    pub picture: String,
    pub email: String,
    pub email_verified: bool,
}

use reqwest::Client;

pub async fn linkedin_callback(
    State(app_state): State<Arc<AppState>>,
    Query(params): Query<LinkedInCallback>,
) -> Result<impl IntoResponse, StatusCode> {
    // TODO
    // Get LinkedIn name, photo, attach to user in supabase

    let client = Client::new();
    
    let token_params = [
        ("grant_type", "authorization_code"),
        ("code", &params.code),
        ("redirect_uri", "http://localhost:3000/oauth/callback"),
        ("client_id", &app_state.l_config.client_id),
        ("client_secret", &app_state.l_config.client_secret),
    ];
    
    let token_response = client
        .post("https://www.linkedin.com/oauth/v2/accessToken")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&token_params)
        .send()
        .await
        .unwrap();

    println!("{:#?}", token_response.text().await.unwrap());
    
    let token_data: LinkedInTokenResponse = token_response
        .json()
        .await
        .unwrap();
    
    let profile_response = client
        .get("https://api.linkedin.com/v2/userinfo")
        .header("Authorization", format!("Bearer {}", token_data.access_token))
        .send()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let profile: LinkedInUserInfo = profile_response
        .json()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let full_name = format!("{} {}", profile.name, profile.family_name);

    let redirect_html = format!(
        r#"
        <html>
        {}
        <img src={}></img>
        </html>
    "#
    , full_name, profile.picture);

    Ok(Html(redirect_html))
}
