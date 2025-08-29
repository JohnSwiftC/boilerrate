use serde::{Deserialize, Serialize};

use std::sync::Arc;

use axum::{
    extract::Query, extract::State, http::StatusCode, response::Html, response::IntoResponse,
    response::Json as ResponseJson,
};

use axum_extra::TypedHeader;
use headers::{Authorization, authorization::Bearer};

use crate::endpoints::{AppState, Claims, JWT};

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
        "http://localhost:3000/auth/callback?email={}",
        claims["email"]
    );

    let auth_url = format!(
        "https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id={}&redirect_uri={}&scope=r_liteprofile",
        app_state.l_config.client_id, redirect_url,
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
    expires_in: u64,
    token_type: String,
}

#[derive(Deserialize)]
pub struct LinkedInProfile {
    id: String,
    #[serde(rename = "localizedFirstName")]
    first_name: String,
    #[serde(rename = "localizedLastName")]
    last_name: String,
}

#[derive(Deserialize)]
pub struct LinkedInProfilePicture {
    #[serde(rename = "profilePicture")]
    profile_picture: ProfilePictureInfo,
}

#[derive(Deserialize)]
pub struct ProfilePictureInfo {
    #[serde(rename = "displayImage")]
    display_image: String,
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
        ("redirect_uri", "http://localhost:3000/auth/callback"),
        ("client_id", &app_state.l_config.client_id),
        ("client_secret", &app_state.l_config.client_secret),
    ];
    
    let token_response = client
        .post("https://www.linkedin.com/oauth/v2/accessToken")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&token_params)
        .send()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let token_data: LinkedInTokenResponse = token_response
        .json()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    
    let profile_response = client
        .get("https://api.linkedin.com/v2/people/~:(id,localizedFirstName,localizedLastName)")
        .header("Authorization", format!("Bearer {}", token_data.access_token))
        .send()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let redirect_html = format!(
        r#"
        <html>
        {}
        <img src={}></img>
        </html>
    "#
    );

    Ok(Html(redirect_html))
}
