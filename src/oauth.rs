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
        "http://boilerrate.io/auth/callback?email={}",
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
    code: String,
    state: Option<String>,
}

pub async fn linkedin_callback(
    State(app_state): State<Arc<AppState>>,
    Query(params): Query<LinkedInCallback>,
) -> Result<impl IntoResponse, StatusCode> {
    // TODO
    // Get LinkedIn name, photo, attach to user in supabase

    // at this point, the browser should have a valid jwt, so connect that auth header
    // to the linkedin info given here

    let redirect_html = format!(
        r#"
        <html>
        <script>
            window.location.href = 'homepage';
        </script>
        </html>
    "#
    );

    Ok(Html(redirect_html))
}
