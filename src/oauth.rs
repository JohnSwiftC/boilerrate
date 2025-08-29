use jwt::{Header, SignWithKey, Token, VerifyWithKey};
use serde::{Deserialize, Serialize};

use std::sync::Arc;

use axum::{
    extract::State,
    extract::Query,
    http::{StatusCode},
    response::Json as ResponseJson,
    response::Html,
    response::IntoResponse,
};

use urlencoding;

use crate::endpoints::AppState;

pub struct LinkedInConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

pub async fn get_linkedin_auth_url(
    State(app_state): State<Arc<AppState>>,
) -> Result<ResponseJson<serde_json::Value>, StatusCode> {
    let auth_url = format!(
        "https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id={}&redirect_uri={}&scope=r_liteprofile%20r_emailaddress",
        app_state.l_config.client_id,
        urlencoding::encode(&app_state.l_config.redirect_uri)
    );
    
    Ok(ResponseJson(serde_json::json!({
        "auth_url": auth_url
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

    let redirect_html = format!(r#"
        <html>
        <script>
            window.location.href = 'http://localhost:3000/dashboard?token={}';
        </script>
        </html>
    "#, jwt_token);
    
    Ok(Html(redirect_html))
}