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

    let auth_url = format!(
        "https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id={}&redirect_uri={}&scope=r_basicprofile&state={}",
        app_state.l_config.client_id,
        urlencoding::encode("https://api.boilerrate.com/oauth/callback"),
        urlencoding::encode(&jwt.token),
    );

    Ok(ResponseJson(serde_json::json!({
        "auth_url": auth_url,
    })))
}

#[derive(Deserialize, Debug)]
pub struct LinkedInCallback {
    code: String,
    state: String,
}

#[derive(Deserialize, Debug)]
pub struct LinkedInTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: String,
    pub refresh_token_expires_in: u32,
    pub scope: String,
}

#[derive(Deserialize, Debug)]
pub struct LinkedInUserInfo {
    pub id: String,
    #[serde(rename = "localizedFirstName")]
    pub localized_first_name: String,
    #[serde(rename = "localizedLastName")] 
    pub localized_last_name: String,
    #[serde(rename = "profilePicture")]
    pub profile_picture: Option<ProfilePicture>, // Direct URL to profile picture
    #[serde(rename = "vanityName")]
    pub vanity_name: String,
}

#[derive(Deserialize, Debug)]
pub struct ProfilePicture {
    #[serde(rename = "displayImage")]
    pub display_image: String, // URN
    #[serde(rename = "displayImage~")]
    pub display_image_data: Option<DisplayImageData>, // Actual URLs
}

#[derive(Deserialize, Debug)]
pub struct DisplayImageData {
    pub elements: Vec<ImageElement>,
}

#[derive(Deserialize, Debug)]
pub struct ImageElement {
    pub identifiers: Vec<ImageIdentifier>,
}

#[derive(Deserialize, Debug)]
pub struct ImageIdentifier {
    pub identifier: String, // This is the actual image URL
}

use reqwest::Client;

pub async fn linkedin_callback(
    State(app_state): State<Arc<AppState>>,
    Query(params): Query<LinkedInCallback>,
) -> Result<impl IntoResponse, StatusCode> {
    println!("LinkedIn callback started with params: {:?}", params);
    
    let client = Client::new();
    let token_params = [
        ("grant_type", "authorization_code"),
        ("code", &params.code),
        (
            "redirect_uri",
            "https://api.boilerrate.com/oauth/callback",
        ),
        ("client_id", &app_state.l_config.client_id),
        ("client_secret", &app_state.l_config.client_secret),
    ];

    println!("Making token request to LinkedIn...");
    let token_response = client
        .post("https://www.linkedin.com/oauth/v2/accessToken")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&token_params)
        .send()
        .await
        .map_err(|e| {
            println!("Token request failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!("Token response status: {}", token_response.status());
    
    // Check if the response is successful before trying to parse
    if !token_response.status().is_success() {
        let error_text = token_response.text().await.unwrap_or_default();
        println!("LinkedIn token error response: {}", error_text);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let token_data: LinkedInTokenResponse = token_response
        .json()
        .await
        .map_err(|e| {
            println!("Failed to parse token response: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!("Token received, making user info request...");
    
    let user_response = client
        .get("https://api.linkedin.com/v2/me?projection=(id,localizedFirstName,localizedLastName,vanityName,profilePicture(displayImage~:playableStreams))")
        .header(
            "Authorization",
            format!("Bearer {}", token_data.access_token),
        )
        .send()
        .await
        .map_err(|e| {
            println!("User info request failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!("User response status: {}", user_response.status());
    
    if !user_response.status().is_success() {
        let error_text = user_response.text().await.unwrap_or_default();
        println!("LinkedIn user info error response: {}", error_text);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let user_info: LinkedInUserInfo = user_response
        .json()
        .await
        .map_err(|e| {
            println!("Failed to parse user info response: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!("User info received: {:?}", user_info);

    let jwt = JWT {
        token: params.state
    };

    let claims = jwt.verify(&app_state.private_key)
        .map_err(|e| {
            println!("JWT verification failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!("JWT verified, updating database...");

    let profile_pic = user_info.profile_picture
            .and_then(|p| p.display_image_data)
            .and_then(|d| d.elements.into_iter().next())
            .and_then(|i| i.identifiers.into_iter().next())
            .and_then(|i| Some(i.identifier.clone()));

    let mut link_clone = String::from("");

    let db_update = match profile_pic {
        Some(p) => {
            link_clone = p.clone();

            serde_json::json!(
                {
                    "name":format!("{} {}", user_info.localized_first_name, user_info.localized_last_name),
                    "image":p,
                    "linkedin_conn":true,
                    "ln_token":token_data.access_token,
                    "profile":user_info.vanity_name,
                }
            )
        },
        None => {
            serde_json::json!(
                {
                    "name":format!("{} {}", user_info.localized_first_name, user_info.localized_last_name),
                    "linkedin_conn":true,
                    "ln_token":token_data.access_token,
                    "profile":user_info.vanity_name,
                }
            )
        }
    };

    
    app_state
        .supabase_client
        .update_with_column_name(
            "Users",
            "email",
            &claims["email"],
            db_update,
        )
        .await
        .map_err(|e| {
            println!("Database update failed: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    println!("Database updated successfully");

    Ok(Html(format!(
        r#"
        <html>
        <h1>{} {}</h1>
        <img src="{}"></img>
        </html>
    "#,
        user_info.localized_first_name, user_info.localized_last_name, link_clone
    )))
}