use axum::{
    http::HeaderValue, routing::{get, post}, Router
};
use hmac::{Hmac, Mac};
use reqwest::{header::{AUTHORIZATION, CONTENT_TYPE}, Method};
use std::sync::Arc;

extern crate dotenv;
use dotenv::dotenv;
use supabase_rs::{SupabaseClient};

use tower_http::cors::{CorsLayer, Any};
use std::time::Duration;

use mailgun_rs::Mailgun;

mod db;
mod endpoints;
mod oauth;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let supabase_client = SupabaseClient::new(
        std::env::var("SUPABASE_URL").expect("No SUPABASE_URL"),
        std::env::var("SUPABASE_KEY").expect("No SUPABASE_KEY"),
    )
    .expect("Failed to establish Supabase connections");

    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let linkedin_config = oauth::LinkedInConfig {
        client_id: std::env::var("L_CID").expect("No L_CID"),
        client_secret: std::env::var("L_SECRET").expect("No L_SECRET"),
    };

    let mailgun_api_key = std::env::var("MAILGUN_KEY").expect("No MAILGUN_KEY");

    let email_domain = std::env::var("MAILGUN_DOMAIN").expect("No MAILGUN_DOMAIN");

    let mailgun = Mailgun {
        api_key: mailgun_api_key,
        domain: email_domain,
    };

    let app_state = Arc::new(endpoints::AppState {
        private_key: Hmac::new_from_slice(secret.as_bytes()).unwrap(),
        supabase_client: Arc::new(supabase_client),
        l_config: Arc::new(linkedin_config),
        mailgun: Arc::new(mailgun),
    });

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        .max_age(Duration::from_secs(3600));

    let router = Router::new()
        .route("/", get(endpoints::get_root))
        .route("/auth_url", get(oauth::get_linkedin_auth_url))
        .route("/create_user", post(endpoints::post_new_user))
        .route("/verify", get(endpoints::verify_registration))
        .route("/verify", post(endpoints::verify_form))
        .route("/oauth/get_route", get(oauth::get_linkedin_auth_url))
        .route("/oauth/callback", get(oauth::linkedin_callback))
        .route("/login", post(endpoints::login))
        .with_state(app_state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to open socket");

    axum::serve(listener, router).await.unwrap();
}
