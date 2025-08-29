use axum::{
    Router,
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

extern crate dotenv;
use dotenv::dotenv;
use supabase_rs::{SupabaseClient, graphql::utils::format_endpoint::endpoint};

mod db;
mod endpoints;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let supabase_client = SupabaseClient::new(
        std::env::var("SUPABASE_URL").expect("No SUPABASE_URL"),
        std::env::var("SUPABASE_KEY").expect("No SUPABASE_KEY"),
    )
    .expect("Failed to establish Supabase connections");

    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let app_state = Arc::new(endpoints::AppState {
        private_key: Hmac::new_from_slice(secret.as_bytes()).unwrap(),
        supabase_client: Arc::new(supabase_client),
    });

    let router = Router::new()
        .route("/", get(endpoints::get_root))
        .route("/create_user", post(endpoints::post_new_user))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to open socket");

    axum::serve(listener, router).await.unwrap();
}
