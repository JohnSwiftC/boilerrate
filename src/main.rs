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

mod endpoints;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let supabase_client = SupabaseClient::new(
        std::env::var("SUPABASE_URL").expect("No SUPABASE_URL"),
        std::env::var("SUPABASE_KEY").expect("No SUPABASE_KEY"),
    )
    .expect("Failed to establish Supabase connections");

    let shared_supabase_state = Arc::new(endpoints::SupabaseState {
        client: supabase_client,
    });

    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let jwt_state = endpoints::JWTState {
        private_key: Hmac::new_from_slice(secret.as_bytes()).unwrap(),
    };

    let shared_jwt_state = Arc::new(jwt_state);

    let router = Router::new()
        .route("/", get(endpoints::get_root))
        .route("/create_user", post(endpoints::post_new_user))
        .with_state(shared_jwt_state)
        .with_state(shared_supabase_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to open socket");

    axum::serve(listener, router).await.unwrap();
}
