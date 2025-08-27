use axum::{
    Router,
    routing::{get, post},
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

extern crate dotenv;
use dotenv::dotenv;

mod endpoints;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let jwt_state = endpoints::JWTState {
        private_key: Hmac::new_from_slice(secret.as_bytes()).unwrap(),
    };

    let shared_jwt_state = Arc::new(jwt_state);

    let router = Router::new()
        .route("/", get(endpoints::get_root))
        .route("/create_user", post(endpoints::post_new_user))
        .with_state(shared_jwt_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to open socket");

    axum::serve(listener, router).await.unwrap();
}
