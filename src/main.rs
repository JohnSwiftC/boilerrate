use axum::{
    Router,
    routing::{get, post},
};

use hmac::{Hmac, Mac};

use std::sync::Arc;

mod endpoints;

#[tokio::main]
async fn main() {
    let jwt_state = endpoints::JWTState {
        private_key: Hmac::new_from_slice(b"temp secret").unwrap(),
    };

    let shared_jwt_state = Arc::new(jwt_state);

    let router = Router::new()
        .route("/", get(endpoints::get_root))
        .with_state(shared_jwt_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to open socket");

    axum::serve(listener, router).await.unwrap();
}
