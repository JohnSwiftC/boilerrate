use axum::{
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};

mod endpoints;

#[tokio::main]
async fn main() {
    let router = Router::new()
        .route("/", get(endpoints::get_root));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.expect("Failed to open socket");

    axum::serve(listener, router).await.unwrap();
}