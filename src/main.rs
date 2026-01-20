// This task aims to introduce a basic API server that acts as the interface for any Web requests.
// The task does NOT include implementing API calls for all elements, but rather to provide an initial version of an API server, providing support for:

// - An example route that returns a simple JSON response
// - Authentication mechanisms (e.g. login, logout, token handling)

// Before jumping into code, here is how the authentication flow will look:

// - Login: Client sends credentials; Server validates and returns a JWT.
// - Storage: Client stores the JWT (usually in localStorage or an HttpOnly cookie).
// - Authorization: Client sends the JWT in the Authorization: Bearer <token> header for protected routes.

mod auth;
mod handlers;
mod middleware;
mod models;
mod state;

use axum::{Router, routing::get, routing::post};
use handlers::*;
use state::AppState;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let jwt_secret = "jwt_secret";

    // Create shared state wrapped in Arc (Atomic Reference Counter)
    let state = Arc::new(AppState {
        jwt_secret: jwt_secret.to_string(),
    });

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/login", post(login))
        .route("/protected", get(protected_route))
        .route("/logout", post(logout))
        .with_state(state); // Attach state to router

    let address = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();

    println!("Server running on http://{address}");

    axum::serve(listener, app).await.unwrap();
}
