// This task aims to introduce a basic API server that acts as the interface for any Web requests.
// The task does NOT include implementing API calls for all elements, but rather to provide an initial version of an API server, providing support for:

// - An example route that returns a simple JSON response
// - Authentication mechanisms (e.g. login, logout, token handling)

// Before jumping into code, here is how the authentication flow will look:

// - Login: Client sends credentials; Server validates and returns a JWT.
// - Storage: Client stores the JWT (usually in localStorage or an HttpOnly cookie).
// - Authorization: Client sends the JWT in the Authorization: Bearer <token> header for protected routes.

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    routing::post,
};

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginResponse {
    token: String,
    message: String,
}

enum AuthError {
    InvalidCredentials,
    TokenCreation,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid Credentials"),
            AuthError::TokenCreation => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create token")
            }
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
        };
        (status, message).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(Clone)]
struct AppState {
    jwt_secret: String,
}

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

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy"
    }))
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    // Check credentials (hardcoded for now)
    if payload.username != "admin" || payload.password != "password123" {
        return Err(AuthError::InvalidCredentials);
    }

    let expiration: usize = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .ok_or(AuthError::TokenCreation)?
        .timestamp() as usize;

    let claims = Claims {
        sub: payload.username.clone(),
        exp: expiration,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(|_| AuthError::TokenCreation)?;

    Ok(Json(LoginResponse {
        token: (token),
        message: ("Login successful").to_string(),
    }))
}

fn verify_token(token: &str, secret: &str) -> Result<Claims, AuthError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| AuthError::InvalidToken)
}

fn extract_token(headers: &HeaderMap) -> Result<String, AuthError> {
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(AuthError::InvalidToken)?;

    // Expected format: "Bearer <token>"
    if !auth_header.starts_with("Bearer ") {
        return Err(AuthError::InvalidToken);
    }

    let token = auth_header.trim_start_matches("Bearer ").to_string();
    Ok(token)
}

async fn protected_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AuthError> {
    // Extract and verify token

    let token = extract_token(&headers)?;
    let claims = verify_token(&token, &state.jwt_secret)?;

    // If we get here, token is valid!
    Ok(Json(serde_json::json!({
        "message": "Access granted to protected resources",
        "username": claims.sub
    })))
}

async fn logout() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Logout successful - discard your token on the client side"
    }))
}