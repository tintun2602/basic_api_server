use crate::auth::*;
use crate::models::*;
use crate::state::AppState;
use std::sync::Arc;

use axum::{Json, extract::State, http::HeaderMap};

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthError> {
    // Check credentials (hardcoded for now)
    if payload.username != "admin" || payload.password != "password123" {
        return Err(AuthError::InvalidCredentials);
    }

    let token = create_token(payload.username.clone(), &state.jwt_secret)?;

    Ok(Json(LoginResponse {
        token,
        message: ("Login successful").to_string(),
    }))
}

pub async fn protected_route(
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

pub async fn logout() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Logout successful - discard your token on the client side"
    }))
}

pub async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy"
    }))
}

pub async fn user_profile(claims:Claims) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user": claims.sub, 
        "message": "Here is your profile", 
        "account_created": "2026.01.01"
    }))
}

pub async fn dashboard(claims:Claims) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user": claims.sub, 
        "message": "Welcome to your dashboard", 
        "stats": {
            "login_count": 42, 
            "last_login": "2025.12.12"
        }
    }))
}