use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};

use crate::models::Claims;

pub enum AuthError {
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

pub fn create_token(username: String, secret: &str) -> Result<String, AuthError> {
    let expiration: usize = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .ok_or(AuthError::TokenCreation)?
        .timestamp() as usize;

    let claims = Claims {
        sub: username,
        exp: expiration,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AuthError::TokenCreation)
}

pub fn verify_token(token: &str, secret: &str) -> Result<Claims, AuthError> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map(|data| data.claims)
    .map_err(|_| AuthError::InvalidToken)
}

pub fn extract_token(headers: &HeaderMap) -> Result<String, AuthError> {
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

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Claims>()
            .cloned()
            .ok_or(AuthError::InvalidToken)
    }
}