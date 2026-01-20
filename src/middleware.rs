use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::auth::{AuthError, extract_token, verify_token};
use crate::models::Claims;
use crate::state::AppState;

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    // Extract and verify token
    let token = extract_token(req.headers())?;
    let claims = verify_token(&token, &state.jwt_secret)?;

    // Store claims in request extensions so handlers can access them
    req.extensions_mut().insert(claims);

    // Continue to the actual handler
    Ok(next.run(req).await)
}
