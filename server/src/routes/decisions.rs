use crate::auth::AuthenticatedAgent;
use crate::db::Db;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Db>,
}

#[derive(Debug, Deserialize)]
pub struct CreateDecisionRequest {
    pub ip: String,
    pub reason: String,
    pub action: String,
    pub timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateDecisionResponse {
    pub id: Option<i64>,
    pub skipped: bool,
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    agent: AuthenticatedAgent,
    Json(payload): Json<CreateDecisionRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let id = state
        .db
        .insert_decision_with_timestamp(
            &payload.ip,
            &payload.reason,
            &payload.action,
            &agent.0,
            payload.timestamp.as_deref(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let status = if id.is_some() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((
        status,
        Json(CreateDecisionResponse {
            id,
            skipped: status == StatusCode::OK,
        }),
    ))
}

#[derive(Debug, Deserialize)]
pub struct ListParams {
    pub since_id: Option<i64>,
    pub limit: Option<i64>,
    pub scope: Option<String>,
}

pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let scope = params.scope.as_deref().unwrap_or("all");
    let limit = params.limit.unwrap_or(match scope {
        "local" => 250,
        _ => 100,
    });
    let limit = limit.clamp(1, 2000);

    let decisions = match (params.since_id, scope) {
        (Some(id), "all") => state
            .db
            .list_decisions_since(id, limit)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        (Some(id), "local") => state
            .db
            .list_local_decisions_since(id, limit)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        (Some(_), _) => return Err(StatusCode::BAD_REQUEST),
        (None, "all") => state
            .db
            .list_decisions(limit)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        (None, "local") => state
            .db
            .list_local_decisions(limit)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        (None, _) => return Err(StatusCode::BAD_REQUEST),
    };

    Ok(Json(decisions))
}
