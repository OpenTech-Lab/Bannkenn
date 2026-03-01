use crate::db::Db;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;

pub struct AppState {
    pub db: Arc<Db>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ListCommunityIpsParams {
    pub limit: Option<i64>,
}

pub async fn list_ips(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListCommunityIpsParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let limit = params.limit.unwrap_or(1000).clamp(1, 5000);
    let rows = state
        .db
        .list_community_ips(limit)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(rows))
}
