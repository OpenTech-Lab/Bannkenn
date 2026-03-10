mod auth;
mod config;
mod db;
mod feeds;
mod geoip;
mod routes;

use anyhow::{bail, Context};
use axum::{
    middleware,
    routing::{get, patch, post},
    Router,
};
use config::ServerConfig;
use db::Db;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower_http::trace::TraceLayer;
use tracing::{error, info};

pub struct AppState {
    pub db: Arc<Db>,
    pub config: Arc<ServerConfig>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if matches!(std::env::args().nth(1).as_deref(), Some("healthcheck")) {
        return run_healthcheck().await;
    }

    init_tracing();
    run_server().await
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing_subscriber::filter::LevelFilter::INFO.into()),
        )
        .init();
}

async fn run_server() -> anyhow::Result<()> {
    info!("Starting BannKenn server...");

    // Load configuration
    let config = ServerConfig::load()?;
    info!("Configuration loaded: bind={}", config.bind);

    // Create database
    let db = Db::new(&config.db_path).await?;
    info!("Database initialized at {}", config.db_path);

    let db = Arc::new(db);
    let config = Arc::new(config);

    // Run geo backfill in background so startup/healthcheck are not blocked on large datasets.
    let db_for_backfill = db.clone();
    tokio::spawn(async move {
        match db_for_backfill.backfill_decision_geoip_unknowns().await {
            Ok(count) => info!("GeoIP backfill complete: {} decision rows updated", count),
            Err(err) => error!("GeoIP backfill failed: {}", err),
        }
    });

    // Start feed task
    feeds::start_feed_task(db.clone()).await;
    info!("Feed task started");

    // Start cross-agent campaign detection task.
    // Every 60 seconds: scan recent telemetry from all agents, find attack
    // categories that appear from many distinct IPs across multiple agents,
    // and auto-create block decisions for every involved IP.
    let db_for_campaign = db.clone();
    tokio::spawn(async move {
        let interval = tokio::time::Duration::from_secs(60);
        info!("Campaign detection task started (interval=60s)");

        loop {
            tokio::time::sleep(interval).await;

            // Configuration: campaign declared when ≥5 distinct IPs from ≥2 agents
            // use the same attack category within the last 10 minutes.
            match db_for_campaign.detect_campaign_ips(600, 5, 2).await {
                Ok(campaign_ips) if !campaign_ips.is_empty() => {
                    info!(
                        "Campaign detection: {} IP(s) identified across agents",
                        campaign_ips.len()
                    );
                    for (ip, category) in campaign_ips {
                        let reason = format!("Campaign auto-block: {}", category);
                        match db_for_campaign
                            .insert_decision(&ip, &reason, "block", "campaign")
                            .await
                        {
                            Ok(id) => info!(
                                "Campaign auto-block: IP={} category='{}' decision_id={}",
                                ip, category, id
                            ),
                            Err(e) => {
                                error!("Failed to insert campaign decision for {}: {}", ip, e)
                            }
                        }
                    }
                }
                Ok(_) => {
                    // No campaigns detected this cycle.
                }
                Err(e) => error!("Campaign detection failed: {}", e),
            }
        }
    });

    let auth_config = auth::AuthConfig {
        jwt_secret: config.jwt_secret.clone(),
    };

    // Health endpoint (no auth required)
    let health_route = get(routes::health::health);

    // Auth middleware (protects POST /decisions only)
    let auth_middleware_layer =
        middleware::from_fn_with_state(Arc::new(auth_config), auth::auth_middleware);

    // Agent registration/listing is public; heartbeat is protected
    let agents_state = Arc::new(routes::agents::AppState {
        db: db.clone(),
        jwt_secret: config.jwt_secret.clone(),
    });
    let agents_public_router = Router::new()
        .route("/", get(routes::agents::list))
        .route("/register", post(routes::agents::register))
        .with_state(agents_state.clone());

    let agents_protected_router = Router::new()
        .route("/heartbeat", post(routes::agents::heartbeat))
        .route("/shared-risk", get(routes::agents::shared_risk_profile))
        .with_state(agents_state.clone())
        .layer(auth_middleware_layer.clone());

    let agents_admin_router = Router::new()
        .route("/:id/backfill-geoip", post(routes::agents::backfill_geoip))
        .route("/:id/telemetry", get(routes::agents::list_telemetry))
        .route("/:id/decisions", get(routes::agents::list_decisions))
        .route(
            "/:id",
            patch(routes::agents::update_nickname).delete(routes::agents::delete_agent),
        )
        .with_state(agents_state);

    let decisions_state = Arc::new(routes::decisions::AppState { db: db.clone() });
    let telemetry_state = Arc::new(routes::telemetry::AppState { db: db.clone() });
    let community_state = Arc::new(routes::community::AppState { db: db.clone() });
    let ssh_logins_state = Arc::new(routes::ssh_logins::AppState { db: db.clone() });

    // Public: GET /api/v1/decisions
    let decisions_read = Router::new()
        .route("/", get(routes::decisions::list))
        .with_state(decisions_state.clone());

    // Protected: POST /api/v1/decisions
    let decisions_write = Router::new()
        .route("/", post(routes::decisions::create))
        .with_state(decisions_state)
        .layer(auth_middleware_layer.clone());

    // Public: GET /api/v1/telemetry
    let telemetry_read = Router::new()
        .route("/", get(routes::telemetry::list))
        .with_state(telemetry_state.clone());

    // Protected: POST /api/v1/telemetry
    let telemetry_write = Router::new()
        .route("/", post(routes::telemetry::create))
        .with_state(telemetry_state)
        .layer(auth_middleware_layer.clone());

    // Public: GET /api/v1/ssh-logins
    let ssh_logins_read = Router::new()
        .route("/", get(routes::ssh_logins::list))
        .with_state(ssh_logins_state.clone());

    // Protected: POST /api/v1/ssh-logins
    let ssh_logins_write = Router::new()
        .route("/", post(routes::ssh_logins::create))
        .with_state(ssh_logins_state)
        .layer(auth_middleware_layer.clone());

    // Combine all routes
    let router = Router::new()
        .route("/api/v1/health", health_route)
        .nest(
            "/api/v1/agents",
            agents_public_router
                .merge(agents_protected_router)
                .merge(agents_admin_router),
        )
        .nest("/api/v1/decisions", decisions_read.merge(decisions_write))
        .nest("/api/v1/telemetry", telemetry_read.merge(telemetry_write))
        .nest(
            "/api/v1/ssh-logins",
            ssh_logins_read.merge(ssh_logins_write),
        )
        .route(
            "/api/v1/community/ips",
            get(routes::community::list_ips).with_state(community_state.clone()),
        )
        .route(
            "/api/v1/community/feeds",
            get(routes::community::list_feeds).with_state(community_state.clone()),
        )
        .route(
            "/api/v1/community/feeds/:source/ips",
            get(routes::community::list_feed_ips).with_state(community_state),
        )
        .layer(TraceLayer::new_for_http());

    // Parse bind address
    let addr: SocketAddr = config.bind.parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Server listening on {}", addr);

    // Setup graceful shutdown
    let server = axum::serve(listener, router);

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                error!("Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received, gracefully shutting down...");
        }
    }

    info!("Server shut down successfully");
    Ok(())
}

async fn run_healthcheck() -> anyhow::Result<()> {
    let config = ServerConfig::load()?;
    let target = healthcheck_target(&config.bind)?;
    let mut stream = tokio::net::TcpStream::connect(target)
        .await
        .with_context(|| format!("failed to connect to {}", target))?;

    stream
        .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .context("failed to send healthcheck request")?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .context("failed to read healthcheck response")?;

    if healthcheck_response_ok(&response) {
        return Ok(());
    }

    bail!("unexpected healthcheck response")
}

fn healthcheck_target(bind: &str) -> anyhow::Result<SocketAddr> {
    let addr: SocketAddr = bind.parse()?;
    let ip = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };

    Ok(SocketAddr::new(ip, addr.port()))
}

fn healthcheck_response_ok(response: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(response) else {
        return false;
    };

    let Some((status_line, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };

    if !status_line.contains("200") {
        return false;
    }

    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|json| {
            json.get("status")
                .and_then(|status| status.as_str())
                .map(|status| status == "ok")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_creation() {
        let config = ServerConfig::default();
        let config = Arc::new(config);
        assert_eq!(config.bind, "0.0.0.0:3022");
    }

    #[test]
    fn healthcheck_target_uses_loopback_for_unspecified_bind() {
        let addr = healthcheck_target("0.0.0.0:3022").unwrap();
        assert_eq!(addr, "127.0.0.1:3022".parse().unwrap());
    }

    #[test]
    fn healthcheck_target_preserves_explicit_host() {
        let addr = healthcheck_target("192.168.1.10:4040").unwrap();
        assert_eq!(addr, "192.168.1.10:4040".parse().unwrap());
    }

    #[test]
    fn healthcheck_response_ok_accepts_expected_payload() {
        let response =
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{\"status\":\"ok\"}";
        assert!(healthcheck_response_ok(response));
    }

    #[test]
    fn healthcheck_response_ok_rejects_unhealthy_payload() {
        let response =
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\n\r\n{\"status\":\"down\"}";
        assert!(!healthcheck_response_ok(response));
    }
}
