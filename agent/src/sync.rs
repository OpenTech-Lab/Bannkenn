use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::client::{ApiClient, WhitelistEntry};
use crate::config::{OfflineAgentState, SyncState};
use crate::firewall::{
    block_ip, detect_backend, should_skip_local_firewall_enforcement, unblock_ip, FirewallBackend,
};
use crate::shared_risk::SharedRiskSnapshot;
use crate::watcher::BlockOutcome;

pub async fn persist_offline_state(
    known_blocked_ips: &Arc<RwLock<HashMap<String, String>>>,
    whitelisted_ips: &Arc<RwLock<HashSet<String>>>,
    shared_risk_snapshot: &Arc<RwLock<SharedRiskSnapshot>>,
) {
    let path = match OfflineAgentState::state_path() {
        Ok(path) => path,
        Err(err) => {
            tracing::warn!("offline-state: cannot determine state path: {}", err);
            return;
        }
    };

    let state = OfflineAgentState {
        known_blocked_ips: known_blocked_ips.read().await.clone(),
        whitelisted_ips: whitelisted_ips.read().await.iter().cloned().collect(),
        shared_risk_snapshot: shared_risk_snapshot.read().await.clone(),
    };

    if let Err(err) = state.save(&path) {
        tracing::warn!("offline-state: failed to save cache: {}", err);
    }
}

pub async fn apply_whitelist_snapshot(
    entries: Vec<WhitelistEntry>,
    known_blocked_ips: &Arc<RwLock<HashMap<String, String>>>,
    enforced_blocked_ips: &Arc<RwLock<HashSet<String>>>,
    whitelisted_ips: &Arc<RwLock<HashSet<String>>>,
    shared_risk_snapshot: &Arc<RwLock<SharedRiskSnapshot>>,
    backend: &FirewallBackend,
) {
    let new_set: HashSet<String> = entries.into_iter().map(|entry| entry.ip).collect();
    let previous_set = whitelisted_ips.read().await.clone();

    {
        let mut known = known_blocked_ips.write().await;
        known.retain(|ip, _| !new_set.contains(ip));
    }

    let to_unblock = {
        let enforced = enforced_blocked_ips.read().await;
        enforced
            .iter()
            .filter(|ip| new_set.contains(*ip))
            .cloned()
            .collect::<Vec<_>>()
    };

    let mut removed_local_blocks = 0u32;
    for ip in to_unblock {
        match unblock_ip(&ip, backend).await {
            Ok(_) => {
                enforced_blocked_ips.write().await.remove(&ip);
                removed_local_blocks += 1;
            }
            Err(err) => tracing::warn!(
                "whitelist: failed to remove local block for {}: {}",
                ip,
                err
            ),
        }
    }

    let added_entries = new_set.difference(&previous_set).count();
    let removed_entries = previous_set.difference(&new_set).count();
    let new_len = new_set.len();
    *whitelisted_ips.write().await = new_set;

    if added_entries > 0 || removed_entries > 0 || removed_local_blocks > 0 {
        tracing::info!(
            "whitelist: {} entry(s) active ({} added, {} removed, {} local block(s) cleared)",
            new_len,
            added_entries,
            removed_entries,
            removed_local_blocks
        );
    }

    persist_offline_state(known_blocked_ips, whitelisted_ips, shared_risk_snapshot).await;
}

/// Polling loop that incrementally pulls block decisions from the server,
/// applies them to the local firewall, and keeps the local whitelist cache fresh.
pub async fn sync_loop(
    client: ApiClient,
    known_blocked_ips: Arc<RwLock<HashMap<String, String>>>,
    enforced_blocked_ips: Arc<RwLock<HashSet<String>>>,
    whitelisted_ips: Arc<RwLock<HashSet<String>>>,
    shared_risk_snapshot: Arc<RwLock<SharedRiskSnapshot>>,
    block_outcome_tx: tokio::sync::mpsc::Sender<BlockOutcome>,
) {
    let state_path = match SyncState::state_path() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("sync_loop: cannot determine state path: {}", e);
            return;
        }
    };

    let mut state = SyncState::load(&state_path);
    let backend = detect_backend();
    let interval = Duration::from_secs(30);

    tracing::info!(
        "sync_loop started (last_synced_id={})",
        state.last_synced_id
    );

    loop {
        match client.fetch_whitelist().await {
            Ok(entries) => {
                apply_whitelist_snapshot(
                    entries,
                    &known_blocked_ips,
                    &enforced_blocked_ips,
                    &whitelisted_ips,
                    &shared_risk_snapshot,
                    &backend,
                )
                .await;
            }
            Err(e) => tracing::warn!("whitelist fetch failed: {}", e),
        }

        match client.fetch_decisions_since(state.last_synced_id).await {
            Ok(rows) => {
                if !rows.is_empty() {
                    tracing::info!("sync fetch: {} new decision(s)", rows.len());
                } else {
                    tracing::debug!(
                        "sync fetch: no new decisions since id={}",
                        state.last_synced_id
                    );
                }

                let whitelist_snapshot = whitelisted_ips.read().await.clone();

                for row in &rows {
                    if whitelist_snapshot.contains(&row.ip) {
                        tracing::info!(
                            "sync: skipping whitelisted IP {} from source {}",
                            row.ip,
                            row.source
                        );
                        known_blocked_ips.write().await.remove(&row.ip);
                        state.last_synced_id = row.id;
                        continue;
                    }

                    if should_skip_local_firewall_enforcement(&row.ip) {
                        tracing::warn!(
                            "sync: skipping firewall enforcement for local/reserved address {}",
                            row.ip
                        );
                        known_blocked_ips
                            .write()
                            .await
                            .insert(row.ip.clone(), row.source.clone());
                        state.last_synced_id = row.id;
                        continue;
                    }

                    match block_ip(&row.ip, &backend).await {
                        Ok(_) => {
                            tracing::info!("sync: blocked IP {}", row.ip);
                            enforced_blocked_ips.write().await.insert(row.ip.clone());
                            let _ = block_outcome_tx
                                .send(BlockOutcome::Enforced(row.ip.clone()))
                                .await;
                        }
                        Err(e) => tracing::warn!("sync block failed for {}: {}", row.ip, e),
                    }
                    known_blocked_ips
                        .write()
                        .await
                        .insert(row.ip.clone(), row.source.clone());
                    state.last_synced_id = row.id;
                }

                if !rows.is_empty() {
                    if let Err(e) = state.save(&state_path) {
                        tracing::warn!("sync: failed to save state: {}", e);
                    }
                    persist_offline_state(
                        &known_blocked_ips,
                        &whitelisted_ips,
                        &shared_risk_snapshot,
                    )
                    .await;
                }
            }
            Err(e) => tracing::warn!("sync fetch failed: {}", e),
        }

        match client.fetch_shared_risk_profile().await {
            Ok(profile) => {
                *shared_risk_snapshot.write().await = profile;
                persist_offline_state(&known_blocked_ips, &whitelisted_ips, &shared_risk_snapshot)
                    .await;
            }
            Err(e) => tracing::warn!("shared-risk fetch failed: {}", e),
        }

        tokio::time::sleep(interval).await;
    }
}
