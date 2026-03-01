use crate::config::AgentConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};
use regex::Regex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

/// Event indicating an IP should be blocked
#[derive(Debug, Clone)]
pub struct BlockEvent {
    pub ip: String,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

/// Monitors log file for failed login attempts and sends block events
/// when threshold is exceeded within a time window
pub async fn watch(config: Arc<AgentConfig>, tx: mpsc::Sender<BlockEvent>) -> Result<()> {
    // All patterns that indicate a hostile IP: (regex, human-readable reason).
    // Each pattern must capture the IPv4 address in group 1.
    let patterns: Vec<(Regex, &str)> = vec![
        // Classic SSH brute-force
        (
            Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")?,
            "Failed SSH password",
        ),
        // Unknown username probes
        (
            Regex::new(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)")?,
            "Invalid SSH user",
        ),
        // Connection dropped after too many failures (sshd preauth)
        (
            Regex::new(
                r"Connection closed by (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
            )?,
            "SSH repeated connection close",
        ),
        // Explicit disconnect due to too many auth failures
        (
            Regex::new(
                r"Disconnecting (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
            )?,
            "SSH disconnected: too many auth failures",
        ),
        // sshd hard limit on authentication rounds
        (
            Regex::new(
                r"maximum authentication attempts exceeded for .* from (\d+\.\d+\.\d+\.\d+)",
            )?,
            "SSH max auth attempts exceeded",
        ),
        // Port scanners that never send an SSH banner
        (
            Regex::new(r"Did not receive identification string from (\d+\.\d+\.\d+\.\d+)")?,
            "SSH port scan (no identification string)",
        ),
        // Clients with incompatible algorithms — common in automated scans
        (
            Regex::new(r"Unable to negotiate with (\d+\.\d+\.\d+\.\d+)")?,
            "SSH port scan (unable to negotiate)",
        ),
    ];

    // Sliding window counters: IP -> deque of attempt timestamps
    let mut ip_attempts: HashMap<String, VecDeque<Instant>> = HashMap::new();

    // IPs already blocked — avoids re-reporting to the server on every
    // subsequent threshold crossing once a block is in effect.
    let mut already_blocked: HashSet<String> = HashSet::new();

    let mut file = open_log_at_end(&config.log_path).await?;
    let mut file_pos = file.seek(std::io::SeekFrom::Current(0)).await?;

    let mut buffer = String::new();
    let poll_interval = Duration::from_millis(200);

    loop {
        // Detect log rotation: if the file on disk is now shorter than our
        // read position the log was rotated. Reopen from the start of the
        // new file so we don't miss entries.
        if let Ok(meta) = tokio::fs::metadata(&config.log_path).await {
            if meta.len() < file_pos {
                tracing::info!("Log rotation detected, reopening {}", config.log_path);
                file = open_log_from_start(&config.log_path).await?;
                file_pos = 0;
            }
        }

        buffer.clear();
        match file.read_to_string(&mut buffer).await {
            Ok(0) => {
                sleep(poll_interval).await;
                continue;
            }
            Ok(_) => {
                file_pos = file.seek(std::io::SeekFrom::Current(0)).await?;

                for line in buffer.lines() {
                    for (re, reason) in &patterns {
                        if let Some(caps) = re.captures(line) {
                            if let Some(m) = caps.get(1) {
                                let ip = m.as_str().to_string();
                                process_failed_attempt(
                                    &ip,
                                    &mut ip_attempts,
                                    &mut already_blocked,
                                    &config,
                                    &tx,
                                    reason,
                                )
                                .await;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Error reading log file: {}", e);
                sleep(poll_interval).await;
            }
        }
    }
}

/// Open log file and seek to the end (normal startup — skip existing content).
async fn open_log_at_end(path: &str) -> Result<File> {
    let mut file = File::open(path).await?;
    file.seek(std::io::SeekFrom::End(0)).await?;
    Ok(file)
}

/// Open log file from the beginning (used after log rotation is detected).
async fn open_log_from_start(path: &str) -> Result<File> {
    Ok(File::open(path).await?)
}

/// Record a failed attempt and fire a BlockEvent when threshold is reached.
async fn process_failed_attempt(
    ip: &str,
    ip_attempts: &mut HashMap<String, VecDeque<Instant>>,
    already_blocked: &mut HashSet<String>,
    config: &AgentConfig,
    tx: &mpsc::Sender<BlockEvent>,
    reason: &str,
) {
    // Already blocked — firewall rule is in place, no need to re-report.
    if already_blocked.contains(ip) {
        return;
    }

    let now = Instant::now();
    let window = Duration::from_secs(config.window_secs);

    let attempts = ip_attempts.entry(ip.to_string()).or_default();

    // Prune attempts that fell outside the sliding window.
    while let Some(&oldest) = attempts.front() {
        if now.duration_since(oldest) > window {
            attempts.pop_front();
        } else {
            break;
        }
    }

    attempts.push_back(now);

    if attempts.len() >= config.threshold as usize {
        tracing::info!(
            "Threshold exceeded for IP {}: {} attempts in window",
            ip,
            attempts.len()
        );

        let block_event = BlockEvent {
            ip: ip.to_string(),
            reason: format!("{} (threshold: {})", reason, config.threshold),
            timestamp: Utc::now(),
        };

        let _ = tx.send(block_event).await;

        // Mark as permanently blocked and drop the attempt history.
        already_blocked.insert(ip.to_string());
        ip_attempts.remove(ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failed_password_regex() {
        let re = Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Jan 15 10:23:45 server sshd[1234]: Failed password for user from 192.168.1.100 port 22 ssh2";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "192.168.1.100"
        );

        // Also matches "Failed password for invalid user"
        let line2 = "Failed password for invalid user admin from 10.0.0.1 port 22 ssh2";
        assert_eq!(
            re.captures(line2).unwrap().get(1).unwrap().as_str(),
            "10.0.0.1"
        );
    }

    #[test]
    fn test_invalid_user_regex() {
        let re = Regex::new(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Jan 15 10:25:12 server sshd[5678]: Invalid user admin from 10.0.0.50 port 22";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "10.0.0.50"
        );
    }

    #[test]
    fn test_connection_closed_regex() {
        let re = Regex::new(
            r"Connection closed by (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
        )
        .unwrap();

        let line1 = "Connection closed by invalid user root 203.0.113.5 port 41022 [preauth]";
        assert_eq!(
            re.captures(line1).unwrap().get(1).unwrap().as_str(),
            "203.0.113.5"
        );

        let line2 =
            "Connection closed by authenticating user admin 198.51.100.9 port 59900 [preauth]";
        assert_eq!(
            re.captures(line2).unwrap().get(1).unwrap().as_str(),
            "198.51.100.9"
        );
    }

    #[test]
    fn test_disconnecting_regex() {
        let re = Regex::new(
            r"Disconnecting (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
        )
        .unwrap();
        let line = "Disconnecting invalid user postgres 172.16.0.7 port 55000: Too many authentication failures [preauth]";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "172.16.0.7"
        );
    }

    #[test]
    fn test_max_auth_attempts_regex() {
        let re = Regex::new(
            r"maximum authentication attempts exceeded for .* from (\d+\.\d+\.\d+\.\d+)",
        )
        .unwrap();
        let line = "error: maximum authentication attempts exceeded for invalid user git from 192.0.2.1 port 12345 ssh2";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "192.0.2.1"
        );
    }

    #[test]
    fn test_no_identification_regex() {
        let re =
            Regex::new(r"Did not receive identification string from (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Did not receive identification string from 198.51.100.42 port 4444";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "198.51.100.42"
        );
    }

    #[test]
    fn test_unable_to_negotiate_regex() {
        let re = Regex::new(r"Unable to negotiate with (\d+\.\d+\.\d+\.\d+)").unwrap();
        let line = "Unable to negotiate with 203.0.113.77 port 60000: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1";
        assert_eq!(
            re.captures(line).unwrap().get(1).unwrap().as_str(),
            "203.0.113.77"
        );
    }
}
