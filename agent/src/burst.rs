use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Configuration for burst detection.
///
/// When `enabled = true`, rapid-fire same-category attempts from a single IP
/// are collapsed into one block event as soon as `threshold` hits arrive
/// within `window_secs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurstConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_burst_window_secs")]
    pub window_secs: u64,
    #[serde(default = "default_burst_threshold")]
    pub threshold: u32,
}

fn default_burst_window_secs() -> u64 {
    10
}

fn default_burst_threshold() -> u32 {
    3
}

impl Default for BurstConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: default_burst_window_secs(),
            threshold: default_burst_threshold(),
        }
    }
}

/// Strip trailing count annotations from a reason string so that
/// `"SSH invalid user (2/5)"` and `"SSH invalid user (3/5)"` map to
/// the same category bucket `"SSH invalid user"`.
pub fn categorize_reason(reason: &str) -> &str {
    if let Some(idx) = reason.rfind(" (") {
        let suffix = &reason[idx + 2..];
        if suffix.ends_with(')') {
            return &reason[..idx];
        }
    }
    reason
}

/// Tracks rapid-fire attempt counts per `(ip, reason_category)` pair.
pub struct BurstDetector {
    attempts: HashMap<(String, String), VecDeque<Instant>>,
}

impl Default for BurstDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BurstDetector {
    pub fn new() -> Self {
        Self {
            attempts: HashMap::new(),
        }
    }

    /// Record one attempt and return the burst hit count if the burst threshold
    /// is reached within the window, or `None` if not.
    ///
    /// Returns `None` immediately when `cfg.enabled == false`.
    pub fn record(&mut self, ip: &str, reason: &str, cfg: &BurstConfig) -> Option<usize> {
        if !cfg.enabled {
            return None;
        }

        let category = categorize_reason(reason).to_string();
        let key = (ip.to_string(), category);
        let now = Instant::now();
        let window = Duration::from_secs(cfg.window_secs);

        let deque = self.attempts.entry(key).or_default();

        // Evict entries outside the window.
        while let Some(&oldest) = deque.front() {
            if now.duration_since(oldest) > window {
                deque.pop_front();
            } else {
                break;
            }
        }

        deque.push_back(now);

        let count = deque.len();
        if count >= cfg.threshold as usize {
            Some(count)
        } else {
            None
        }
    }

    /// Remove all burst tracking state for the given IP.
    pub fn clear_ip(&mut self, ip: &str) {
        self.attempts.retain(|(k_ip, _), _| k_ip != ip);
    }
}

#[cfg(test)]
#[path = "../tests/unit/burst_tests.rs"]
mod tests;
