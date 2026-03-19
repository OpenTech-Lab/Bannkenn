use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Configuration for the host risk level tracker.
///
/// When `enabled = true`, the effective block threshold is multiplied down
/// as recent block events accumulate, making already-targeted hosts more
/// sensitive to further attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskLevelConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Time window (seconds) in which recent blocks are counted.
    #[serde(default = "default_risk_window_secs")]
    pub window_secs: u64,
    /// Number of blocks within the window that corresponds to maximum risk.
    #[serde(default = "default_max_blocks")]
    pub max_blocks: u32,
    /// Multiplier applied to the threshold when risk score is 1.0.
    /// E.g. 0.4 means the threshold drops to 40 % of its base at maximum risk.
    #[serde(default = "default_min_threshold_multiplier")]
    pub min_threshold_multiplier: f64,
}

fn default_risk_window_secs() -> u64 {
    3600
}

fn default_max_blocks() -> u32 {
    20
}

fn default_min_threshold_multiplier() -> f64 {
    0.4
}

impl Default for RiskLevelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: default_risk_window_secs(),
            max_blocks: default_max_blocks(),
            min_threshold_multiplier: default_min_threshold_multiplier(),
        }
    }
}

/// Tracks recent block events to compute an adaptive risk score for this host.
pub struct HostRiskLevel {
    block_timestamps: VecDeque<Instant>,
}

impl Default for HostRiskLevel {
    fn default() -> Self {
        Self::new()
    }
}

impl HostRiskLevel {
    pub fn new() -> Self {
        Self {
            block_timestamps: VecDeque::new(),
        }
    }

    /// Record that a block just occurred.
    pub fn record_block(&mut self) {
        self.block_timestamps.push_back(Instant::now());
    }

    /// Compute the risk score in [0.0, 1.0].
    ///
    /// score = (recent_blocks / max_blocks).clamp(0, 1)
    ///
    /// Also prunes stale entries older than `window_secs`.
    pub fn risk_score(&mut self, cfg: &RiskLevelConfig) -> f64 {
        let now = Instant::now();
        let window = Duration::from_secs(cfg.window_secs);

        while let Some(&oldest) = self.block_timestamps.front() {
            if now.duration_since(oldest) > window {
                self.block_timestamps.pop_front();
            } else {
                break;
            }
        }

        let recent = self.block_timestamps.len() as f64;
        let max = cfg.max_blocks as f64;
        (recent / max).clamp(0.0, 1.0)
    }

    /// Return the effective threshold after applying the risk multiplier.
    ///
    /// Linear interpolation:
    ///   score=0   → multiplier=1.0         (no change)
    ///   score=1   → multiplier=min_threshold_multiplier
    ///
    /// Returns the base `threshold` unchanged when `cfg.enabled == false`.
    /// Always returns at least 1.
    pub fn apply(&mut self, threshold: u32, cfg: &RiskLevelConfig) -> u32 {
        if !cfg.enabled {
            return threshold;
        }

        let score = self.risk_score(cfg);
        let multiplier = 1.0 - score * (1.0 - cfg.min_threshold_multiplier);
        let effective = (threshold as f64 * multiplier).round() as u32;
        effective.max(1)
    }
}

#[cfg(test)]
#[path = "../tests/unit/risk_level_tests.rs"]
mod tests;
