//! Event-type risk ranking and surge detection.
//!
//! ## Two independent systems work together:
//!
//! 1. **Risk rank**: every event type has a static base rank (Low → Critical).
//!    The rank is derived from the reason string and dictates a threshold
//!    *multiplier* — Critical events block at ¼ the normal threshold.
//!
//! 2. **Surge detector**: a per-category sliding-window counter tracks the
//!    *current rate* vs. an exponential-moving-average baseline.  When the rate
//!    exceeds `baseline × surge_ratio`, the category is in surge mode and an
//!    additional multiplier is applied on top of the rank multiplier.
//!
//! Combined: `effective = round(base × rank_mult × (surge ? surge_reduction : 1))`

use crate::burst::categorize_reason;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

// ── Risk Rank ────────────────────────────────────────────────────────────────

/// Severity rank assigned to each event type.
///
/// Higher rank → lower threshold multiplier → the agent blocks sooner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskRank {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl RiskRank {
    /// Fraction of the base threshold that applies for this rank.
    ///
    /// | Rank     | Multiplier | Effect                             |
    /// |----------|------------|------------------------------------|
    /// | Low      | 1.00       | No change                          |
    /// | Medium   | 0.75       | Block at 75 % of normal threshold  |
    /// | High     | 0.50       | Block at 50 % of normal threshold  |
    /// | Critical | 0.25       | Block at 25 % of normal threshold  |
    pub fn threshold_multiplier(self) -> f64 {
        match self {
            Self::Low => 1.00,
            Self::Medium => 0.75,
            Self::High => 0.50,
            Self::Critical => 0.25,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }
}

/// Derive a `RiskRank` from an event reason string.
///
/// Uses substring matching: the first matching category wins.  Order matters —
/// more specific patterns should appear before broader ones.
pub fn classify_reason(reason: &str) -> RiskRank {
    // ── Critical ─────────────────────────────────────────────────────────────
    // These reasons already indicate that many authentication rounds were
    // exhausted inside a single connection — they are immediate-block signals
    // by themselves.
    if matches!(
        reason,
        "SSH max auth attempts exceeded"
            | "SSH disconnected: too many auth failures"
            | "SSH repeated connection close"
    ) {
        return RiskRank::Critical;
    }

    // ── High ─────────────────────────────────────────────────────────────────
    // Direct credential attacks or known high-risk web probes.
    const HIGH_KEYWORDS: &[&str] = &[
        "Failed SSH password",
        "Invalid SSH user",
        "SQL",        // SQL injection
        "shell",      // webshell probe / shell upload
        "eval-stdin", // PHPUnit eval-stdin exploit
        "log4j",      // Log4Shell (JNDI)
        "JNDI",
        "jndi",
        "code inject",
        "wp-login", // WordPress brute force
        "xmlrpc",   // XML-RPC amplification attack
        "scanner",  // known scanner bots
        "path traversal",
        "XSS",
        "metadata", // cloud metadata SSRF (AWS, GCP, Azure)
    ];
    for kw in HIGH_KEYWORDS {
        if reason.contains(kw) {
            return RiskRank::High;
        }
    }

    // ── Medium ────────────────────────────────────────────────────────────────
    // Probe-like patterns or indirect auth failures.
    const MEDIUM_KEYWORDS: &[&str] = &[
        "port scan",
        "PAM",
        "FTP",
        "SMTP",
        "IMAP",
        "POP3",
        "Dovecot",
        "Exim",
        "Postfix",
        "MySQL",
        "PostgreSQL",
        "SMB",
        "RDP",
    ];
    for kw in MEDIUM_KEYWORDS {
        if reason.contains(kw) {
            return RiskRank::Medium;
        }
    }

    RiskRank::Low
}

// ── Surge Detection ───────────────────────────────────────────────────────────

/// Configuration for event-type surge detection and rank-based threshold scaling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRiskConfig {
    /// Whether this subsystem is active.
    #[serde(default)]
    pub enabled: bool,
    /// Window (seconds) used to measure the *current* rate of each event type.
    #[serde(default = "default_surge_window_secs")]
    pub surge_window_secs: u64,
    /// Ratio of current count to baseline above which a surge is declared.
    /// E.g. `3.0` means "3× the baseline rate".
    #[serde(default = "default_surge_ratio")]
    pub surge_ratio: f64,
    /// EMA smoothing factor for baseline update: `0.0–1.0`.
    /// Lower values make the baseline slower to adapt (more stable).
    #[serde(default = "default_baseline_alpha")]
    pub baseline_alpha: f64,
    /// Additional threshold multiplier applied *on top of* the rank multiplier
    /// when a surge is active.  E.g. `0.5` halves the already-reduced threshold.
    #[serde(default = "default_surge_reduction")]
    pub surge_reduction: f64,
}

fn default_surge_window_secs() -> u64 {
    300
}
fn default_surge_ratio() -> f64 {
    3.0
}
fn default_baseline_alpha() -> f64 {
    0.1
}
fn default_surge_reduction() -> f64 {
    0.5
}

impl Default for EventRiskConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            surge_window_secs: default_surge_window_secs(),
            surge_ratio: default_surge_ratio(),
            baseline_alpha: default_baseline_alpha(),
            surge_reduction: default_surge_reduction(),
        }
    }
}

struct CategoryState {
    /// Recent event timestamps within the surge window.
    timestamps: VecDeque<Instant>,
    /// Exponential moving-average of events-per-window (the "calm" baseline).
    baseline: f64,
    /// When we last updated the baseline.
    last_baseline_update: Instant,
}

fn bootstrap_surge_threshold(cfg: &EventRiskConfig) -> f64 {
    // In a fresh process there is no historical baseline yet. Use a derived
    // minimum event count so an obvious same-category wave can still escalate
    // during the first active window instead of staying stuck at rank-only.
    (cfg.surge_ratio.ceil() + 1.0).max(4.0)
}

impl CategoryState {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::new(),
            baseline: 0.0,
            last_baseline_update: Instant::now(),
        }
    }
}

/// Tracks the per-category event frequency and detects surges.
pub struct EventSurgeDetector {
    state: HashMap<String, CategoryState>,
}

impl Default for EventSurgeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSurgeDetector {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
    }

    /// Record one event for `category` and return `true` if the category is
    /// currently in surge mode.  Always returns `false` when disabled.
    pub fn record(&mut self, category: &str, cfg: &EventRiskConfig) -> bool {
        if !cfg.enabled {
            return false;
        }

        let now = Instant::now();
        let window = Duration::from_secs(cfg.surge_window_secs.max(10));
        let entry = self
            .state
            .entry(category.to_string())
            .or_insert_with(CategoryState::new);

        // Evict timestamps outside the window.
        while let Some(&oldest) = entry.timestamps.front() {
            if now.duration_since(oldest) > window {
                entry.timestamps.pop_front();
            } else {
                break;
            }
        }
        entry.timestamps.push_back(now);

        let current_count = entry.timestamps.len() as f64;

        // Update the EMA baseline once per window period.
        if now.duration_since(entry.last_baseline_update) >= window {
            if entry.baseline < 1.0 {
                // Bootstrap: seed with the current count.
                entry.baseline = current_count;
            } else {
                entry.baseline = entry.baseline * (1.0 - cfg.baseline_alpha)
                    + current_count * cfg.baseline_alpha;
            }
            entry.last_baseline_update = now;
        }

        // Surge: current count significantly exceeds the baseline.
        //
        // Bootstrap path: on a fresh start there is no baseline yet, but an
        // obvious same-category flood should still escalate inside the first
        // window instead of waiting an entire window just to learn "normal".
        if entry.baseline > 1.0 {
            current_count > entry.baseline * cfg.surge_ratio
        } else {
            current_count >= bootstrap_surge_threshold(cfg)
        }
    }
}

// ── Combined Adjustment ───────────────────────────────────────────────────────

/// Apply risk-rank and surge adjustments to a raw threshold.
///
/// Returns `(effective_threshold, rank, surge_active)`.
///
/// When `cfg.enabled == false` the rank is still computed (useful for logging)
/// but no threshold adjustment is made.
pub fn adjust_threshold(
    base: u32,
    reason: &str,
    surge_detector: &mut EventSurgeDetector,
    cfg: &EventRiskConfig,
) -> (u32, RiskRank, bool) {
    let rank = classify_reason(reason);

    if !cfg.enabled {
        return (base, rank, false);
    }

    let category = categorize_reason(reason);
    let surge = surge_detector.record(category, cfg);

    let mut multiplier = rank.threshold_multiplier();
    if surge {
        multiplier *= cfg.surge_reduction;
    }

    let effective = ((base as f64) * multiplier).round() as u32;

    (effective.max(1), rank, surge)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "../tests/unit/event_risk_tests.rs"]
mod tests;
