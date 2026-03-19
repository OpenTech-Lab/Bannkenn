use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

/// ButterflyShield configuration parameters.
///
/// When `enabled = true`, the agent replaces its static `threshold` with a
/// dynamically computed value derived from a logistic-map chaotic iteration.
/// The effective multiplier is in [0.5, 1.5] relative to the static base,
/// seeded from the attacker IP and the current unix second.
///
/// An attacker who reads the source code still cannot pre-compute "safe"
/// request rates, because the seed changes every second and depends on
/// server-side time — solving the inverse chaotic iteration is infeasible.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ButterflyShieldConfig {
    /// Whether dynamic threshold mode is active.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Logistic-map parameter r. Must be in (3.57, 4.0] for full chaos.
    #[serde(default = "default_chaos_r")]
    pub chaos_r: f64,
    /// Number of logistic-map iterations (higher = more unpredictable).
    #[serde(default = "default_iterations")]
    pub iterations: u32,
}

fn default_enabled() -> bool {
    true
}

fn default_chaos_r() -> f64 {
    3.99
}

fn default_iterations() -> u32 {
    10
}

impl Default for ButterflyShieldConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            chaos_r: default_chaos_r(),
            iterations: default_iterations(),
        }
    }
}

/// Compute the effective block threshold for `ip` using the logistic-map.
///
/// The seed is derived from the attacker IP and the current **window epoch**
/// (`unix_sec / window_secs`), not the raw unix second.  This keeps the
/// threshold **stable for the entire sliding window period**: all attempts
/// from the same IP within one window bucket see the same threshold, so the
/// comparison `attempts.len() >= effective` is consistent and blocking
/// eventually triggers as expected.
///
/// Previously the seed used `unix_sec` directly, causing the threshold to
/// change every second.  If the chaotic function happened to produce a high
/// multiplier in consecutive seconds the effective threshold could remain
/// permanently above the accumulated attempt count, silently preventing any
/// block from firing.
///
/// Returns at least 1 to avoid divide-by-zero or never-triggering logic.
pub fn effective_threshold(
    base: u32,
    ip: &str,
    window_secs: u64,
    cfg: &ButterflyShieldConfig,
) -> u32 {
    let seed = make_seed(ip, window_secs);
    effective_threshold_with_seed(base, seed, cfg)
}

/// Deterministic version of [`effective_threshold`] — accepts an explicit
/// seed in [0.0, 1.0) so unit tests can verify bounds and repeatability.
pub fn effective_threshold_with_seed(base: u32, seed: f64, cfg: &ButterflyShieldConfig) -> u32 {
    let mut x = seed.fract().abs();
    // Avoid the fixed-point x=0 (maps to threshold = base * 0.5).
    // Use a mid-range value as a safe fallback.
    if x == 0.0 {
        x = 0.5;
    }

    let r = cfg.chaos_r.clamp(0.0, 4.0);
    for _ in 0..cfg.iterations {
        x = r * x * (1.0 - x);
    }

    // Multiplier in [0.5, 1.5]
    let multiplier = 0.5 + x;
    let effective = (base as f64 * multiplier).round() as u32;
    // Always at least 1 so detection never becomes impossible.
    effective.max(1)
}

/// Build a normalised seed ∈ [0.0, 1.0) from `ip` and the current window epoch.
///
/// The time component is `unix_sec / window_secs.max(1)`, which advances once
/// per window period rather than once per second.  All attempts within the
/// same window bucket therefore produce the same seed → same threshold →
/// consistent `attempts >= threshold` comparison.
fn make_seed(ip: &str, window_secs: u64) -> f64 {
    let unix_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Quantise to the window period so the threshold is stable within one window.
    let window_epoch = unix_sec / window_secs.max(1);
    let key = format!("{}{}", ip, window_epoch);
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let h = hasher.finish();
    // Normalize to [0, 1)
    (h as f64) / (u64::MAX as f64 + 1.0)
}

#[cfg(test)]
#[path = "../tests/unit/butterfly_tests.rs"]
mod tests;
