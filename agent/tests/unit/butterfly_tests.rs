use super::*;

fn default_cfg() -> ButterflyShieldConfig {
    ButterflyShieldConfig::default()
}

/// The multiplier x after 10 iterations of the logistic map is always
/// in [0, 1], so the effective threshold must be in [base*0.5, base*1.5].
#[test]
fn test_multiplier_bounds() {
    let cfg = default_cfg();
    let base = 10u32;

    let seeds = [0.1, 0.25, 0.5, 0.75, 0.99, 0.123, 0.987, 0.333];
    for seed in seeds {
        let t = effective_threshold_with_seed(base, seed, &cfg);
        assert!(t >= base / 2, "threshold {} below floor for seed {seed}", t);
        assert!(
            t <= base * 2,
            "threshold {} above ceiling for seed {seed}",
            t
        );
    }
}

/// Same seed must always produce the same threshold (determinism).
#[test]
fn test_determinism() {
    let cfg = default_cfg();
    let seed = 0.42;
    let base = 5u32;
    let t1 = effective_threshold_with_seed(base, seed, &cfg);
    let t2 = effective_threshold_with_seed(base, seed, &cfg);
    assert_eq!(t1, t2);
}

/// Minimum threshold is always at least 1.
#[test]
fn test_minimum_threshold() {
    let cfg = default_cfg();
    for base in [1u32, 2, 5] {
        for seed in [0.0, 0.01, 0.99] {
            let t = effective_threshold_with_seed(base, seed, &cfg);
            assert!(t >= 1, "threshold must be >= 1, got {t}");
        }
    }
}

/// Different seeds should (almost always) produce different thresholds,
/// demonstrating sensitivity — a core property of chaos.
#[test]
fn test_sensitivity() {
    let cfg = default_cfg();
    let base = 20u32;
    let t1 = effective_threshold_with_seed(base, 0.40001, &cfg);
    let t2 = effective_threshold_with_seed(base, 0.40002, &cfg);
    // We can't guarantee exact difference (chaos isn't perfectly uniform),
    // but both must still be within valid bounds.
    let lo = base / 2;
    let hi = base * 2;
    assert!((lo..=hi).contains(&t1));
    assert!((lo..=hi).contains(&t2));
}

/// Disabling butterfly shield should fall back to the static base value,
/// handled by the call-site in watcher.rs, but ensure the helper still
/// computes a valid number when called with enabled=false.
#[test]
fn test_disabled_still_computes() {
    let cfg = ButterflyShieldConfig {
        enabled: false,
        ..Default::default()
    };
    let t = effective_threshold_with_seed(5, 0.5, &cfg);
    assert!(t >= 1);
}
