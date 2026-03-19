use super::*;

fn cfg() -> RiskLevelConfig {
    RiskLevelConfig {
        enabled: true,
        window_secs: 3600,
        max_blocks: 20,
        min_threshold_multiplier: 0.4,
    }
}

#[test]
fn test_zero_risk_gives_full_threshold() {
    let mut risk = HostRiskLevel::new();
    let c = cfg();
    // No blocks recorded → score=0 → multiplier=1.0 → effective==threshold
    assert_eq!(risk.apply(5, &c), 5);
    assert_eq!(risk.apply(10, &c), 10);
}

#[test]
fn test_max_risk_gives_min_multiplier() {
    let mut risk = HostRiskLevel::new();
    let c = cfg();
    // Record max_blocks to hit score=1.0
    for _ in 0..c.max_blocks {
        risk.record_block();
    }
    // score=1.0 → multiplier=0.4 → effective = round(10 * 0.4) = 4
    let result = risk.apply(10, &c);
    assert_eq!(result, 4);
}

#[test]
fn test_apply_never_below_one() {
    let mut risk = HostRiskLevel::new();
    let c = cfg();
    for _ in 0..c.max_blocks {
        risk.record_block();
    }
    // threshold=1 with min_multiplier=0.4 → round(0.4)=0 → clamped to 1
    assert_eq!(risk.apply(1, &c), 1);
}

#[test]
fn test_disabled_returns_base_threshold() {
    let mut risk = HostRiskLevel::new();
    let mut c = cfg();
    c.enabled = false;
    for _ in 0..c.max_blocks {
        risk.record_block();
    }
    assert_eq!(risk.apply(5, &c), 5);
}

#[test]
fn test_half_risk_midpoint_multiplier() {
    let mut risk = HostRiskLevel::new();
    let c = cfg();
    // Record half of max_blocks → score=0.5 → multiplier=0.7 → effective=round(10*0.7)=7
    for _ in 0..(c.max_blocks / 2) {
        risk.record_block();
    }
    let result = risk.apply(10, &c);
    assert_eq!(result, 7);
}
