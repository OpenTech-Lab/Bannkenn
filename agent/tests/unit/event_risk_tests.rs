use super::*;

#[test]
fn ssh_max_auth_is_critical() {
    assert_eq!(
        classify_reason("SSH max auth attempts exceeded"),
        RiskRank::Critical
    );
    assert_eq!(
        classify_reason("SSH disconnected: too many auth failures"),
        RiskRank::Critical
    );
    assert_eq!(
        classify_reason("SSH repeated connection close"),
        RiskRank::Critical
    );
}

#[test]
fn failed_password_is_high() {
    assert_eq!(classify_reason("Failed SSH password"), RiskRank::High);
    assert_eq!(classify_reason("Invalid SSH user"), RiskRank::High);
    assert_eq!(classify_reason("SQL injection probe"), RiskRank::High);
}

#[test]
fn port_scan_is_medium() {
    assert_eq!(
        classify_reason("SSH port scan (no identification string)"),
        RiskRank::Medium
    );
    assert_eq!(
        classify_reason("PAM authentication failure"),
        RiskRank::Medium
    );
}

#[test]
fn unknown_is_low() {
    assert_eq!(classify_reason("Unknown random event"), RiskRank::Low);
}

#[test]
fn rank_threshold_multipliers_are_ordered() {
    assert!(RiskRank::Critical.threshold_multiplier() < RiskRank::High.threshold_multiplier());
    assert!(RiskRank::High.threshold_multiplier() < RiskRank::Medium.threshold_multiplier());
    assert!(RiskRank::Medium.threshold_multiplier() < RiskRank::Low.threshold_multiplier());
}

#[test]
fn adjust_disabled_returns_base() {
    let cfg = EventRiskConfig {
        enabled: false,
        ..Default::default()
    };
    let mut det = EventSurgeDetector::new();
    // Even a Critical event should not adjust threshold when disabled.
    let (eff, rank, surge) = adjust_threshold(5, "SSH max auth attempts exceeded", &mut det, &cfg);
    assert_eq!(eff, 5);
    assert_eq!(rank, RiskRank::Critical);
    assert!(!surge);
}

#[test]
fn critical_rank_reduces_threshold_to_quarter() {
    let cfg = EventRiskConfig {
        enabled: true,
        ..Default::default()
    };
    let mut det = EventSurgeDetector::new();
    let (eff, rank, _surge) = adjust_threshold(8, "SSH max auth attempts exceeded", &mut det, &cfg);
    assert_eq!(rank, RiskRank::Critical);
    // 8 * 0.25 = 2
    assert_eq!(eff, 2);
}

#[test]
fn high_rank_reduces_threshold_to_half() {
    let cfg = EventRiskConfig {
        enabled: true,
        ..Default::default()
    };
    let mut det = EventSurgeDetector::new();
    let (eff, rank, _) = adjust_threshold(10, "Failed SSH password", &mut det, &cfg);
    assert_eq!(rank, RiskRank::High);
    assert_eq!(eff, 5);
}

#[test]
fn effective_is_always_at_least_one() {
    let cfg = EventRiskConfig {
        enabled: true,
        ..Default::default()
    };
    let mut det = EventSurgeDetector::new();
    let (eff, _, _) = adjust_threshold(1, "SSH max auth attempts exceeded", &mut det, &cfg);
    assert!(eff >= 1);
}

#[test]
fn surge_bootstraps_within_first_window() {
    let cfg = EventRiskConfig {
        enabled: true,
        surge_window_secs: 300,
        surge_ratio: 3.0,
        ..Default::default()
    };
    let mut det = EventSurgeDetector::new();

    assert!(!det.record("Invalid SSH user", &cfg));
    assert!(!det.record("Invalid SSH user", &cfg));
    assert!(!det.record("Invalid SSH user", &cfg));
    assert!(
        det.record("Invalid SSH user", &cfg),
        "fourth same-category hit in a fresh window should bootstrap surge"
    );
}

#[test]
fn adjust_threshold_marks_bootstrap_surge() {
    let cfg = EventRiskConfig {
        enabled: true,
        surge_window_secs: 300,
        surge_ratio: 3.0,
        surge_reduction: 0.5,
        ..Default::default()
    };
    let mut det = EventSurgeDetector::new();

    let _ = adjust_threshold(8, "Invalid SSH user", &mut det, &cfg);
    let _ = adjust_threshold(8, "Invalid SSH user", &mut det, &cfg);
    let _ = adjust_threshold(8, "Invalid SSH user", &mut det, &cfg);
    let (eff, rank, surge) = adjust_threshold(8, "Invalid SSH user", &mut det, &cfg);

    assert_eq!(rank, RiskRank::High);
    assert!(surge, "bootstrap wave should enter surge mode");
    assert_eq!(eff, 2, "High rank (0.5) plus surge (0.5) should quarter 8");
}
