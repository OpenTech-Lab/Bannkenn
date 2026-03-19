use super::*;

fn cfg(enabled: bool) -> BurstConfig {
    BurstConfig {
        enabled,
        window_secs: 10,
        threshold: 3,
    }
}

#[test]
fn test_burst_fires_at_threshold_not_before() {
    let mut detector = BurstDetector::new();
    let c = cfg(true);

    assert_eq!(detector.record("1.2.3.4", "SSH", &c), None);
    assert_eq!(detector.record("1.2.3.4", "SSH", &c), None);
    // Third hit hits the threshold.
    let result = detector.record("1.2.3.4", "SSH", &c);
    assert!(result.is_some(), "should detect burst on third hit");
    assert_eq!(result.unwrap(), 3);
}

#[test]
fn test_burst_disabled_returns_none() {
    let mut detector = BurstDetector::new();
    let c = cfg(false);

    for _ in 0..10 {
        assert_eq!(
            detector.record("1.2.3.4", "SSH", &c),
            None,
            "disabled burst must always return None"
        );
    }
}

#[test]
fn test_clear_ip_resets_counter() {
    let mut detector = BurstDetector::new();
    let c = cfg(true);

    // Push two hits so one more would trigger.
    detector.record("1.2.3.4", "SSH", &c);
    detector.record("1.2.3.4", "SSH", &c);

    // Clear resets.
    detector.clear_ip("1.2.3.4");

    // After clearing, two more hits should still be below threshold.
    assert_eq!(detector.record("1.2.3.4", "SSH", &c), None);
    assert_eq!(detector.record("1.2.3.4", "SSH", &c), None);
}

#[test]
fn test_different_ips_are_independent() {
    let mut detector = BurstDetector::new();
    let c = cfg(true);

    detector.record("1.1.1.1", "SSH", &c);
    detector.record("1.1.1.1", "SSH", &c);

    // Different IP should not contribute to 1.1.1.1 counter.
    assert_eq!(detector.record("2.2.2.2", "SSH", &c), None);
}

#[test]
fn test_categorize_reason_strips_annotation() {
    assert_eq!(
        categorize_reason("SSH invalid user (2/5)"),
        "SSH invalid user"
    );
    assert_eq!(
        categorize_reason("SSH invalid user (3/5)"),
        "SSH invalid user"
    );
    assert_eq!(
        categorize_reason("SSH failed password"),
        "SSH failed password"
    );
    assert_eq!(
        categorize_reason("SSH failed password (threshold: 5)"),
        "SSH failed password"
    );
}
