use super::*;

#[test]
fn global_shared_risk_reduces_threshold() {
    let snapshot = SharedRiskSnapshot {
        global_threshold_multiplier: 0.5,
        ..Default::default()
    };

    let decision = snapshot.apply(8, "Invalid SSH user");
    assert_eq!(decision.effective_threshold, Some(4));
    assert_eq!(decision.tags, vec!["shared:global"]);
}

#[test]
fn category_campaign_is_more_aggressive_than_global() {
    let snapshot = SharedRiskSnapshot {
        global_threshold_multiplier: 0.5,
        categories: vec![SharedRiskCategory {
            category: "Invalid SSH user".to_string(),
            distinct_ips: 3,
            distinct_agents: 2,
            event_count: 3,
            threshold_multiplier: 0.25,
            force_threshold: Some(1),
            label: "shared:campaign".to_string(),
        }],
        ..Default::default()
    };

    let decision = snapshot.apply(8, "Invalid SSH user");
    assert_eq!(decision.effective_threshold, Some(1));
    assert_eq!(
        decision.tags,
        vec!["shared:campaign".to_string(), "shared:global".to_string()]
    );
}

#[test]
fn unrelated_category_does_not_apply() {
    let snapshot = SharedRiskSnapshot {
        categories: vec![SharedRiskCategory {
            category: "Web SQL Injection attempt".to_string(),
            distinct_ips: 3,
            distinct_agents: 2,
            event_count: 3,
            threshold_multiplier: 0.25,
            force_threshold: Some(1),
            label: "shared:campaign".to_string(),
        }],
        ..Default::default()
    };

    let decision = snapshot.apply(8, "Invalid SSH user");
    assert_eq!(decision, SharedRiskDecision::default());
}
