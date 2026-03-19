use super::*;

fn cfg(threshold: u32) -> CampaignConfig {
    CampaignConfig {
        enabled: true,
        window_secs: 3600,
        distinct_ips_threshold: threshold,
        geo_grouping: false,
        geo_ips_threshold: 2,
    }
}

fn geo_cfg(vol_threshold: u32, geo_threshold: u32) -> CampaignConfig {
    CampaignConfig {
        enabled: true,
        window_secs: 3600,
        distinct_ips_threshold: vol_threshold,
        geo_grouping: true,
        geo_ips_threshold: geo_threshold,
    }
}

#[test]
fn disabled_never_returns_campaign() {
    let mut tracker = LocalCampaignTracker::new();
    let c = CampaignConfig {
        enabled: false,
        ..Default::default()
    };
    for i in 0..100 {
        let ip = format!("1.2.3.{}", i);
        assert!(tracker.record(&ip, "Invalid SSH user", None, &c).is_none());
    }
}

#[test]
fn volume_campaign_fires_at_threshold() {
    let mut tracker = LocalCampaignTracker::new();
    let c = cfg(3);
    // First two IPs should not trigger.
    assert!(tracker
        .record("1.1.1.1", "Invalid SSH user", None, &c)
        .is_none());
    assert!(tracker
        .record("2.2.2.2", "Invalid SSH user", None, &c)
        .is_none());
    // Third distinct IP crosses the threshold.
    let result = tracker.record("3.3.3.3", "Invalid SSH user", None, &c);
    assert_eq!(result, Some(CampaignLevel::ByVolume));
}

#[test]
fn repeated_same_ip_does_not_trigger_volume_campaign() {
    let mut tracker = LocalCampaignTracker::new();
    let c = cfg(3);
    // Same IP repeated many times — only one distinct IP.
    for _ in 0..10 {
        let r = tracker.record("1.1.1.1", "Failed SSH password", None, &c);
        assert!(r.is_none(), "repeated same IP must not trigger campaign");
    }
}

#[test]
fn different_categories_are_independent() {
    let mut tracker = LocalCampaignTracker::new();
    let c = cfg(3);
    tracker.record("1.1.1.1", "Invalid SSH user", None, &c);
    tracker.record("2.2.2.2", "Invalid SSH user", None, &c);
    // Different category — should not affect "Invalid SSH user" count.
    tracker.record("3.3.3.3", "Failed SSH password", None, &c);
    // Fourth distinct IP for "Invalid SSH user".
    let r = tracker.record("4.4.4.4", "Invalid SSH user", None, &c);
    assert_eq!(r, Some(CampaignLevel::ByVolume));
}

#[test]
fn reason_annotations_are_normalized() {
    let mut tracker = LocalCampaignTracker::new();
    let c = cfg(3);
    // Annotated reasons like "(1/3)" and "(2/3)" map to the same category.
    tracker.record("1.1.1.1", "Invalid SSH user (1/3)", None, &c);
    tracker.record("2.2.2.2", "Invalid SSH user (2/3)", None, &c);
    let r = tracker.record("3.3.3.3", "Invalid SSH user (1/3)", None, &c);
    assert_eq!(r, Some(CampaignLevel::ByVolume));
}

#[test]
fn geo_campaign_fires_within_same_country_asn() {
    let mut tracker = LocalCampaignTracker::new();
    let c = geo_cfg(100, 2); // volume threshold too high; geo threshold = 2

    let china = GeoTag {
        country: "China".to_string(),
        asn_org: "ChinaTelecom".to_string(),
    };
    tracker.record("1.1.1.1", "Invalid SSH user", Some(&china), &c);
    let r = tracker.record("2.2.2.2", "Invalid SSH user", Some(&china), &c);
    assert_eq!(
        r,
        Some(CampaignLevel::ByGeo {
            country: "China".to_string(),
            asn_org: "ChinaTelecom".to_string()
        })
    );
}

#[test]
fn geo_campaign_does_not_fire_across_different_asn() {
    let mut tracker = LocalCampaignTracker::new();
    let c = geo_cfg(100, 2);

    let china_a = GeoTag {
        country: "China".to_string(),
        asn_org: "ChinaTelecom".to_string(),
    };
    let china_b = GeoTag {
        country: "China".to_string(),
        asn_org: "Alibaba".to_string(),
    };
    tracker.record("1.1.1.1", "Invalid SSH user", Some(&china_a), &c);
    let r = tracker.record("2.2.2.2", "Invalid SSH user", Some(&china_b), &c);
    assert!(r.is_none(), "Different ASN should not trigger geo campaign");
}
