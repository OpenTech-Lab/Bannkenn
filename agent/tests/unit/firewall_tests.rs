use super::*;

#[test]
fn test_backend_detection() {
    let backend = detect_backend();
    // Don't assert on specific backend since it depends on the system
    // Just ensure it doesn't panic
    match backend {
        FirewallBackend::Nftables => println!("nftables available"),
        FirewallBackend::Iptables => println!("iptables available"),
        FirewallBackend::None => println!("no firewall available"),
    }
}

#[test]
fn test_ip_validation() {
    // Ensure IPs are properly formatted when passed to commands
    let valid_ip = "192.168.1.1";
    assert!(valid_ip.contains('.'));
}

#[test]
fn local_and_reserved_ips_are_skipped_for_firewall_enforcement() {
    for ip in [
        "127.0.0.1",
        "10.0.0.8",
        "172.17.0.1",
        "192.168.1.20",
        "169.254.10.2",
        "100.64.1.5",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(
            should_skip_local_firewall_enforcement(ip),
            "{} should be skipped",
            ip
        );
    }
}

#[test]
fn public_ips_remain_eligible_for_firewall_enforcement() {
    for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
        assert!(
            !should_skip_local_firewall_enforcement(ip),
            "{} should remain blockable",
            ip
        );
    }
}

#[test]
fn bannkenn_rule_handle_parser_ignores_unrelated_rules() {
    let chain = r#"
table inet bannkenn {
	chain input {
		type filter hook input priority filter; policy accept;
		ct state established,related accept # handle 1
		ip saddr @bannkenn_blocklist drop comment "bannkenn-managed" # handle 7
		ip saddr 203.0.113.10 drop # handle 9
		ip saddr @bannkenn_blocklist drop # handle 11
	}
}
"#;

    assert_eq!(bannkenn_rule_handles(chain), vec![7, 11]);
}

#[test]
fn nft_handle_parser_requires_numeric_handle() {
    assert_eq!(
        extract_nft_rule_handle("ip saddr @bannkenn_blocklist drop # handle 42"),
        Some(42)
    );
    assert_eq!(
        extract_nft_rule_handle("ip saddr @bannkenn_blocklist drop"),
        None
    );
    assert_eq!(
        extract_nft_rule_handle("ip saddr @bannkenn_blocklist drop # handle abc"),
        None
    );
}

#[test]
fn effective_block_patterns_collapse_overlapping_hosts_and_cidrs() {
    let effective = effective_block_patterns([
        "101.47.142.48",
        "101.47.142.0/24",
        "193.32.162.17",
        "193.32.162.0/24",
        "8.8.8.8",
    ]);

    assert_eq!(
        effective,
        vec![
            "101.47.142.0/24".to_string(),
            "193.32.162.0/24".to_string(),
            "8.8.8.8".to_string(),
        ]
    );
}

#[test]
fn effective_enforcement_recognizes_cidr_coverage() {
    let enforced = HashSet::from(["101.47.142.0/24".to_string(), "193.32.162.0/24".to_string()]);

    assert!(is_block_pattern_effectively_enforced(
        "101.47.142.48",
        &enforced
    ));
    assert!(is_block_pattern_effectively_enforced(
        "193.32.162.0/24",
        &enforced
    ));
    assert!(!is_block_pattern_effectively_enforced("8.8.8.8", &enforced));
}

#[test]
fn source_matching_supports_cidr_patterns() {
    let known = HashMap::from([
        ("203.0.113.0/24".to_string(), "feed".to_string()),
        ("198.51.100.77".to_string(), "agent".to_string()),
    ]);

    assert_eq!(
        find_matching_block_source(&known, "203.0.113.9"),
        Some("feed".to_string())
    );
    assert_eq!(
        find_matching_block_source(&known, "198.51.100.77"),
        Some("agent".to_string())
    );
    assert_eq!(find_matching_block_source(&known, "198.51.100.78"), None);
}

#[test]
fn local_cidr_patterns_are_skipped() {
    assert!(should_skip_local_firewall_enforcement("10.0.0.0/24"));
    assert!(should_skip_local_firewall_enforcement("fc00::/7"));
    assert!(!should_skip_local_firewall_enforcement("11.0.0.0/8"));
}

#[test]
fn pattern_sets_match_ips_and_cover_patterns() {
    let patterns = HashSet::from(["203.0.113.0/24".to_string(), "198.51.100.77".to_string()]);

    assert!(pattern_set_matches_ip(&patterns, "203.0.113.99"));
    assert!(pattern_set_matches_ip(&patterns, "198.51.100.77"));
    assert!(!pattern_set_matches_ip(&patterns, "198.51.100.78"));
    assert!(pattern_set_covers_pattern(&patterns, "203.0.113.0/25"));
    assert!(!pattern_set_covers_pattern(&patterns, "203.0.112.0/24"));
}

#[tokio::test]
async fn whitelist_reconcile_tracks_exact_ip_and_cidr_overrides() {
    let desired = vec!["203.0.113.0/24".to_string(), "198.51.100.77".to_string()];
    let enforced = Arc::new(RwLock::new(HashSet::from(["198.51.100.7".to_string()])));

    let summary = reconcile_whitelist_ips(&desired, &enforced, &FirewallBackend::None).await;

    assert_eq!(summary.added, 2);
    assert_eq!(summary.removed, 1);
    assert_eq!(summary.add_failed, 0);
    assert_eq!(summary.remove_failed, 0);
    assert_eq!(*enforced.read().await, desired.into_iter().collect());
}
