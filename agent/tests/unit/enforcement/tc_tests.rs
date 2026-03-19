use super::*;

#[test]
fn parse_management_endpoint_uses_known_default_port() {
    let endpoint =
        parse_management_endpoint("https://dashboard.example.test/api").expect("endpoint");
    assert_eq!(
        endpoint,
        ManagementEndpoint {
            host: "dashboard.example.test".to_string(),
            port: 443,
        }
    );
}

#[test]
fn default_interface_from_route_table_detects_default_route() {
    let table = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t010011AC\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t000011AC\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";

    assert_eq!(
        default_interface_from_route_table(table),
        Some("eth0".to_string())
    );
}

#[test]
fn build_tc_commands_preserves_management_ports_and_heartbeat_endpoint() {
    let commands = build_tc_commands(
        "eth0",
        1024,
        &[22],
        Some(&ResolvedHeartbeatEndpoint {
            port: 8443,
            ipv4s: vec!["203.0.113.10".to_string()],
            port_only_fallback: false,
        }),
    );

    assert_eq!(commands[0][0], "tc");
    assert!(commands.iter().any(|command| {
        command
            == &vec![
                "tc", "filter", "replace", "dev", "eth0", "protocol", "ip", "parent", "1:", "prio",
                "10", "u32", "match", "ip", "protocol", "6", "0xff", "match", "ip", "sport", "22",
                "0xffff", "flowid", "1:1",
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    }));
    assert!(commands.iter().any(|command| {
        command.contains(&"203.0.113.10/32".to_string()) && command.contains(&"8443".to_string())
    }));
}
