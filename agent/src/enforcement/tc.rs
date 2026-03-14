use crate::config::ContainmentConfig;
use crate::enforcement::{EnforcementAction, EnforcementFuture, EnforcementOutcome, Enforcer};
use anyhow::{anyhow, Context, Result};
use reqwest::Url;
use std::collections::BTreeSet;
use std::net::IpAddr;
use tokio::fs;
use tokio::net::lookup_host;
use tokio::process::Command;

const ROUTE_TABLE_PATH: &str = "/proc/net/route";
const TC_ALLOW_RATE: &str = "10000mbit";

#[derive(Debug, Clone)]
pub struct TrafficControlEnforcer {
    interface: Option<String>,
    throttle_kbit: u32,
    management_ports: Vec<u16>,
    heartbeat_endpoint: Option<ManagementEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagementEndpoint {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedHeartbeatEndpoint {
    port: u16,
    ipv4s: Vec<String>,
    port_only_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcCommandPlan {
    interface: String,
    commands: Vec<Vec<String>>,
    detail: String,
}

impl TrafficControlEnforcer {
    pub fn new(config: &ContainmentConfig, server_url: &str) -> Self {
        let management_ports = config
            .management_allow_ports
            .iter()
            .copied()
            .filter(|port| *port > 0)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        Self {
            interface: config
                .throttle_network_interface
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            throttle_kbit: config.throttle_network_kbit,
            management_ports,
            heartbeat_endpoint: parse_management_endpoint(server_url),
        }
    }

    async fn build_plan(&self) -> Result<TcCommandPlan> {
        if self.throttle_kbit == 0 {
            return Err(anyhow!("throttle_network_kbit must be > 0"));
        }

        let interface = match self.interface.clone() {
            Some(interface) => interface,
            None => detect_default_interface().await?,
        };
        let heartbeat = resolve_heartbeat_endpoint(self.heartbeat_endpoint.as_ref()).await;
        let commands = build_tc_commands(
            &interface,
            self.throttle_kbit,
            &self.management_ports,
            heartbeat.as_ref(),
        );
        let heartbeat_detail = heartbeat
            .map(|endpoint| {
                if endpoint.ipv4s.is_empty() {
                    format!("heartbeat port {} (port-only fallback)", endpoint.port)
                } else {
                    format!("heartbeat {}:{} ", endpoint.ipv4s.join(","), endpoint.port)
                }
            })
            .unwrap_or_else(|| "heartbeat endpoint unavailable".to_string());

        Ok(TcCommandPlan {
            interface,
            detail: format!(
                "tc throttle={}kbit management_ports={:?} {}",
                self.throttle_kbit, self.management_ports, heartbeat_detail
            ),
            commands,
        })
    }
}

impl Default for TrafficControlEnforcer {
    fn default() -> Self {
        Self::new(&ContainmentConfig::default(), "")
    }
}

impl Enforcer for TrafficControlEnforcer {
    fn name(&self) -> &'static str {
        "tc"
    }

    fn supports(&self, action: &EnforcementAction) -> bool {
        matches!(action, EnforcementAction::ApplyNetworkThrottle { .. })
    }

    fn execute<'a>(
        &'a self,
        action: &'a EnforcementAction,
        dry_run: bool,
    ) -> EnforcementFuture<'a> {
        Box::pin(async move {
            if !matches!(action, EnforcementAction::ApplyNetworkThrottle { .. }) {
                return Ok(EnforcementOutcome {
                    action: action.clone(),
                    enforcer: self.name().to_string(),
                    applied: false,
                    dry_run,
                    detail: "unsupported tc action".to_string(),
                });
            }

            let plan = match self.build_plan().await {
                Ok(plan) => plan,
                Err(error) => {
                    return Ok(EnforcementOutcome {
                        action: action.clone(),
                        enforcer: self.name().to_string(),
                        applied: false,
                        dry_run,
                        detail: format!("failed to build tc throttle plan: {}", error),
                    });
                }
            };

            if dry_run {
                return Ok(EnforcementOutcome {
                    action: action.clone(),
                    enforcer: self.name().to_string(),
                    applied: false,
                    dry_run: true,
                    detail: format!(
                        "dry-run network throttle on {} ({}, {} command(s))",
                        plan.interface,
                        plan.detail,
                        plan.commands.len()
                    ),
                });
            }

            match apply_tc_commands(&plan.commands).await {
                Ok(()) => Ok(EnforcementOutcome {
                    action: action.clone(),
                    enforcer: self.name().to_string(),
                    applied: true,
                    dry_run: false,
                    detail: format!(
                        "applied network throttle on {} ({})",
                        plan.interface, plan.detail
                    ),
                }),
                Err(error) => Ok(EnforcementOutcome {
                    action: action.clone(),
                    enforcer: self.name().to_string(),
                    applied: false,
                    dry_run: false,
                    detail: format!("network throttle failed: {}", error),
                }),
            }
        })
    }
}

fn parse_management_endpoint(server_url: &str) -> Option<ManagementEndpoint> {
    let url = Url::parse(server_url).ok()?;
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default()?;
    Some(ManagementEndpoint { host, port })
}

async fn detect_default_interface() -> Result<String> {
    let route_table = fs::read_to_string(ROUTE_TABLE_PATH)
        .await
        .with_context(|| format!("failed to read {}", ROUTE_TABLE_PATH))?;
    default_interface_from_route_table(&route_table).ok_or_else(|| {
        anyhow!(
            "could not determine default network interface from {}",
            ROUTE_TABLE_PATH
        )
    })
}

fn default_interface_from_route_table(route_table: &str) -> Option<String> {
    route_table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let interface = fields.next()?;
        let destination = fields.next()?;
        if destination == "00000000" {
            Some(interface.to_string())
        } else {
            None
        }
    })
}

async fn resolve_heartbeat_endpoint(
    endpoint: Option<&ManagementEndpoint>,
) -> Option<ResolvedHeartbeatEndpoint> {
    let endpoint = endpoint?;
    let mut ipv4s = BTreeSet::new();
    let mut port_only_fallback = false;

    match endpoint.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ipv4)) => {
            ipv4s.insert(ipv4.to_string());
        }
        Ok(IpAddr::V6(_)) => {
            port_only_fallback = true;
        }
        Err(_) => match lookup_host((endpoint.host.as_str(), endpoint.port)).await {
            Ok(addresses) => {
                for address in addresses {
                    if let IpAddr::V4(ipv4) = address.ip() {
                        ipv4s.insert(ipv4.to_string());
                    }
                }
                if ipv4s.is_empty() {
                    port_only_fallback = true;
                }
            }
            Err(_) => {
                port_only_fallback = true;
            }
        },
    }

    Some(ResolvedHeartbeatEndpoint {
        port: endpoint.port,
        ipv4s: ipv4s.into_iter().collect(),
        port_only_fallback,
    })
}

fn build_tc_commands(
    interface: &str,
    throttle_kbit: u32,
    management_ports: &[u16],
    heartbeat: Option<&ResolvedHeartbeatEndpoint>,
) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let throttled_rate = format!("{}kbit", throttle_kbit);

    commands.push(vec![
        "tc".to_string(),
        "qdisc".to_string(),
        "replace".to_string(),
        "dev".to_string(),
        interface.to_string(),
        "root".to_string(),
        "handle".to_string(),
        "1:".to_string(),
        "htb".to_string(),
        "default".to_string(),
        "20".to_string(),
    ]);
    commands.push(vec![
        "tc".to_string(),
        "class".to_string(),
        "replace".to_string(),
        "dev".to_string(),
        interface.to_string(),
        "parent".to_string(),
        "1:".to_string(),
        "classid".to_string(),
        "1:1".to_string(),
        "htb".to_string(),
        "rate".to_string(),
        TC_ALLOW_RATE.to_string(),
        "ceil".to_string(),
        TC_ALLOW_RATE.to_string(),
    ]);
    commands.push(vec![
        "tc".to_string(),
        "class".to_string(),
        "replace".to_string(),
        "dev".to_string(),
        interface.to_string(),
        "parent".to_string(),
        "1:".to_string(),
        "classid".to_string(),
        "1:20".to_string(),
        "htb".to_string(),
        "rate".to_string(),
        throttled_rate.clone(),
        "ceil".to_string(),
        throttled_rate,
    ]);

    let mut prio = 10u32;
    let management_port_set = management_ports.iter().copied().collect::<BTreeSet<_>>();
    for port in management_ports {
        commands.push(tcp_port_filter(interface, prio, "sport", *port));
        prio += 1;
        commands.push(tcp_port_filter(interface, prio, "dport", *port));
        prio += 1;
    }

    if let Some(heartbeat) = heartbeat {
        for ipv4 in &heartbeat.ipv4s {
            commands.push(heartbeat_endpoint_filter(
                interface,
                prio,
                ipv4,
                heartbeat.port,
            ));
            prio += 1;
        }

        if heartbeat.port_only_fallback && !management_port_set.contains(&heartbeat.port) {
            commands.push(tcp_port_filter(interface, prio, "dport", heartbeat.port));
        }
    }

    commands
}

fn tcp_port_filter(interface: &str, prio: u32, direction: &str, port: u16) -> Vec<String> {
    vec![
        "tc".to_string(),
        "filter".to_string(),
        "replace".to_string(),
        "dev".to_string(),
        interface.to_string(),
        "protocol".to_string(),
        "ip".to_string(),
        "parent".to_string(),
        "1:".to_string(),
        "prio".to_string(),
        prio.to_string(),
        "u32".to_string(),
        "match".to_string(),
        "ip".to_string(),
        "protocol".to_string(),
        "6".to_string(),
        "0xff".to_string(),
        "match".to_string(),
        "ip".to_string(),
        direction.to_string(),
        port.to_string(),
        "0xffff".to_string(),
        "flowid".to_string(),
        "1:1".to_string(),
    ]
}

fn heartbeat_endpoint_filter(interface: &str, prio: u32, ipv4: &str, port: u16) -> Vec<String> {
    vec![
        "tc".to_string(),
        "filter".to_string(),
        "replace".to_string(),
        "dev".to_string(),
        interface.to_string(),
        "protocol".to_string(),
        "ip".to_string(),
        "parent".to_string(),
        "1:".to_string(),
        "prio".to_string(),
        prio.to_string(),
        "u32".to_string(),
        "match".to_string(),
        "ip".to_string(),
        "protocol".to_string(),
        "6".to_string(),
        "0xff".to_string(),
        "match".to_string(),
        "ip".to_string(),
        "dst".to_string(),
        format!("{}/32", ipv4),
        "match".to_string(),
        "ip".to_string(),
        "dport".to_string(),
        port.to_string(),
        "0xffff".to_string(),
        "flowid".to_string(),
        "1:1".to_string(),
    ]
}

async fn apply_tc_commands(commands: &[Vec<String>]) -> Result<()> {
    for command in commands {
        let status = Command::new(&command[0])
            .args(&command[1..])
            .status()
            .await
            .with_context(|| format!("failed to execute {}", command.join(" ")))?;

        if !status.success() {
            return Err(anyhow!("{} exited with {}", command.join(" "), status));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
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
                    "tc", "filter", "replace", "dev", "eth0", "protocol", "ip", "parent", "1:",
                    "prio", "10", "u32", "match", "ip", "protocol", "6", "0xff", "match", "ip",
                    "sport", "22", "0xffff", "flowid", "1:1",
                ]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        }));
        assert!(commands.iter().any(|command| {
            command.contains(&"203.0.113.10/32".to_string())
                && command.contains(&"8443".to_string())
        }));
    }
}
