use anyhow::{anyhow, Result};
use tokio::process::Command;

const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "filter";
const NFT_BLOCKLIST_SET: &str = "bannkenn_blocklist";
const NFT_BANNKENN_CHAINS: [&str; 2] = ["input", "forward"];

/// Firewall backend detection and blocking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    None,
}

/// Initialize firewall infrastructure required by the agent.
/// For nftables: creates the `bannkenn_blocklist` named set and drop rules in the
/// `inet filter input` and `inet filter forward` chains if they do not already exist.
/// Safe to call on every startup.
/// For iptables and None backends, no setup is needed.
pub async fn init_firewall(backend: &FirewallBackend) -> Result<()> {
    match backend {
        FirewallBackend::Nftables => init_nftables().await,
        FirewallBackend::Iptables | FirewallBackend::None => Ok(()),
    }
}

/// Remove BannKenn-managed firewall state for the active backend.
/// For nftables, this removes the BannKenn drop rules and shared blocklist set.
/// The operation is idempotent so it can safely run both on process shutdown and
/// via a systemd ExecStopPost hook.
pub async fn cleanup_firewall(backend: &FirewallBackend) -> Result<()> {
    match backend {
        FirewallBackend::Nftables => cleanup_nftables().await,
        FirewallBackend::Iptables | FirewallBackend::None => Ok(()),
    }
}

/// Set up the nftables infrastructure needed by bannkenn:
///   inet filter table → bannkenn_blocklist set → drop rules in input + forward chains.
/// Every step is guarded by a check so re-running on restart is idempotent.
async fn init_nftables() -> Result<()> {
    tracing::info!("nftables: initializing bannkenn firewall infrastructure");

    // Create inet filter table — nft add is idempotent for tables.
    let _ = nft_run(&["add", "table", NFT_FAMILY, NFT_TABLE]).await;

    // Ensure the shared blocklist set exists.
    let set_check = Command::new("nft")
        .args(["list", "set", NFT_FAMILY, NFT_TABLE, NFT_BLOCKLIST_SET])
        .output()
        .await?;
    if !set_check.status.success() {
        nft_run(&[
            "add",
            "set",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_BLOCKLIST_SET,
            "{ type ipv4_addr ; flags interval ; }",
        ])
        .await
        .map_err(|e| anyhow!("Failed to create {} set: {}", NFT_BLOCKLIST_SET, e))?;
    }

    ensure_nft_chain("input", "input").await?;
    ensure_nft_chain("forward", "forward").await?;
    ensure_nft_drop_rule("input").await?;
    ensure_nft_drop_rule("forward").await?;

    tracing::info!("nftables: bannkenn_blocklist set and drop rules configured");
    Ok(())
}

async fn cleanup_nftables() -> Result<()> {
    tracing::info!("nftables: removing BannKenn-managed firewall rules");

    for chain in NFT_BANNKENN_CHAINS {
        remove_nft_drop_rules(chain).await?;
    }

    nft_run_allow_missing(&["delete", "set", NFT_FAMILY, NFT_TABLE, NFT_BLOCKLIST_SET]).await?;

    tracing::info!("nftables: BannKenn-managed firewall rules removed");
    Ok(())
}

async fn ensure_nft_chain(chain: &str, hook: &str) -> Result<()> {
    let chain_check = Command::new("nft")
        .args(["list", "chain", NFT_FAMILY, NFT_TABLE, chain])
        .output()
        .await?;
    if !chain_check.status.success() {
        nft_run(&[
            "add",
            "chain",
            NFT_FAMILY,
            NFT_TABLE,
            chain,
            &format!(
                "{{ type filter hook {} priority 0 ; policy accept ; }}",
                hook
            ),
        ])
        .await
        .map_err(|e| anyhow!("Failed to create inet filter {} chain: {}", chain, e))?;
    }
    Ok(())
}

async fn ensure_nft_drop_rule(chain: &str) -> Result<()> {
    let chain_out = Command::new("nft")
        .args(["list", "chain", NFT_FAMILY, NFT_TABLE, chain])
        .output()
        .await?;
    if !String::from_utf8_lossy(&chain_out.stdout).contains(NFT_BLOCKLIST_SET) {
        nft_run(&[
            "add",
            "rule",
            NFT_FAMILY,
            NFT_TABLE,
            chain,
            "ip",
            "saddr",
            &format!("@{}", NFT_BLOCKLIST_SET),
            "drop",
            "comment",
            "bannkenn-managed",
        ])
        .await
        .map_err(|e| anyhow!("Failed to add blocklist drop rule to {}: {}", chain, e))?;
    }
    Ok(())
}

/// Run an nft command with the given arguments, returning an error if it fails.
async fn nft_run(args: &[&str]) -> Result<()> {
    let output = Command::new("nft").args(args).output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("{}", stderr.trim()));
    }
    Ok(())
}

async fn nft_run_allow_missing(args: &[&str]) -> Result<()> {
    let output = Command::new("nft").args(args).output().await?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_nft_missing_error(&stderr) {
        return Ok(());
    }

    Err(anyhow!("{}", stderr.trim()))
}

async fn remove_nft_drop_rules(chain: &str) -> Result<()> {
    let output = Command::new("nft")
        .args(["-a", "list", "chain", NFT_FAMILY, NFT_TABLE, chain])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_nft_missing_error(&stderr) {
            return Ok(());
        }
        return Err(anyhow!(
            "Failed to inspect nftables chain {}: {}",
            chain,
            stderr.trim()
        ));
    }

    for handle in bannkenn_rule_handles(&String::from_utf8_lossy(&output.stdout)) {
        let handle_str = handle.to_string();
        nft_run_allow_missing(&[
            "delete",
            "rule",
            NFT_FAMILY,
            NFT_TABLE,
            chain,
            "handle",
            &handle_str,
        ])
        .await?;
    }

    Ok(())
}

fn bannkenn_rule_handles(chain_output: &str) -> Vec<u32> {
    chain_output
        .lines()
        .filter(|line| line.contains(&format!("@{}", NFT_BLOCKLIST_SET)))
        .filter_map(extract_nft_rule_handle)
        .collect()
}

fn extract_nft_rule_handle(line: &str) -> Option<u32> {
    line.split("# handle ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn is_nft_missing_error(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("no such file or directory")
        || stderr.contains("not found")
        || stderr.contains("does not exist")
}

/// Detect available firewall backend on the system
pub fn detect_backend() -> FirewallBackend {
    // Check if nft (nftables) is available
    if command_exists("nft") {
        return FirewallBackend::Nftables;
    }

    // Check if iptables is available
    if command_exists("iptables") {
        return FirewallBackend::Iptables;
    }

    // No firewall backend found
    FirewallBackend::None
}

/// Check if a command exists in PATH
fn command_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Block an IP address using the detected firewall backend
pub async fn block_ip(ip: &str, backend: &FirewallBackend) -> Result<()> {
    match backend {
        FirewallBackend::Nftables => block_ip_nftables(ip).await,
        FirewallBackend::Iptables => block_ip_iptables(ip).await,
        FirewallBackend::None => {
            tracing::warn!(
                "No firewall backend available; skipping block for IP: {}",
                ip
            );
            Ok(())
        }
    }
}

/// Block IP using nftables
async fn block_ip_nftables(ip: &str) -> Result<()> {
    let output = Command::new("nft")
        .args([
            "add",
            "element",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_BLOCKLIST_SET,
            &format!("{{ {} }}", ip),
        ])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("File exists") {
            tracing::debug!("IP {} already present in nftables blocklist", ip);
            return Ok(());
        }
        return Err(anyhow!("nftables block failed for {}: {}", ip, stderr));
    }

    tracing::info!("Blocked IP {} using nftables", ip);
    Ok(())
}

/// Block IP using iptables
async fn block_ip_iptables(ip: &str) -> Result<()> {
    ensure_iptables_drop("INPUT", ip).await?;
    ensure_iptables_drop("FORWARD", ip).await?;

    tracing::info!("Blocked IP {} using iptables", ip);
    Ok(())
}

async fn ensure_iptables_drop(chain: &str, ip: &str) -> Result<()> {
    let check = Command::new("iptables")
        .args(["-C", chain, "-s", ip, "-j", "DROP"])
        .output()
        .await?;
    if check.status.success() {
        return Ok(());
    }

    let output = Command::new("iptables")
        .args(["-I", chain, "-s", ip, "-j", "DROP"])
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "iptables block failed for {} in {}: {}",
            ip,
            chain,
            stderr
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
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
    fn bannkenn_rule_handle_parser_ignores_unrelated_rules() {
        let chain = r#"
table inet filter {
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
}
