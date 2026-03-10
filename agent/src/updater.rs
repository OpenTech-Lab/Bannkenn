use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use std::env;
use std::path::{Path, PathBuf};
use tokio::process::Command;

const GITHUB_RELEASES_BASE: &str = "https://github.com/OpenTech-Lab/bannkenn/releases";

pub async fn update(version: Option<&str>) -> Result<()> {
    let current_version = env!("CARGO_PKG_VERSION");
    let asset_name = release_asset_name()?;
    let download_url = release_download_url(version, asset_name)?;
    let target_path = env::current_exe().context("Could not determine current executable path")?;

    tracing::info!(
        "Updating bannkenn-agent {} using {}",
        current_version,
        download_url
    );

    let client = Client::new();
    let response = client
        .get(&download_url)
        .send()
        .await
        .with_context(|| format!("Failed to download {}", download_url))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "Release download failed with status {}: {}",
            status,
            body
        ));
    }

    let resolved_url = response.url().to_string();
    let bytes = response.bytes().await?.to_vec();
    let resolved_release = resolved_release_label(&resolved_url);

    install_binary(&target_path, &bytes).await?;
    let restarted = restart_service_if_active().await?;

    println!(
        "Updated bannkenn-agent {} -> {} at {}",
        current_version,
        resolved_release,
        target_path.display()
    );
    if restarted {
        println!("Restarted systemd service: bannkenn-agent");
    } else {
        println!("Systemd service not active; skipped restart");
    }

    Ok(())
}

fn release_asset_name() -> Result<&'static str> {
    match (env::consts::OS, env::consts::ARCH) {
        ("linux", "x86_64") => Ok("bannkenn-agent-linux-x64"),
        ("linux", "aarch64") => Ok("bannkenn-agent-linux-arm64"),
        ("windows", "x86_64") => Ok("bannkenn-agent-windows-x64.exe"),
        (os, arch) => Err(anyhow!("Unsupported platform for self-update: {os}/{arch}")),
    }
}

fn release_download_url(version: Option<&str>, asset_name: &str) -> Result<String> {
    if let Some(version) = version {
        let version = normalize_version(version)?;
        Ok(format!(
            "{}/download/{}/{}",
            GITHUB_RELEASES_BASE, version, asset_name
        ))
    } else {
        Ok(format!(
            "{}/latest/download/{}",
            GITHUB_RELEASES_BASE, asset_name
        ))
    }
}

fn normalize_version(version: &str) -> Result<String> {
    let version = version.trim();
    let version = version.strip_prefix('v').unwrap_or(version);
    if version.is_empty() {
        return Err(anyhow!("Version cannot be empty"));
    }

    let is_valid = regex::Regex::new(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?$")
        .expect("version regex should compile")
        .is_match(version);
    if !is_valid {
        return Err(anyhow!("Version must look like 1.3.18 or 1.3.18-beta.1"));
    }

    Ok(format!("v{}", version))
}

fn resolved_release_label(resolved_url: &str) -> String {
    resolved_url
        .split("/download/")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("latest")
        .to_string()
}

async fn install_binary(target_path: &Path, bytes: &[u8]) -> Result<()> {
    let temp_path = temp_install_path(target_path);
    tokio::fs::write(&temp_path, bytes)
        .await
        .with_context(|| format!("Failed to write {}", temp_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp_path, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("Failed to chmod {}", temp_path.display()))?;
    }

    tokio::fs::rename(&temp_path, target_path)
        .await
        .with_context(|| format!("Failed to replace {}", target_path.display()))?;

    Ok(())
}

fn temp_install_path(target_path: &Path) -> PathBuf {
    let name = target_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("bannkenn-agent");
    target_path.with_file_name(format!(".{}.update-{}", name, std::process::id()))
}

async fn restart_service_if_active() -> Result<bool> {
    let active = match Command::new("systemctl")
        .args(["is-active", "--quiet", "bannkenn-agent"])
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(_) => return Ok(false),
    };

    if !active {
        return Ok(false);
    }

    let status = Command::new("systemctl")
        .args(["restart", "bannkenn-agent"])
        .status()
        .await
        .context("Failed to restart systemd service bannkenn-agent")?;
    if !status.success() {
        return Err(anyhow!("systemctl restart bannkenn-agent failed"));
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_version_is_normalized() {
        assert_eq!(
            release_download_url(Some("1.3.18"), "bannkenn-agent-linux-x64").unwrap(),
            "https://github.com/OpenTech-Lab/bannkenn/releases/download/v1.3.18/bannkenn-agent-linux-x64"
        );
        assert_eq!(
            release_download_url(Some("v1.3.18"), "bannkenn-agent-linux-x64").unwrap(),
            "https://github.com/OpenTech-Lab/bannkenn/releases/download/v1.3.18/bannkenn-agent-linux-x64"
        );
    }

    #[test]
    fn no_version_uses_latest_release_redirect() {
        assert_eq!(
            release_download_url(None, "bannkenn-agent-linux-x64").unwrap(),
            "https://github.com/OpenTech-Lab/bannkenn/releases/latest/download/bannkenn-agent-linux-x64"
        );
    }

    #[test]
    fn invalid_version_is_rejected() {
        assert!(normalize_version("latest").is_err());
        assert!(normalize_version("1.3").is_err());
    }

    #[test]
    fn resolved_release_is_parsed_from_redirect_url() {
        assert_eq!(
            resolved_release_label(
                "https://github.com/OpenTech-Lab/bannkenn/releases/download/v1.3.18/bannkenn-agent-linux-x64"
            ),
            "v1.3.18"
        );
    }
}
