use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// A pattern that matches a successful SSH login.
/// capture group 1 = username, capture group 2 = attacker/source IP.
pub struct SshLoginPattern {
    pub regex: Regex,
}

/// Return all patterns that detect a *successful* SSH authentication.
/// These events are informational (not blocks) and carry the authenticated
/// username so the dashboard can display who logged in and from where.
pub fn login_patterns() -> Result<Vec<SshLoginPattern>> {
    Ok(vec![
        // password auth: "Accepted password for root from 1.2.3.4 port 22 ssh2"
        SshLoginPattern {
            regex: Regex::new(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")?,
        },
        // pubkey auth: "Accepted publickey for ubuntu from 1.2.3.4 port 22 ssh2: ..."
        SshLoginPattern {
            regex: Regex::new(r"Accepted publickey for (\S+) from (\d+\.\d+\.\d+\.\d+)")?,
        },
        // keyboard-interactive / PAM auth
        SshLoginPattern {
            regex: Regex::new(
                r"Accepted keyboard-interactive(?:/pam)? for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            )?,
        },
        // GSSAPI auth (Kerberos)
        SshLoginPattern {
            regex: Regex::new(
                r"Accepted gssapi(?:-with-mic|-keyex)? for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            )?,
        },
    ])
}

pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // Classic SSH brute-force
        DetectionPattern {
            regex: Regex::new(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")?,
            reason: "Failed SSH password",
        },
        // Unknown username probes
        DetectionPattern {
            regex: Regex::new(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)")?,
            reason: "Invalid SSH user",
        },
        // Connection dropped after too many failures (sshd preauth)
        DetectionPattern {
            regex: Regex::new(
                r"Connection closed by (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "SSH repeated connection close",
        },
        // Explicit disconnect due to too many auth failures
        DetectionPattern {
            regex: Regex::new(
                r"Disconnecting (?:invalid user|authenticating user) \S+ (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "SSH disconnected: too many auth failures",
        },
        // sshd hard limit on authentication rounds
        DetectionPattern {
            regex: Regex::new(
                r"maximum authentication attempts exceeded for .* from (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "SSH max auth attempts exceeded",
        },
        // Port scanners that never send an SSH banner
        DetectionPattern {
            regex: Regex::new(r"Did not receive identification string from (\d+\.\d+\.\d+\.\d+)")?,
            reason: "SSH port scan (no identification string)",
        },
        // Clients with incompatible algorithms — common in automated scans
        DetectionPattern {
            regex: Regex::new(r"Unable to negotiate with (\d+\.\d+\.\d+\.\d+)")?,
            reason: "SSH port scan (unable to negotiate)",
        },
    ])
}

#[cfg(test)]
#[path = "../../tests/unit/patterns/ssh_tests.rs"]
mod tests;
