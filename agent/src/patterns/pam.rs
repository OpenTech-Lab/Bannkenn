use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// Generic PAM authentication failure patterns.
/// Covers any PAM-authenticated service that logs `rhost=<ip>`.
/// MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing), T1078 (Valid Accounts)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // pam_unix auth failure with rhost (covers SSH, su, login, etc.)
        DetectionPattern {
            regex: Regex::new(
                r"pam_unix\([^)]+\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "PAM authentication failure",
        },
        // pam_sss (SSSD/LDAP) failure with rhost
        DetectionPattern {
            regex: Regex::new(
                r"pam_sss\([^)]+\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "PAM SSSD authentication failure",
        },
        // pam_krb5 (Kerberos) failure with rhost
        DetectionPattern {
            regex: Regex::new(
                r"pam_krb5\([^)]+\): authentication failure.*from (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "PAM Kerberos authentication failure",
        },
        // Generic PAM auth failure line with rhost= (any module)
        DetectionPattern {
            regex: Regex::new(r"authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)")?,
            reason: "PAM authentication failure (generic)",
        },
        // pam_faillock / pam_tally2: account temporarily locked after failures
        DetectionPattern {
            regex: Regex::new(r"pam_(?:faillock|tally2)\([^)]+\):.*rhost=(\d+\.\d+\.\d+\.\d+)")?,
            reason: "PAM account lockout triggered",
        },
    ])
}

#[cfg(test)]
#[path = "../../tests/unit/patterns/pam_tests.rs"]
mod tests;
