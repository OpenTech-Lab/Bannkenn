use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// SMB / Samba brute-force and lateral movement detection patterns.
/// MITRE ATT&CK: T1021.002 (Remote Services: SMB/Windows Admin Shares),
///               T1110.001 (Brute Force: Password Guessing)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // Samba smbd: authentication failure for IP address (smb_audit or verbose logging)
        DetectionPattern {
            regex: Regex::new(r"smbd.*[Aa]uth(?:entication)? failed.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB Samba authentication failed",
        },
        // Samba: NT_STATUS_LOGON_FAILURE with remote IP
        DetectionPattern {
            regex: Regex::new(r"smbd.*NT_STATUS_LOGON_FAILURE.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB NT_STATUS_LOGON_FAILURE",
        },
        // Samba: NT_STATUS_WRONG_PASSWORD with remote IP
        DetectionPattern {
            regex: Regex::new(r"smbd.*NT_STATUS_WRONG_PASSWORD.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB NT_STATUS_WRONG_PASSWORD",
        },
        // Samba: NT_STATUS_ACCOUNT_LOCKED_OUT — lockout policy triggered
        DetectionPattern {
            regex: Regex::new(r"smbd.*NT_STATUS_ACCOUNT_LOCKED_OUT.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB account locked out",
        },
        // Samba PAM authentication failure via pam_unix with rhost
        DetectionPattern {
            regex: Regex::new(
                r"pam_unix\(samba:auth\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "SMB Samba PAM authentication failure",
        },
        // Winbind: check_password failed with remote IP
        DetectionPattern {
            regex: Regex::new(r"winbindd.*check_password.*failed.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "SMB Winbind password check failed",
        },
    ])
}

#[cfg(test)]
#[path = "../../tests/unit/patterns/smb_tests.rs"]
mod tests;
