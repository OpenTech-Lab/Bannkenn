use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// FTP brute-force detection patterns.
/// Covers vsftpd, ProFTPD, and Pure-FTPd.
/// MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing), T1021 (Remote Services)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // vsftpd: PAM auth failure — rhost= carries the attacker IP
        DetectionPattern {
            regex: Regex::new(
                r"pam_unix\(vsftpd:auth\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "FTP vsftpd authentication failure",
        },
        // ProFTPD: login failed line includes the remote IP in square brackets
        // Log format: proftpd[pid]: server (hostname[IP]) - Login failed: user
        DetectionPattern {
            regex: Regex::new(
                r"proftpd\[\d+\]:.*\[(\d+\.\d+\.\d+\.\d+)\].*[Ll]ogin (?:failed|incorrect)",
            )?,
            reason: "FTP ProFTPD login failed",
        },
        // ProFTPD: USER login attempt with no valid shell
        DetectionPattern {
            regex: Regex::new(r"proftpd\[\d+\]:.*\[(\d+\.\d+\.\d+\.\d+)\].*no valid shell")?,
            reason: "FTP ProFTPD no valid shell",
        },
        // Pure-FTPd: authentication failed — IP in (?@IP) field, count in [N]
        // Log format: pure-ftpd: (?@IP) [N] Authentication failed for user [name]
        DetectionPattern {
            regex: Regex::new(
                r"pure-ftpd:.*\(\?@(\d+\.\d+\.\d+\.\d+)\).*\[\d+\].*[Aa]uthentication failed",
            )?,
            reason: "FTP Pure-FTPd authentication failed",
        },
        // Pure-FTPd: too many connections from same IP
        DetectionPattern {
            regex: Regex::new(r"pure-ftpd:.*\(\?@(\d+\.\d+\.\d+\.\d+)\).*[Tt]oo many connections")?,
            reason: "FTP Pure-FTPd connection flood",
        },
    ])
}

#[cfg(test)]
#[path = "../../tests/unit/patterns/ftp_tests.rs"]
mod tests;
