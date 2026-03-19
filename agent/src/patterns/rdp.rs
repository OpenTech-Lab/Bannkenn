use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// RDP (Remote Desktop Protocol) brute-force detection patterns.
/// Covers xrdp on Linux.
/// MITRE ATT&CK: T1021.001 (Remote Services: Remote Desktop Protocol), T1110.001 (Brute Force)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // xrdp-sesman: PAM authentication failed — includes source IP
        DetectionPattern {
            regex: Regex::new(
                r"xrdp-sesman\[\d+\]:.*(?:[Aa]uth(?:entication)? failed|[Ll]ogin [Ff]ailed).*\b(\d+\.\d+\.\d+\.\d+)\b",
            )?,
            reason: "RDP xrdp authentication failed",
        },
        // xrdp-sesman: PAM error line with IP
        DetectionPattern {
            regex: Regex::new(r"xrdp-sesman\[\d+\]:.*pam_\w+.*fail.*\b(\d+\.\d+\.\d+\.\d+)\b")?,
            reason: "RDP xrdp PAM failure",
        },
        // xrdp: connection established then closed — logs client IP in "ip" field
        DetectionPattern {
            regex: Regex::new(
                r"xrdp\[\d+\]:.*connection (?:error|lost|closed|dropped).*ip (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "RDP xrdp connection dropped",
        },
        // xrdp: incoming connection log — useful for rate-limiting aggressive scanners
        DetectionPattern {
            regex: Regex::new(r"xrdp\[\d+\]:.*\[(?:WARN|ERROR)\].*from ip (\d+\.\d+\.\d+\.\d+)")?,
            reason: "RDP xrdp warning from IP",
        },
        // FreeRDP / xrdp NLA: NTLM logon failure
        DetectionPattern {
            regex: Regex::new(r"xrdp(?:-sesman)?\[\d+\]:.*ntlm.*fail.*(\d+\.\d+\.\d+\.\d+)")?,
            reason: "RDP xrdp NTLM authentication failed",
        },
    ])
}

#[cfg(test)]
#[path = "../../tests/unit/patterns/rdp_tests.rs"]
mod tests;
