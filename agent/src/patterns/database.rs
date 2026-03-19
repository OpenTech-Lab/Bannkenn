use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// Database authentication brute-force detection patterns.
/// Covers MySQL/MariaDB and PostgreSQL.
/// MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing), T1078 (Valid Accounts)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // MySQL/MariaDB: access denied for user from host
        // Log format: Access denied for user 'user'@'1.2.3.4' (using password: YES)
        DetectionPattern {
            regex: Regex::new(r"Access denied for user '.*'@'(\d+\.\d+\.\d+\.\d+)'")?,
            reason: "Database MySQL access denied",
        },
        // MySQL/MariaDB: host blocked due to too many connection errors
        DetectionPattern {
            regex: Regex::new(
                r"Host '(\d+\.\d+\.\d+\.\d+)' is blocked because of many connection errors",
            )?,
            reason: "Database MySQL host blocked (too many errors)",
        },
        // MySQL/MariaDB: host not allowed to connect
        DetectionPattern {
            regex: Regex::new(r"Host '(\d+\.\d+\.\d+\.\d+)' is not allowed to connect")?,
            reason: "Database MySQL host not allowed",
        },
        // PostgreSQL: no pg_hba.conf entry for host (connection rejected at auth layer)
        DetectionPattern {
            regex: Regex::new(r#"no pg_hba\.conf entry for host "(\d+\.\d+\.\d+\.\d+)""#)?,
            reason: "Database PostgreSQL no pg_hba entry for host",
        },
        // PostgreSQL: pg_hba rejects the connection (host= in log prefix)
        DetectionPattern {
            regex: Regex::new(
                r"FATAL:.*pg_hba\.conf rejects connection.*host=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "Database PostgreSQL pg_hba connection rejected",
        },
        // PostgreSQL: password authentication failed (with host in log_line_prefix)
        // Standard postgresql.conf log_line_prefix includes %h for remote host
        DetectionPattern {
            regex: Regex::new(
                r"FATAL:.*password authentication failed for user.*host=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "Database PostgreSQL password authentication failed",
        },
        // MongoDB: authentication failed with remote IP in message
        DetectionPattern {
            regex: Regex::new(
                r"SASL SCRAM.*authentication failed.*client:.*\b(\d+\.\d+\.\d+\.\d+)\b",
            )?,
            reason: "Database MongoDB SCRAM authentication failed",
        },
        // Redis: protected by requirepass — wrong password from remote IP
        DetectionPattern {
            regex: Regex::new(r"NOAUTH.*from (\d+\.\d+\.\d+\.\d+)")?,
            reason: "Database Redis NOAUTH error",
        },
    ])
}

#[cfg(test)]
#[path = "../../tests/unit/patterns/database_tests.rs"]
mod tests;
