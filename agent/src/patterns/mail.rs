use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// Mail server brute-force detection patterns.
/// Covers Postfix SASL and Dovecot IMAP/POP3.
/// MITRE ATT&CK: T1078 (Valid Accounts), T1110.001 (Brute Force: Password Guessing)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // Postfix smtpd: SASL login authentication failed — IP is in the "unknown[IP]" prefix
        DetectionPattern {
            regex: Regex::new(
                r"postfix/smtpd\[\d+\].*\bunknown\[(\d+\.\d+\.\d+\.\d+)\].*SASL \w+ authentication failed",
            )?,
            reason: "Mail Postfix SASL authentication failed",
        },
        // Postfix smtpd: lost connection after AUTH (common in brute-force scans)
        DetectionPattern {
            regex: Regex::new(
                r"postfix/smtpd\[\d+\].*lost connection after AUTH from [^\[]*\[(\d+\.\d+\.\d+\.\d+)\]",
            )?,
            reason: "Mail Postfix lost connection after AUTH",
        },
        // Dovecot imap-login / pop3-login: Aborted login with remote IP (rip=)
        DetectionPattern {
            regex: Regex::new(
                r"(?:imap|pop3|managesieve)-login:.*(?:Aborted login|auth failed).*rip=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "Mail Dovecot login aborted/failed",
        },
        // Dovecot: Disconnected with auth failed and rip=
        DetectionPattern {
            regex: Regex::new(r"dovecot.*Disconnected.*auth failed.*rip=(\d+\.\d+\.\d+\.\d+)")?,
            reason: "Mail Dovecot disconnected: auth failed",
        },
        // Dovecot: too many bad commands from IP
        DetectionPattern {
            regex: Regex::new(
                r"dovecot.*Disconnected.*Too many invalid commands.*rip=(\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "Mail Dovecot too many invalid commands",
        },
        // Exim: login authentication failed with remote IP
        DetectionPattern {
            regex: Regex::new(r"exim.*authenticator failed for.*\[(\d+\.\d+\.\d+\.\d+)\]")?,
            reason: "Mail Exim authentication failed",
        },
        // Courier IMAP/POP3: LOGIN FAILED from remote IP
        DetectionPattern {
            regex: Regex::new(r"courierpop3login:.*LOGIN FAILED.*\[(\d+\.\d+\.\d+\.\d+)\]")?,
            reason: "Mail Courier POP3 login failed",
        },
        DetectionPattern {
            regex: Regex::new(r"imapd:.*LOGIN FAILED.*\[(\d+\.\d+\.\d+\.\d+)\]")?,
            reason: "Mail Courier IMAP login failed",
        },
    ])
}

#[cfg(test)]
#[path = "../../tests/unit/patterns/mail_tests.rs"]
mod tests;
