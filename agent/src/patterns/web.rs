use super::DetectionPattern;
use anyhow::Result;
use regex::Regex;

/// Web server authentication brute-force detection patterns.
/// Covers Apache httpd (mod_auth_basic, mod_auth_digest) and nginx (ngx_http_auth_basic).
/// MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1110.001 (Brute Force),
///               T1595.002 (Active Scanning: Vulnerability Scanning)
pub fn patterns() -> Result<Vec<DetectionPattern>> {
    Ok(vec![
        // Apache: AH01617 — user not found in HTTP Basic auth
        // Apache logs client as [client IP:port], so port suffix is optional
        DetectionPattern {
            regex: Regex::new(
                r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01617:.*user .* not found",
            )?,
            reason: "Web Apache Basic auth user not found (AH01617)",
        },
        // Apache: AH01618 — password mismatch in HTTP Basic auth
        DetectionPattern {
            regex: Regex::new(
                r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01618:.*password mismatch",
            )?,
            reason: "Web Apache Basic auth password mismatch (AH01618)",
        },
        // Apache: AH01776 — user denied by require directives
        DetectionPattern {
            regex: Regex::new(
                r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01776:.*user .* not authorized",
            )?,
            reason: "Web Apache user not authorized (AH01776)",
        },
        // Apache: AH01627 — digest auth: nonce mismatch / stale
        DetectionPattern {
            regex: Regex::new(r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01627:")?,
            reason: "Web Apache Digest auth failure (AH01627)",
        },
        // Apache generic: user not found / user denied (older log format without AH codes)
        DetectionPattern {
            regex: Regex::new(
                r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*user .* (?:not found|denied)",
            )?,
            reason: "Web Apache HTTP auth denied",
        },
        // nginx: no user/password provided (basic auth probe)
        DetectionPattern {
            regex: Regex::new(
                r"no user/pass was provided for basic authentication.*client: (\d+\.\d+\.\d+\.\d+)",
            )?,
            reason: "Web nginx Basic auth: no credentials",
        },
        // nginx: user was not found in basic auth
        DetectionPattern {
            regex: Regex::new(r#"user ".*" was not found.*client: (\d+\.\d+\.\d+\.\d+)"#)?,
            reason: "Web nginx Basic auth user not found",
        },
        // nginx: password mismatch
        DetectionPattern {
            regex: Regex::new(r#"user ".*" password mismatch.*client: (\d+\.\d+\.\d+\.\d+)"#)?,
            reason: "Web nginx Basic auth password mismatch",
        },
        // mod_security / WAF: blocked request with client IP
        DetectionPattern {
            regex: Regex::new(
                r#"ModSecurity.*\[client (\d+\.\d+\.\d+\.\d+)\].*\[severity "CRITICAL"\]"#,
            )?,
            reason: "Web ModSecurity critical rule match",
        },
        // ── nginx / Apache combined access log patterns ───────────────────────
        // These match the standard Combined Log Format:
        //   IP - USER [timestamp] "METHOD /path HTTP/x.x" STATUS BYTES "REF" "UA"
        // The attacker IP is always capture group 1 (start of line).
        //
        // PHPUnit eval-stdin.php — WordPress plugin RCE probe
        // Attack: POST /wp-content/plugins/*/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
        // MITRE ATT&CK: T1190 (Exploit Public-Facing Application)
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*eval-stdin\.php"#,
            )?,
            reason: "Web WordPress phpunit eval-stdin.php RCE probe",
        },
        // WordPress wp-content plugin/theme exploit path scan (broader catch for
        // phpunit, vendor, and other framework files embedded in plugins/themes)
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ /wp-content/[^"]*(?:phpunit|vendor/[^"]*\.php|eval)[^"]*""#,
            )?,
            reason: "Web WordPress plugin/theme exploit path scan",
        },
        // Webshell probe — classic PHP webshell filenames
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*(?:c99|r57|b374k|webshell|shell|cmd|wso)\.php"#,
            )?,
            reason: "Web PHP webshell probe",
        },
        // Sensitive file disclosure probe (.env, wp-config.php, .git, /etc/passwd …)
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "GET [^"]*(?:\.env|wp-config\.php|/\.git/|/\.svn/|/etc/passwd|/etc/shadow|/proc/self)"#,
            )?,
            reason: "Web sensitive file disclosure probe",
        },
        // PHP code-injection via query string (?cmd=, ?exec=, ?system=, …)
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*\?(?:cmd|exec|system|passthru|eval|shell_exec)="#,
            )?,
            reason: "Web PHP code injection via query string",
        },
        // Log4j JNDI RCE (CVE-2021-44228) — matches in path or query
        DetectionPattern {
            regex: Regex::new(r#"^(\d+\.\d+\.\d+\.\d+) .*?(?:\$\{jndi:|%24%7Bjndi:)"#)?,
            reason: "Web Log4j JNDI RCE attempt (CVE-2021-44228)",
        },
        // Path Traversal / LFI (Local File Inclusion)
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "(?i)[a-z]+ [^"]*(?:\.\./\.\./|\.\.\\\.\.\\|%2e%2e%2f|%252e%252e%252f)"#,
            )?,
            reason: "Web Path Traversal / LFI probe",
        },
        // SQL Injection (Basic booleans and UNION SELECT probes)
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "(?i)[a-z]+ [^"]*(?:UNION(?:%20|\+)(?:ALL(?:%20|\+))?SELECT|%27\s*(?:OR|AND)\s*(?:%27|\d)|'\s*(?:OR|AND)\s*('\d|\d))"#,
            )?,
            reason: "Web SQL Injection attempt",
        },
        // Cross-Site Scripting (XSS) probe
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "(?i)[a-z]+ [^"]*(?:<script>|%3Cscript%3E|javascript:|alert\()"#,
            )?,
            reason: "Web Cross-Site Scripting (XSS) probe",
        },
        // Cloud Metadata SSRF probe (AWS/GCP/Azure)
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*169\.254\.169\.254"#,
            )?,
            reason: "Web Cloud Metadata SSRF probe",
        },
        // Malicious Vulnerability Scanners via User-Agent (Nuclei, ZGrab, Masscan, etc)
        DetectionPattern {
            regex: Regex::new(
                r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*" \d+ \d+ "[^"]*" "(?i)[^"]*(?:nuclei|zgrab|masscan|zmeu|nikto)"#,
            )?,
            reason: "Web Malicious Security Scanner bot",
        },
    ])
}

#[cfg(test)]
#[path = "../../tests/unit/patterns/web_tests.rs"]
mod tests;
