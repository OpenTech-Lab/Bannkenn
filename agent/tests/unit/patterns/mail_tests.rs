use regex::Regex;

#[test]
fn test_postfix_sasl_failed() {
    let re = Regex::new(
        r"postfix/smtpd\[\d+\].*\bunknown\[(\d+\.\d+\.\d+\.\d+)\].*SASL \w+ authentication failed",
    )
    .unwrap();

    let line = "Jan 15 12:00:01 mx postfix/smtpd[9901]: warning: unknown[203.0.113.80]: SASL LOGIN authentication failed: authentication failure";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "203.0.113.80"
    );
}

#[test]
fn test_postfix_lost_connection_after_auth() {
    let re = Regex::new(
        r"postfix/smtpd\[\d+\].*lost connection after AUTH from [^\[]*\[(\d+\.\d+\.\d+\.\d+)\]",
    )
    .unwrap();

    let line = "Jan 15 12:01:07 mx postfix/smtpd[9902]: lost connection after AUTH from unknown[198.51.100.55]";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "198.51.100.55"
    );
}

#[test]
fn test_dovecot_aborted_login() {
    let re = Regex::new(
        r"(?:imap|pop3|managesieve)-login:.*(?:Aborted login|auth failed).*rip=(\d+\.\d+\.\d+\.\d+)",
    )
    .unwrap();

    let line = "Jan 15 12:02:33 mx dovecot: imap-login: Aborted login (no auth attempts in 0 secs): user=<>, rip=10.20.30.40, lip=10.0.0.1, TLS";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "10.20.30.40"
    );
}

#[test]
fn test_dovecot_pop3_auth_failed() {
    let re = Regex::new(
        r"(?:imap|pop3|managesieve)-login:.*(?:Aborted login|auth failed).*rip=(\d+\.\d+\.\d+\.\d+)",
    )
    .unwrap();

    let line = "Jan 15 12:03:44 mx dovecot: pop3-login: Aborted login (auth failed, 3 attempts in 4 secs): user=<bob>, method=PLAIN, rip=172.16.0.50, lip=10.0.0.1";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "172.16.0.50"
    );
}

#[test]
fn test_exim_auth_failed() {
    let re = Regex::new(r"exim.*authenticator failed for.*\[(\d+\.\d+\.\d+\.\d+)\]").unwrap();

    let line = "Jan 15 12:04:01 mx exim[4000]: 2024-01-15 12:04:01 plain authenticator failed for (attacker) [192.0.2.9]:54321: 535 Incorrect authentication data";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "192.0.2.9"
    );
}
