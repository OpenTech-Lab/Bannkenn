use regex::Regex;

#[test]
fn test_mysql_access_denied() {
    let re = Regex::new(r"Access denied for user '.*'@'(\d+\.\d+\.\d+\.\d+)'").unwrap();

    let line = "2025-01-15T16:00:01.000000Z 10 [Note] Access denied for user 'root'@'203.0.113.11' (using password: YES)";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "203.0.113.11"
    );
}

#[test]
fn test_mysql_host_blocked() {
    let re =
        Regex::new(r"Host '(\d+\.\d+\.\d+\.\d+)' is blocked because of many connection errors")
            .unwrap();

    let line = "2025-01-15T16:01:22.000000Z 0 [Warning] Host '198.51.100.77' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "198.51.100.77"
    );
}

#[test]
fn test_mysql_host_not_allowed() {
    let re = Regex::new(r"Host '(\d+\.\d+\.\d+\.\d+)' is not allowed to connect").unwrap();

    let line = "Host '10.99.0.5' is not allowed to connect to this MySQL server";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "10.99.0.5"
    );
}

#[test]
fn test_postgres_no_pghba() {
    let re = Regex::new(r#"no pg_hba\.conf entry for host "(\d+\.\d+\.\d+\.\d+)""#).unwrap();

    let line = "2025-01-15 16:02:00 UTC [5678] FATAL:  no pg_hba.conf entry for host \"192.0.2.200\", user \"postgres\", database \"prod\", SSL off";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "192.0.2.200"
    );
}

#[test]
fn test_postgres_password_failed_with_host() {
    let re =
        Regex::new(r"FATAL:.*password authentication failed for user.*host=(\d+\.\d+\.\d+\.\d+)")
            .unwrap();

    let line = "2025-01-15 16:03:11 UTC [9999] FATAL:  password authentication failed for user \"admin\" host=172.31.0.50";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "172.31.0.50"
    );
}
