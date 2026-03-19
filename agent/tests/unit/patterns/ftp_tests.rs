use regex::Regex;

#[test]
fn test_vsftpd_pam_failure() {
    let re =
        Regex::new(r"pam_unix\(vsftpd:auth\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)")
            .unwrap();

    let line = "Jan 15 11:00:01 server vsftpd[1234]: pam_unix(vsftpd:auth): authentication failure; logname= uid=0 euid=0 tty=ftp ruser=anonymous rhost=198.51.100.20";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "198.51.100.20"
    );
}

#[test]
fn test_proftpd_login_failed() {
    let re =
        Regex::new(r"proftpd\[\d+\]:.*\[(\d+\.\d+\.\d+\.\d+)\].*[Ll]ogin (?:failed|incorrect)")
            .unwrap();

    let line = "Jan 15 11:01:22 server proftpd[5678]: server.example.com (client.example.com[203.0.113.42]) - Login failed: guest";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "203.0.113.42"
    );
}

#[test]
fn test_pureftpd_auth_failed() {
    let re =
        Regex::new(r"pure-ftpd:.*\(\?@(\d+\.\d+\.\d+\.\d+)\).*\[\d+\].*[Aa]uthentication failed")
            .unwrap();

    let line = "Jan 15 11:02:55 server pure-ftpd: (?@192.168.1.77) [3] Authentication failed for user [hacker]";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "192.168.1.77"
    );
}
