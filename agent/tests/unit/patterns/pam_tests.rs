use regex::Regex;

#[test]
fn test_pam_unix_rhost() {
    let re = Regex::new(r"pam_unix\([^)]+\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)")
        .unwrap();

    let line = "Jan 15 10:01:02 server sshd[1234]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=root";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "203.0.113.5"
    );
}

#[test]
fn test_pam_sss_rhost() {
    let re = Regex::new(r"pam_sss\([^)]+\): authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)")
        .unwrap();

    let line = "Jan 15 10:01:03 server sshd[2345]: pam_sss(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.7  user=admin";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "198.51.100.7"
    );
}

#[test]
fn test_generic_pam_rhost() {
    let re = Regex::new(r"authentication failure;.*rhost=(\d+\.\d+\.\d+\.\d+)").unwrap();

    let line = "sshd[9999]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.99 user=ubuntu";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "10.0.0.99"
    );
}
