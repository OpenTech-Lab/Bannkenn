use super::*;

#[test]
fn render_systemd_unit_uses_binary_path_for_start_and_stop() {
    let unit = render_systemd_unit(Path::new(DEFAULT_SYSTEM_BINARY_PATH));

    assert!(unit.contains("After=network-online.target"));
    assert!(unit.contains("Environment=HOME=/root"));
    assert!(unit.contains("Environment=XDG_CONFIG_HOME=/root/.config"));
    assert!(unit.contains("ExecStart=/usr/local/bin/bannkenn-agent run"));
    assert!(unit.contains("ExecStopPost=-/usr/local/bin/bannkenn-agent cleanup-firewall"));
    assert!(unit.contains("WantedBy=multi-user.target"));
}

#[test]
fn render_systemd_unit_falls_back_to_supplied_binary_when_default_is_missing() {
    let non_installed = Path::new("/tmp/bannkenn-agent");
    let unit = render_systemd_unit(non_installed);

    if Path::new(DEFAULT_SYSTEM_BINARY_PATH).exists() {
        assert!(unit.contains("ExecStart=/usr/local/bin/bannkenn-agent run"));
    } else {
        assert!(unit.contains("ExecStart=/tmp/bannkenn-agent run"));
    }
}
