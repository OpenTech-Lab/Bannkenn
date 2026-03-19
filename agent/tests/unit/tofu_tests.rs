use super::*;

#[test]
fn sanitize_host_port_replaces_non_alnum() {
    assert_eq!(
        sanitize_host_port("123.123.123.123", 1234),
        "123_123_123_123_1234"
    );
    assert_eq!(sanitize_host_port("2001:db8::1", 443), "2001_db8__1_443");
}

#[test]
fn pem_encoder_wraps_certificate_body() {
    let pem = pem_encode_certificate(&[1, 2, 3, 4]);
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
}

#[test]
fn fingerprint_is_uppercase_colon_hex() {
    let fingerprint = sha256_fingerprint(b"bannkenn");
    assert!(fingerprint.contains(':'));
    assert_eq!(fingerprint, fingerprint.to_ascii_uppercase());
}
