use super::*;

#[test]
fn test_client_creation() {
    let client = ApiClient::new(
        "http://localhost:8080".to_string(),
        "test_token".to_string(),
        None,
    )
    .unwrap();

    assert_eq!(client.base_url, "http://localhost:8080");
    assert_eq!(client.token, "test_token");
}

#[test]
fn test_http_client_creation_without_custom_ca() {
    let client = build_http_client(None).unwrap();
    let clone = client.clone();
    drop(clone);
}

#[test]
fn test_json_body_construction() {
    let body = json!({
        "ip": "192.168.1.1",
        "reason": "Failed login attempts",
        "action": "block"
    });

    assert_eq!(body["ip"], "192.168.1.1");
    assert_eq!(body["action"], "block");
}
