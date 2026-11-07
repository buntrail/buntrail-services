fn main() {
    let services = buntrail_services::Services::new();
    let error = services.call(&serde_json::json!({"command":"unknown"}));
    assert!(error.is_err());
}
