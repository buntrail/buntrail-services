#![cfg(windows)]
use buntrail_services::Services;
use serde_json::json;
#[test]
fn conpty_runs_command_resizes_and_reaps_on_explicit_close() {
    let directory = tempfile::tempdir().unwrap();
    let services = Services::new();
    let shell =
        std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/cmd.exe");
    let session = services
        .call(&json!({"command":"terminal.start","root":directory.path(),"shell":shell}))
        .unwrap();
    let id = &session["id"];
    services
        .call(&json!({"command":"terminal.resize","id":id,"columns":100,"rows":30}))
        .unwrap();
    services
        .call(&json!({"command":"terminal.write","id":id,"text":"echo BUNTRAIL_CONPTY_OK\r\n"}))
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut output = String::new();
    while !output.contains("BUNTRAIL_CONPTY_OK") && std::time::Instant::now() < deadline {
        output.push_str(
            services
                .call(&json!({"command":"terminal.read","id":id}))
                .unwrap()["output"]
                .as_str()
                .unwrap(),
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(output.contains("BUNTRAIL_CONPTY_OK"), "{output}");
    services
        .call(&json!({"command":"terminal.write","id":id,"text":"exit\r\n"}))
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut drained = false;
    while std::time::Instant::now() < deadline {
        if services
            .call(&json!({"command":"terminal.read","id":id}))
            .unwrap()["drained"]
            == true
        {
            drained = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        drained,
        "ConPTY must release its output pipe after shell exit"
    );
    services
        .call(&json!({"command":"terminal.close","id":id}))
        .unwrap();
    assert!(
        services
            .call(&json!({"command":"terminal.read","id":id}))
            .is_err()
    );
}
