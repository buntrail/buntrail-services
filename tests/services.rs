use buntrail_services::Services;
use serde_json::json;
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
#[test]
fn fifo_read_is_rejected_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("not-a-text-file");
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let (sender, receiver) = std::sync::mpsc::channel();
    let input = path.clone();
    let worker = std::thread::spawn(move || {
        let _ = sender.send(Services::new().call(&json!({"command":"fs.read","path":input})));
    });
    let result = receiver.recv_timeout(std::time::Duration::from_millis(200));
    if result.is_err() {
        // Release a blocking implementation before reporting the regression.
        let _writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let _ = receiver.recv_timeout(std::time::Duration::from_secs(1));
    }
    worker.join().unwrap();
    assert!(result.is_ok(), "Opening a FIFO blocked the service worker");
    assert!(result.unwrap().is_err());
}

#[cfg(unix)]
#[test]
fn terminal_keeps_final_output_until_reader_and_backlog_are_drained() {
    let directory = tempfile::tempdir().unwrap();
    let services = Services::new();
    let session = services
        .call(&json!({"command":"terminal.start","root":directory.path(),"shell":"/bin/sh"}))
        .unwrap();
    let id = &session["id"];
    services.call(&json!({"command":"terminal.write","id":id,"text":"awk 'BEGIN{for(i=0;i<300000;i++)printf \"x\"; print \"BUNTRAIL_TAIL\"}'\nexit\n"})).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut bytes = Vec::new();
    let mut drained = false;
    while std::time::Instant::now() < deadline {
        let output = services
            .call(&json!({"command":"terminal.read","id":id}))
            .unwrap();
        bytes.extend(
            output["bytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as u8),
        );
        assert_eq!(output["truncated"], false);
        if output["drained"] == true {
            drained = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    services
        .call(&json!({"command":"terminal.close","id":id}))
        .unwrap();
    assert!(
        drained,
        "reader must report complete drain after process exit"
    );
    assert!(
        bytes.iter().filter(|byte| **byte == b'x').count() >= 300000,
        "final output was lost"
    );
    assert!(bytes.windows(13).any(|window| window == b"BUNTRAIL_TAIL"));
}
use std::{fs, process::Command};

#[test]
fn read_write_preserves_bom_and_rejects_stale_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("literal ; $ file.txt");
    fs::write(&path, "\u{feff}hello").unwrap();
    let service = Services::new();
    let first = service
        .call(&json!({"command":"fs.read","path":path}))
        .unwrap();
    #[cfg(unix)]
    assert_eq!(first["text"], "hello");
    #[cfg(not(unix))]
    assert_eq!(first["text"], "\u{feff}hello");
    assert!(
        service
            .call(&json!({"command":"fs.write","path":path,"text":"no"}))
            .is_err()
    );
    let saved = service
        .call(&json!({"command":"fs.write","path":path,"text":"second","version":first["version"]}))
        .unwrap();
    assert_ne!(saved["version"], first["version"]);
    fs::write(&path, "external").unwrap();
    assert!(
        service
            .call(
                &json!({"command":"fs.write","path":path,"text":"bad","version":saved["version"]})
            )
            .unwrap_err()
            .contains("conflict")
    );
    assert_eq!(fs::read_to_string(path).unwrap(), "external");
}

#[cfg(unix)]
#[test]
fn write_preserves_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");
    fs::write(&path, "before").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let services = Services::new();
    let read = services
        .call(&json!({"command":"fs.read","path":path}))
        .unwrap();
    services
        .call(&json!({"command":"fs.write","path":path,"text":"after","version":read["version"]}))
        .unwrap();
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn git_and_search_use_literal_arguments() {
    let dir = tempfile::tempdir().unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(dir.path())
            .status()
            .unwrap()
            .success()
    );
    fs::write(
        dir.path().join("literal.txt"),
        "literal $(touch DANGER)\nother\n",
    )
    .unwrap();
    let services = Services::new();
    let git = services
        .call(&json!({"command":"git","root":dir.path(),"args":["status","--porcelain"]}))
        .unwrap();
    assert_eq!(git["status"], 0);
    assert!(git["stdout"].as_str().unwrap().contains("literal.txt"));
    let found = services
        .call(&json!({"command":"search","root":dir.path(),"query":"$(touch DANGER)"}))
        .unwrap();
    assert_eq!(found["matches"][0]["line"], 1);
    assert!(!dir.path().join("DANGER").exists());
    assert!(
        services
            .call(&json!({"command":"git","root":dir.path(),"args":[7]}))
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn terminal_is_real_pty_and_closes_explicitly() {
    let dir = tempfile::tempdir().unwrap();
    let services = Services::new();
    let session = services
        .call(&json!({"command":"terminal.start","root":dir.path(),"shell":"/bin/sh"}))
        .unwrap();
    let id = session["id"].clone();
    services
        .call(&json!({"command":"terminal.resize","id":id,"columns":97,"rows":31}))
        .unwrap();
    services.call(&json!({"command":"terminal.write","id":id,"text":"test -t 0 && printf '\\nPTY_READY\\n'; stty size\n"})).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    let mut output = String::new();
    while Instant::now() < until {
        let read = services
            .call(&json!({"command":"terminal.read","id":id}))
            .unwrap();
        output.push_str(read["output"].as_str().unwrap());
        if output.contains("\r\nPTY_READY\r\n") && output.contains("31 97") {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(output.contains("\r\nPTY_READY\r\n"), "{output}");
    assert!(output.contains("31 97"), "{output}");
    services
        .call(&json!({"command":"terminal.close","id":id}))
        .unwrap();
    assert!(
        services
            .call(&json!({"command":"terminal.read","id":id}))
            .is_err()
    );
}

#[test]
fn create_is_exclusive_and_never_replaces_existing_paths() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("new.txt");
    let services = Services::new();
    let created = services
        .call(&json!({"command":"fs.create","path":path,"text":"new"}))
        .unwrap();
    assert!(created["version"].is_string());
    assert_eq!(fs::read_to_string(&path).unwrap(), "new");
    assert!(
        services
            .call(&json!({"command":"fs.create","path":path,"text":"replace"}))
            .is_err()
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), "new");
    #[cfg(unix)]
    {
        let link = dir.path().join("symlink");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            services
                .call(&json!({"command":"fs.create","path":link,"text":"replace"}))
                .is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
    }
}

#[test]
fn search_reports_result_limit() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("many.txt"), "needle\n".repeat(10_100)).unwrap();
    let result = Services::new()
        .call(&json!({"command":"search","root":dir.path(),"query":"needle"}))
        .unwrap();
    assert_eq!(result["truncated"], true);
    assert_eq!(result["matches"].as_array().unwrap().len(), 10_000);
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_paths_return_error_instead_of_panicking() {
    use std::os::unix::ffi::OsStringExt;
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join(std::ffi::OsString::from_vec(vec![0xff])),
        "text",
    )
    .unwrap();
    assert!(
        Services::new()
            .call(&json!({"command":"fs.list","path":dir.path()}))
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn terminal_preserves_unicode_control_and_non_utf8_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let services = Services::new();
    let id = services
        .call(&json!({"command":"terminal.start","root":dir.path(),"shell":"/bin/sh"}))
        .unwrap()["id"]
        .clone();
    for bytes in [json!([-1]), json!([256]), json!([1.5]), json!([true])] {
        assert!(
            services
                .call(&json!({"command":"terminal.write","id":id,"bytes":bytes}))
                .is_err()
        );
    }
    assert!(
        services
            .call(&json!({"command":"terminal.write","id":id,"text":"x".repeat(1024*1024+1)}))
            .is_err()
    );
    let command = "printf '\\033[31m\\303\\251\\377\\033[0m\\n'\n";
    services
        .call(&json!({"command":"terminal.write","id":id,"bytes":command.as_bytes()}))
        .unwrap();
    let expected = b"\x1b[31m\xc3\xa9\xff\x1b[0m\r\n";
    let until = Instant::now() + Duration::from_secs(3);
    let mut bytes = Vec::new();
    while Instant::now() < until {
        let read = services
            .call(&json!({"command":"terminal.read","id":id}))
            .unwrap();
        let part: Vec<u8> = serde_json::from_value(read["bytes"].clone()).unwrap();
        bytes.extend(part);
        if bytes.windows(expected.len()).any(|part| part == expected) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    services
        .call(&json!({"command":"terminal.close","id":id}))
        .unwrap();
    assert!(
        bytes.windows(expected.len()).any(|part| part == expected),
        "{bytes:?}"
    );
}

#[test]
fn binary_files_are_rejected_without_changes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary");
    fs::write(&path, b"utf8\0binary").unwrap();
    let services = Services::new();
    assert!(
        services
            .call(&json!({"command":"fs.read","path":path}))
            .unwrap_err()
            .contains("binary")
    );
    assert!(
        services
            .call(&json!({"command":"fs.write","path":path,"text":"nul\0","version":"any"}))
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), b"utf8\0binary");
    let new = dir.path().join("new");
    assert!(
        services
            .call(&json!({"command":"fs.create","path":new,"text":"nul\0"}))
            .is_err()
    );
    assert!(!new.exists());
}

#[test]
fn explorer_mutations_never_clobber_or_recursively_delete() {
    let dir = tempfile::tempdir().unwrap();
    let services = Services::new();
    let folder = dir.path().join("folder");
    services
        .call(&json!({"command":"fs.mkdir","path":folder}))
        .unwrap();
    let first = folder.join("first");
    let second = folder.join("second");
    fs::write(&first, "first").unwrap();
    fs::write(&second, "second").unwrap();
    assert!(
        services
            .call(&json!({"command":"fs.rename","path":first,"to":second}))
            .is_err()
    );
    assert_eq!(fs::read_to_string(&first).unwrap(), "first");
    assert_eq!(fs::read_to_string(&second).unwrap(), "second");
    assert!(
        services
            .call(&json!({"command":"fs.remove","path":folder}))
            .is_err()
    );
    let renamed = folder.join("renamed ; literal");
    services
        .call(&json!({"command":"fs.rename","path":first,"to":renamed}))
        .unwrap();
    assert!(!first.exists());
    assert_eq!(fs::read_to_string(&renamed).unwrap(), "first");
    services
        .call(&json!({"command":"fs.remove","path":renamed}))
        .unwrap();
    services
        .call(&json!({"command":"fs.remove","path":second}))
        .unwrap();
    services
        .call(&json!({"command":"fs.remove","path":folder}))
        .unwrap();
    assert!(!folder.exists());
}
