#![cfg(unix)]
use buntrail_services::Services;
use serde_json::json;
use std::fs;

#[test]
fn save_refuses_hardlinks_without_modification() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("file");
    let peer = root.path().join("peer");
    fs::write(&path, "original").unwrap();
    fs::hard_link(&path, &peer).unwrap();
    let state_directory = tempfile::tempdir().unwrap();
    let services = Services::with_state_directory(state_directory.path().to_owned());
    let read = services
        .call(&json!({"command":"fs.read","path":path}))
        .unwrap();
    assert!(services.call(&json!({"command":"fs.write","path":path,"version":read["version"],"text":"changed"})).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"original");
    assert_eq!(fs::read(&peer).unwrap(), b"original");
}

#[test]
fn save_rejects_replaced_file_identity() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("file");
    fs::write(&path, "same").unwrap();
    let state_directory = tempfile::tempdir().unwrap();
    let services = Services::with_state_directory(state_directory.path().to_owned());
    let read = services
        .call(&json!({"command":"fs.read","path":path}))
        .unwrap();
    let replacement = root.path().join("replacement");
    fs::write(&replacement, "same").unwrap();
    fs::rename(&replacement, &path).unwrap();
    assert!(services.call(&json!({"command":"fs.write","path":path,"version":read["version"],"text":"changed"})).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"same");
}

#[test]
fn utf16_and_utf8_bom_round_trip() {
    let root = tempfile::tempdir().unwrap();
    let state_directory = tempfile::tempdir().unwrap();
    let services = Services::with_state_directory(state_directory.path().to_owned());
    for (name, original, expected) in [
        (
            "utf16le",
            b"\xff\xfea\0\r\0\n\0".as_slice(),
            b"\xff\xfeb\0\r\0\n\0".as_slice(),
        ),
        (
            "utf16be",
            b"\xfe\xff\0a\0\r\0\n".as_slice(),
            b"\xfe\xff\0b\0\r\0\n".as_slice(),
        ),
        (
            "utf8bom",
            b"\xef\xbb\xbfa\r\n".as_slice(),
            b"\xef\xbb\xbfb\r\n".as_slice(),
        ),
    ] {
        let path = root.path().join(name);
        fs::write(&path, original).unwrap();
        let read = services
            .call(&json!({"command":"fs.read","path":path}))
            .unwrap();
        assert_eq!(read["text"], "a\r\n");
        services
            .call(
                &json!({"command":"fs.write","path":path,"version":read["version"],"text":"b\r\n"}),
            )
            .unwrap();
        assert_eq!(fs::read(&path).unwrap(), expected);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn save_preserves_extended_metadata() {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("file");
    fs::write(&path, "original").unwrap();
    let raw = CString::new(path.as_os_str().as_bytes()).unwrap();
    let key = CString::new("com.buntrail.regression").unwrap();
    assert_eq!(
        unsafe { libc::setxattr(raw.as_ptr(), key.as_ptr(), b"keep".as_ptr().cast(), 4, 0, 0) },
        0
    );
    let state_directory = tempfile::tempdir().unwrap();
    let services = Services::with_state_directory(state_directory.path().to_owned());
    let read = services
        .call(&json!({"command":"fs.read","path":path}))
        .unwrap();
    services
        .call(&json!({"command":"fs.write","path":path,"version":read["version"],"text":"changed"}))
        .unwrap();
    let mut bytes = [0u8; 4];
    assert_eq!(
        unsafe {
            libc::getxattr(
                raw.as_ptr(),
                key.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                0,
                0,
            )
        },
        4
    );
    assert_eq!(&bytes, b"keep");
}

#[test]
fn save_as_preserves_source_encoding_and_existing_destination() {
    let root = tempfile::tempdir().unwrap();
    let services = Services::with_state_directory(root.path().join("private/nested/state"));
    let source = root.path().join("source");
    let destination = root.path().join("destination");
    fs::write(&source, b"\xff\xfea\0\r\0\n\0").unwrap();
    let read = services
        .call(&json!({"command":"fs.read","path":source}))
        .unwrap();
    services.call(&json!({"command":"fs.create","path":destination,"text":"b\r\n","source_version":read["version"]})).unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"\xff\xfeb\0\r\0\n\0");
    assert!(services.call(&json!({"command":"fs.create","path":destination,"text":"overwrite","source_version":read["version"]})).is_err());
    assert_eq!(fs::read(&source).unwrap(), b"\xff\xfea\0\r\0\n\0");
    assert_eq!(fs::read(&destination).unwrap(), b"\xff\xfeb\0\r\0\n\0");
}

#[test]
fn observed_tokens_are_stable_after_creation_and_save() {
    let root = tempfile::tempdir().unwrap();
    let services = Services::with_state_directory(root.path().join("state"));
    let path = root.path().join("file");
    let created = services
        .call(&json!({"command":"fs.create","path":path,"text":"original"}))
        .unwrap();
    let observed = services
        .call(&json!({"command":"fs.read","path":path}))
        .unwrap();
    assert_eq!(created["version"], observed["version"]);
    let saved = services.call(&json!({"command":"fs.write","path":path,"version":created["version"],"text":"changed"})).unwrap();
    let observed = services
        .call(&json!({"command":"fs.read","path":path}))
        .unwrap();
    assert_eq!(saved["version"], observed["version"]);
}

#[test]
fn save_as_cannot_export_a_foreign_binding_through_local_services() {
    let directory = tempfile::tempdir().unwrap();
    let service = Services::with_state_directory(directory.path().join("state"));
    let original = directory.path().join("original");
    std::fs::write(&original, "text").unwrap();
    let read = service
        .call(&json!({"command":"fs.read","path":original}))
        .unwrap();
    let mut binding = Services::file_binding(read["version"].as_str().unwrap()).unwrap();
    binding.file.target.effective_user.push(1);
    binding.version.target = binding.file.target.clone();
    let destination = directory.path().join("must-not-exist");
    assert!(service.call(&json!({"command":"fs.create","path":destination,"text":"private foreign draft","source_version":binding.token().unwrap()})).is_err());
    assert!(!destination.exists());
}

#[test]
fn malformed_source_encoding_is_not_silently_replaced_by_utf8() {
    let directory = tempfile::tempdir().unwrap();
    let service = Services::with_state_directory(directory.path().join("state"));
    let path = directory.path().join("must-not-exist");
    assert!(
        service
            .call(&json!({"command":"fs.create","path":path,"text":"draft","source_version":12}))
            .is_err()
    );
    assert!(!path.exists());
}

#[test]
fn destructive_facade_uses_the_node_observed_before_confirmation() {
    let root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let services = Services::with_state_directory(state.path().to_owned());
    let file = root.path().join("file");
    fs::write(&file, "approved").unwrap();
    let observed = services
        .call(&json!({"command":"fs.observe","path":file}))
        .unwrap();
    let replacement = root.path().join("replacement");
    fs::write(&replacement, "new owner").unwrap();
    fs::rename(&replacement, &file).unwrap();
    assert!(
        services
            .call(&json!({"command":"fs.remove","path":file,"observed":observed["observed"]}))
            .is_err()
    );
    assert_eq!(fs::read(&file).unwrap(), b"new owner");
    assert!(services.call(&json!({"command":"fs.rename","path":file,"to":root.path().join("moved"),"observed":observed["observed"]})).is_err());
}

#[test]
fn utf16_encoded_size_above_64_mib_remains_readable_and_saveable() {
    let root = tempfile::tempdir().unwrap();
    let state = tempfile::tempdir().unwrap();
    let services = Services::with_state_directory(state.path().to_owned());
    let path = root.path().join("large-utf16");
    let length = 33 * 1024 * 1024;
    let mut bytes = Vec::with_capacity(length * 2 + 2);
    bytes.extend_from_slice(&[255, 254]);
    for _ in 0..length {
        bytes.extend_from_slice(&[b'a', 0]);
    }
    fs::write(&path, &bytes).unwrap();
    drop(bytes);
    let read = services
        .call(&json!({"command":"fs.read","path":path}))
        .unwrap();
    assert_eq!(read["text"].as_str().unwrap().len(), length);
    let saved=services.call(&json!({"command":"fs.write","path":path,"version":read["version"],"text":"b".repeat(length)})).unwrap();
    assert!(saved["version"].as_str().unwrap().starts_with("bt2:"));
    let read = services
        .call(&json!({"command":"fs.read","path":path}))
        .unwrap();
    assert_eq!(read["text"].as_str().unwrap().len(), length);
    assert!(read["text"].as_str().unwrap().bytes().all(|b| b == b'b'));
    let created = path.with_extension("copy");
    services.call(&json!({"command":"fs.create","path":created,"text":read["text"],"source_version":read["version"]})).unwrap();
    assert_eq!(
        fs::metadata(created).unwrap().len(),
        (length * 2 + 2) as u64
    );
    assert_eq!(fs::metadata(path).unwrap().len(), (length * 2 + 2) as u64);
}
