use buntrail_services::welcome_folder;
#[test]
fn validates_names_and_preserves_collisions() {
    let dir = tempfile::tempdir().unwrap();
    for invalid in ["", ".", "..", "a/b"] {
        assert!(welcome_folder(dir.path(), Some(invalid), None).is_err());
    }
    let child = welcome_folder(dir.path(), Some("a b"), None).unwrap();
    std::fs::write(child.join("keep"), b"original").unwrap();
    assert!(welcome_folder(dir.path(), Some("a b"), None).is_err());
    assert_eq!(std::fs::read(child.join("keep")).unwrap(), b"original");
}
#[test]
fn clones_into_exact_new_child_once() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source.git");
    assert!(
        std::process::Command::new("git")
            .args(["init", "--bare"])
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    let dest = dir.path().join("parent");
    std::fs::create_dir(&dest).unwrap();
    let clone = || welcome_folder(&dest, None, source.to_str());
    assert_eq!(clone().unwrap(), dest.join("source"));
    assert!(dest.join("source/.git").is_dir());
    assert!(clone().is_err());
}
