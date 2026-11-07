use super::process;
use crate::files::{digest, io_error};
use buntrail_core::contracts::*;
use std::{
    ffi::{OsStr, OsString},
    fs::OpenOptions,
    io::Read,
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

// Reconciliation is a bounded read, never a retry. A latched cancellation of the mutation
// does not skip its evidence. A new cancellation during post-failure observation still applies.
const OBSERVATION_DEADLINE: Duration = Duration::from_secs(5);
const OBSERVATION_OUTPUT: usize = 64 * 1024;
fn command(
    root: &Path,
    args: &[OsString],
    cancel: &AtomicBool,
    until: Instant,
) -> Result<Vec<u8>, CoreError> {
    let remaining = until
        .checked_duration_since(Instant::now())
        .ok_or_else(|| io_error("network observation deadline exceeded"))?;
    process::run_with_limits(root, args, cancel, remaining, OBSERVATION_OUTPUT)?.checked()
}
pub(super) fn intent(
    root: &Path,
    mutation: &GitMutation,
    cancel: &AtomicBool,
) -> Option<GitNetworkIntent> {
    let (action, remote, reference) = match mutation {
        GitMutation::Fetch { remote } => (GitNetworkAction::Fetch, remote, Vec::new()),
        GitMutation::Push { remote, reference } => {
            (GitNetworkAction::Push, remote, reference.clone())
        }
        GitMutation::PullFastForward { remote, reference } => {
            (GitNetworkAction::PullFastForward, remote, reference.clone())
        }
        _ => return None,
    };
    let until = Instant::now() + OBSERVATION_DEADLINE;
    let push_mapping_unconfigured = action != GitNetworkAction::Push
        || unmapped_push(root, remote, cancel, until).unwrap_or(false);
    let resolved = resolve(root, remote, &action, cancel, until);
    let alias = resolved.as_ref().is_ok_and(|(_, alias)| *alias);
    Some(GitNetworkIntent {
        action,
        push_mapping_unconfigured,
        remote: if alias {
            remote.clone()
        } else {
            b"direct endpoint".to_vec()
        },
        reference,
        endpoint_fingerprint: resolved.ok().map(|(endpoint, _)| digest(&endpoint)),
    })
}
fn unmapped_push(
    root: &Path,
    remote: &[u8],
    cancel: &AtomicBool,
    until: Instant,
) -> Result<bool, CoreError> {
    // Names alone establish presence, including empty/multiple values, without retaining config secrets.
    let names = command(
        root,
        &process::args(&["config", "--null", "--list", "--name-only"]),
        cancel,
        until,
    )?;
    let key = [b"remote.".as_slice(), remote, b".push"].concat();
    Ok(!names.split(|b| *b == 0).any(|name| name == key))
}
fn check_push_mapping(
    root: &Path,
    intent: &GitNetworkIntent,
    remote: &[u8],
    cancel: &AtomicBool,
    until: Instant,
) -> Result<(), CoreError> {
    // shortcut: configured push refspecs stay unresolved; extend only with exact destination resolution.
    if intent.action == GitNetworkAction::Push
        && (!intent.push_mapping_unconfigured || !unmapped_push(root, remote, cancel, until)?)
    {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "Configured push mapping: destination observation unresolved; terminal handoff disabled",
        ));
    }
    Ok(())
}
fn resolve(
    root: &Path,
    remote: &[u8],
    action: &GitNetworkAction,
    cancel: &AtomicBool,
    until: Instant,
) -> Result<(Vec<u8>, bool), CoreError> {
    let names = command(root, &process::args(&["remote"]), cancel, until)?;
    if !names.split(|b| *b == b'\n').any(|n| n == remote) {
        return Ok((remote.to_vec(), false));
    }
    let mut args = process::args(&["remote", "get-url", "--all"]);
    if *action == GitNetworkAction::Push {
        args.push("--push".into());
    }
    args.push("--".into());
    args.push(OsStr::from_bytes(remote).into());
    let urls = command(root, &args, cancel, until)?;
    let urls: Vec<_> = urls
        .split(|b| *b == b'\n')
        .filter(|u| !u.is_empty())
        .collect();
    if urls.len() != 1 || urls[0].len() > 4096 {
        return Err(io_error("remote has multiple or oversized endpoints"));
    }
    Ok((urls[0].to_vec(), true))
}
pub(super) fn observe(
    root: &Path,
    intent: &GitNetworkIntent,
    mutation: &GitMutation,
    cancel: &AtomicBool,
) -> Result<GitNetworkObservation, CoreError> {
    observe_until(
        root,
        intent,
        mutation,
        cancel,
        Instant::now() + OBSERVATION_DEADLINE,
    )
}
fn observe_until(
    root: &Path,
    intent: &GitNetworkIntent,
    mutation: &GitMutation,
    cancel: &AtomicBool,
    until: Instant,
) -> Result<GitNetworkObservation, CoreError> {
    let remote = match mutation {
        GitMutation::Fetch { remote }
        | GitMutation::Push { remote, .. }
        | GitMutation::PullFastForward { remote, .. } => remote,
        _ => return Err(io_error("not a network operation")),
    };
    check_push_mapping(root, intent, remote, cancel, until)?;
    let (endpoint, alias) = resolve(root, remote, &intent.action, cancel, until)?;
    // shortcut: direct URL rewrites remain unresolved; extend when exact transport resolution is available.
    if !alias || intent.remote != *remote {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "Direct or changed remote selection: network observation unresolved",
        ));
    }
    if intent.endpoint_fingerprint != Some(digest(&endpoint)) {
        return Err(io_error(
            "network endpoint changed or unresolved; handoff remains disabled",
        ));
    }
    if intent.action == GitNetworkAction::Push
        && resolve(root, remote, &GitNetworkAction::Fetch, cancel, until)?.0 != endpoint
    {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "Push and fetch endpoints differ: network observation unresolved",
        ));
    }
    if !intent.reference.is_empty() && !intent.reference.starts_with(b"refs/") {
        return Err(io_error(
            "network reconciliation requires an unambiguous full ref",
        ));
    }
    let mut args = process::args(&["ls-remote", "--refs", "--"]);
    args.push(OsStr::from_bytes(remote).into());
    if !intent.reference.is_empty() {
        args.push(OsStr::from_bytes(&intent.reference).into());
    }
    let refs = command(root, &args, cancel, until)?;
    let mut remote_oid = None;
    for line in refs.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
        let Some(tab) = line.iter().position(|b| *b == b'\t') else {
            return Err(io_error("invalid remote ref observation"));
        };
        let oid = &line[..tab];
        if !(oid.len() == 40 || oid.len() == 64) || !oid.iter().all(u8::is_ascii_hexdigit) {
            return Err(io_error("invalid remote OID"));
        }
        if &line[tab + 1..] == intent.reference.as_slice() {
            remote_oid = Some(String::from_utf8_lossy(oid).into_owned());
        }
    }
    let local = command(
        root,
        &process::args(&["for-each-ref", "--format=%(refname)%00%(objectname)"]),
        cancel,
        until,
    )?;
    let fetch_path = command(
        root,
        &process::args(&[
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "FETCH_HEAD",
        ]),
        cancel,
        until,
    )?;
    let fetch_path = fetch_path
        .strip_suffix(b"\n")
        .ok_or_else(|| io_error("invalid FETCH_HEAD path"))?;
    let mut fetch_head = Vec::new();
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(Path::new(OsStr::from_bytes(fetch_path)))
    {
        Ok(file) => {
            let metadata = file.metadata().map_err(io_error)?;
            if !metadata.is_file() || metadata.len() > 4096 {
                return Err(io_error("FETCH_HEAD is not a bounded regular file"));
            }
            file.take(4097)
                .read_to_end(&mut fetch_head)
                .map_err(io_error)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io_error(e)),
    }
    if cancel.load(std::sync::atomic::Ordering::SeqCst) || Instant::now() >= until {
        return Err(io_error("network observation interrupted"));
    }
    if fetch_head.len() > 4096 {
        return Err(io_error("FETCH_HEAD observation exceeds bound"));
    }
    // Re-check configuration after observing through the alias; do not qualify a changed route.
    if resolve(root, remote, &intent.action, cancel, until)?.0 != endpoint
        || resolve(root, remote, &GitNetworkAction::Fetch, cancel, until)?.0 != endpoint
    {
        return Err(io_error("network endpoint changed during observation"));
    }
    check_push_mapping(root, intent, remote, cancel, until)?;
    Ok(GitNetworkObservation {
        remote_oid,
        remote_refs_fingerprint: digest(&refs),
        local_refs_fingerprint: digest(&local),
        fetch_head_fingerprint: digest(&fetch_head),
        fetch_head_oids: fetch_oids(&fetch_head)?,
    })
}

fn fetch_oids(bytes: &[u8]) -> Result<Vec<u8>, CoreError> {
    let mut oids = Vec::new();
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let oid = line.split(|b| *b == b'\t').next().unwrap();
        if !(oid.len() == 40 || oid.len() == 64) || !oid.iter().all(u8::is_ascii_hexdigit) {
            return Err(io_error("invalid FETCH_HEAD OID"));
        }
        oids.extend_from_slice(oid);
        oids.push(b'\n');
    }
    Ok(oids)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn push_mapping_presence_includes_empty_and_multiple_values_for_only_selected_remote() {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(dir.path())
                    .args(args)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        };
        git(&["init"]);
        let supported = |remote: &[u8]| {
            unmapped_push(
                dir.path(),
                remote,
                &AtomicBool::new(false),
                Instant::now() + OBSERVATION_DEADLINE,
            )
            .unwrap()
        };
        assert!(supported(b"origin"));
        git(&[
            "config",
            "--add",
            "remote.other.push",
            "refs/heads/main:refs/heads/deploy",
        ]);
        assert!(supported(b"origin"));
        git(&["config", "--add", "remote.origin.push", ""]);
        assert!(!supported(b"origin"));
        git(&[
            "config",
            "--add",
            "remote.origin.push",
            "refs/heads/main:refs/heads/deploy",
        ]);
        assert!(!supported(b"origin"));
        git(&["config", "--unset-all", "remote.origin.push"]);
        assert!(supported(b"origin"));
    }
    #[test]
    fn fetch_head_keeps_only_valid_oids_not_endpoint_descriptions() {
        let oid = "a".repeat(40);
        let contents =
            format!("{oid}\t\tbranch 'main' of https://user:secret@example.invalid/repo\n");
        assert_eq!(
            fetch_oids(contents.as_bytes()).unwrap(),
            format!("{oid}\n").as_bytes()
        );
        assert!(fetch_oids(b"secret\t\tdescription\n").is_err());
    }
    #[test]
    fn durable_intent_does_not_store_credential_bearing_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            std::process::Command::new("git")
                .arg("init")
                .arg(dir.path())
                .output()
                .unwrap()
                .status
                .success()
        );
        let secret = b"https://user:fixture-secret@example.invalid/repo";
        for remote in [secret.to_vec(), b"origin".to_vec()] {
            if remote == b"origin" {
                assert!(
                    std::process::Command::new("git")
                        .arg("-C")
                        .arg(dir.path())
                        .args([
                            "remote",
                            "add",
                            "origin",
                            std::str::from_utf8(secret).unwrap()
                        ])
                        .output()
                        .unwrap()
                        .status
                        .success()
                );
            }
            let value = intent(
                dir.path(),
                &GitMutation::Fetch { remote },
                &AtomicBool::new(false),
            )
            .unwrap();
            let encoded = serde_json::to_value(value).unwrap();
            assert!(
                encoded.get("endpoint").is_none(),
                "raw resolved endpoint must not be durable"
            );
            assert_ne!(
                encoded["remote"],
                serde_json::to_value(secret.to_vec()).unwrap()
            );
        }
    }
    #[test]
    fn slow_remote_observation_is_stopped_at_the_shared_deadline() {
        let dir = tempfile::tempdir().unwrap();
        for args in [vec!["init"], vec!["config", "protocol.ext.allow", "always"]] {
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(dir.path())
                    .args(args)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        }
        std::fs::write(
            dir.path().join("wait"),
            b"echo started > observed-started\nsleep 20\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(["remote", "add", "fixture", "ext::sh ./wait"])
                .output()
                .unwrap()
                .status
                .success()
        );
        let intent = GitNetworkIntent {
            action: GitNetworkAction::Push,
            remote: b"fixture".to_vec(),
            reference: b"refs/heads/main".to_vec(),
            endpoint_fingerprint: Some(digest(b"ext::sh ./wait")),
            push_mapping_unconfigured: true,
        };
        let start = Instant::now();
        let error = observe_until(
            dir.path(),
            &intent,
            &GitMutation::Push {
                remote: b"fixture".to_vec(),
                reference: b"refs/heads/main".to_vec(),
            },
            &AtomicBool::new(false),
            start + Duration::from_secs(2),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Cancelled);
        assert!(dir.path().join("observed-started").exists());
        assert!(start.elapsed() < Duration::from_secs(4));
    }
    #[test]
    fn network_observation_is_cancellable_and_has_a_total_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let intent = GitNetworkIntent {
            action: GitNetworkAction::Push,
            remote: b"origin".to_vec(),
            reference: b"refs/heads/main".to_vec(),
            endpoint_fingerprint: Some(digest(b"unused")),
            push_mapping_unconfigured: true,
        };
        assert_eq!(
            observe(
                dir.path(),
                &intent,
                &GitMutation::Fetch {
                    remote: b"unused".to_vec()
                },
                &AtomicBool::new(true)
            )
            .unwrap_err()
            .code,
            ErrorCode::Cancelled
        );
        let start = Instant::now();
        assert!(
            observe_until(
                dir.path(),
                &intent,
                &GitMutation::Fetch {
                    remote: b"unused".to_vec()
                },
                &AtomicBool::new(false),
                start
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
