use super::local::*;
use crate::operations::ledger::{Record, now, unknown};
use buntrail_core::contracts::*;
use std::{
    fs,
    fs::File,
    io::Write,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::Path,
};
impl LocalFileService {
    pub fn list_sync(&self, directory: FileRef) -> Result<Vec<FileEntry>, CoreError> {
        let path = self.validate(&directory)?;
        let mut entries = vec![];
        for entry in fs::read_dir(path).map_err(io_error)? {
            let e = entry.map_err(io_error)?;
            if entries.len() == 100_000 {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "directory exceeds 100,000 entries",
                ));
            }
            let m = e.metadata().map_err(io_error)?;
            let kind = if e.file_type().map_err(io_error)?.is_symlink() {
                FileKind::Symlink
            } else if m.is_dir() {
                FileKind::Directory
            } else if m.is_file() {
                FileKind::File
            } else {
                FileKind::Other
            };
            entries.push(FileEntry {
                file: FileRef {
                    target: directory.target.clone(),
                    path: target_path(&e.path()),
                    resolved_identity: None,
                },
                display_name: e.file_name().to_string_lossy().into_owned(),
                kind,
            });
        }
        entries.sort_by(|a, b| {
            (a.kind != FileKind::Directory, &a.display_name)
                .cmp(&(b.kind != FileKind::Directory, &b.display_name))
        });
        Ok(entries)
    }
    /// Version directory contents and symlink nodes without following them for destructive actions.
    pub fn path_version(&self, file: FileRef) -> Result<FileVersion, CoreError> {
        let p = self.validate(&file)?;
        let m = fs::symlink_metadata(&p).map_err(io_error)?;
        if m.is_file() {
            return self.current_version(file);
        }
        let tree = super::watcher::fingerprint(&p)?;
        let content = digest(&tree);
        Ok(FileVersion {
            target: file.target,
            opaque_token: content.to_vec(),
            content_digest: content,
            file_identity: [m.dev().to_be_bytes(), m.ino().to_be_bytes()].concat(),
        })
    }
    pub fn mutate_sync(&self, request: FileMutationRequest) -> OperationReceipt {
        let fail = |e| failure(request.operation, request.file.target.clone(), e);
        let result = (|| -> Result<OperationReceipt, CoreError> {
            let original = self.validate(&request.file)?;
            let bytes = match &request.command {
                FileMutation::Create { source } => {
                    Some(self.source_bytes(source, super::MAX_ENCODED_BYTES, true)?)
                }
                _ => None,
            };
            let command_digest = match &request.command {
                FileMutation::Create { .. } => digest(bytes.as_ref().unwrap()),
                _ => digest(&serde_json::to_vec(&request.command).map_err(io_error)?),
            };
            let fingerprint = digest(
                &serde_json::to_vec(&(&request.file, &request.expected, command_digest))
                    .map_err(io_error)?,
            );
            let ledger = self.ledger.lock().map_err(io_error)?;
            let _lock = ledger.lock()?;
            if let Some(old) = ledger.read(request.operation)? {
                if old.envelope.request_digest != fingerprint
                    || old.envelope.target != request.file.target
                {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "operation ID reused with different request",
                    ));
                }
                return ledger.inspect(request.operation, request.file.target.clone());
            }
            let validate = || -> Result<(), CoreError> {
                match &request.expected {
                    ExpectedPathState::Absent
                        if fs::symlink_metadata(&original)
                            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                    {
                        Ok(())
                    }
                    ExpectedPathState::Present(v)
                        if self.path_version(request.file.clone())? == *v =>
                    {
                        Ok(())
                    }
                    _ => Err(CoreError::new(
                        ErrorCode::StaleRevision,
                        "path changed; refresh before retrying",
                    )),
                }
            };
            validate()?;
            let destination = match &request.command {
                FileMutation::Rename { destination } | FileMutation::Move { destination } => {
                    Some(path(destination)?)
                }
                FileMutation::Trash => Some(trash_destination(&original)?),
                _ => None,
            };
            if let Some(dest) = &destination {
                if fs::symlink_metadata(dest).is_ok() {
                    return Err(CoreError::new(
                        ErrorCode::StaleRevision,
                        "destination exists",
                    ));
                }
                if dest.starts_with(&original) {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "cannot move a folder into itself",
                    ));
                }
            }
            let mut record = Record {
                envelope: OperationEnvelope {
                    id: request.operation,
                    target: request.file.target.clone(),
                    request_digest: fingerprint,
                    kind: MutationKind::File,
                    expected: ExpectedState::File {
                        file: request.file.clone(),
                        version: match &request.expected {
                            ExpectedPathState::Absent => None,
                            ExpectedPathState::Present(v) => Some(v.clone()),
                        },
                    },
                },
                destination: None,
                save_proof: None,
                terminal_request: None,
                git_intent: None,
                requested_digest: command_digest,
                revision: BufferRevision(0),
                receipt: OperationReceipt {
                    id: request.operation,
                    state: OperationState::Accepted,
                },
                created: now(),
            };
            if let Some(existing) = ledger.accept(&record, &_lock)? {
                return Ok(existing);
            }
            let mut effected = false;
            let effect = (|| -> Result<MutationResult, CoreError> {
                validate()?;
                match &request.command {
                    FileMutation::Create { .. } => {
                        let parent = original
                            .parent()
                            .ok_or_else(|| io_error("missing parent"))?;
                        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(io_error)?;
                        tmp.write_all(bytes.as_ref().unwrap()).map_err(io_error)?;
                        tmp.as_file().sync_all().map_err(io_error)?;
                        tmp.persist_noclobber(&original).map_err(io_error)?;
                    }
                    FileMutation::CreateDirectory => fs::create_dir(&original).map_err(io_error)?,
                    FileMutation::Rename { .. }
                    | FileMutation::Move { .. }
                    | FileMutation::Trash => {
                        rename_exclusive(&original, destination.as_ref().unwrap())?
                    }
                    FileMutation::Remove => {
                        let m = fs::symlink_metadata(&original).map_err(io_error)?;
                        if m.is_dir() {
                            fs::remove_dir(&original).map_err(io_error)?;
                        } else {
                            fs::remove_file(&original).map_err(io_error)?;
                        }
                    }
                    FileMutation::Delete => {
                        let m = fs::symlink_metadata(&original).map_err(io_error)?;
                        if m.is_dir() {
                            effected = true;
                            fs::remove_dir_all(&original).map_err(io_error)?;
                        } else {
                            fs::remove_file(&original).map_err(io_error)?;
                        }
                    }
                }
                effected = true;
                File::open(
                    original
                        .parent()
                        .ok_or_else(|| io_error("missing parent"))?,
                )
                .and_then(|f| f.sync_all())
                .map_err(io_error)?;
                if let Some(dest) = &destination {
                    File::open(dest.parent().unwrap())
                        .and_then(|f| f.sync_all())
                        .map_err(io_error)?;
                }
                let removed = matches!(
                    request.command,
                    FileMutation::Delete | FileMutation::Remove | FileMutation::Trash
                );
                let mut file = request.file.clone();
                if let Some(dest) = destination.as_ref().filter(|_| !removed) {
                    file.path = target_path(dest);
                }
                file.resolved_identity = None;
                let version = if removed {
                    None
                } else {
                    Some(self.path_version(file.clone())?)
                };
                Ok(MutationResult::FileChanged { file, version })
            })();
            record.receipt = match effect {
                Ok(v) => OperationReceipt {
                    id: request.operation,
                    state: OperationState::Confirmed(v),
                },
                Err(e) if !effected => fail(e),
                Err(_) => unknown(
                    request.operation,
                    request.file.target.clone(),
                    "mutation may have partial effects; inspect paths before another action",
                ),
            };
            if ledger.write(&record).is_err() {
                return Ok(unknown(
                    request.operation,
                    request.file.target.clone(),
                    "mutation completion not durable; inspect paths",
                ));
            }
            Ok(record.receipt)
        })();
        result.unwrap_or_else(fail)
    }
}
#[cfg(target_os = "macos")]
pub(crate) fn rename_exclusive(from: &Path, to: &Path) -> Result<(), CoreError> {
    let from = std::ffi::CString::new(from.as_os_str().as_bytes()).map_err(io_error)?;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes()).map_err(io_error)?;
    if unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) } == 0 {
        Ok(())
    } else {
        Err(io_error(std::io::Error::last_os_error()))
    }
}
#[cfg(target_os = "linux")]
pub(crate) fn rename_exclusive(from: &Path, to: &Path) -> Result<(), CoreError> {
    let from = std::ffi::CString::new(from.as_os_str().as_bytes()).map_err(io_error)?;
    let to = std::ffi::CString::new(to.as_os_str().as_bytes()).map_err(io_error)?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io_error(std::io::Error::last_os_error()))
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn rename_exclusive(_: &Path, _: &Path) -> Result<(), CoreError> {
    Err(CoreError::new(
        ErrorCode::Unavailable,
        "exclusive rename unavailable on this platform",
    ))
}
fn trash_destination(original: &Path) -> Result<std::path::PathBuf, CoreError> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| io_error("home unavailable"))?;
        let trash = std::path::PathBuf::from(home).join(".Trash");
        let m = fs::symlink_metadata(&trash).map_err(io_error)?;
        if !m.is_dir()
            || m.uid() != unsafe { libc::geteuid() }
            || m.dev() != fs::symlink_metadata(original).map_err(io_error)?.dev()
        {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "Trash unavailable for this volume; choose permanent deletion explicitly",
            ));
        }
        let suffix = crate::connections::local::new_id()?;
        let mut name = original
            .file_name()
            .ok_or_else(|| io_error("missing name"))?
            .to_os_string();
        name.push(format!(
            ".{}",
            suffix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        Ok(trash.join(name))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = original;
        Err(CoreError::new(
            ErrorCode::Unavailable,
            "local Trash unavailable",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_version_matches_original_and_stale_delete_has_no_effect() {
        let temp = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(temp.path()).unwrap();
        let project = base.join("project");
        fs::create_dir_all(project.join("sub")).unwrap();
        fs::write(project.join("sub/file"), b"original").unwrap();
        fs::write(project.join("keep"), b"keep").unwrap();
        let alias = base.join("external-hardlink");
        fs::hard_link(project.join("sub/file"), &alias).unwrap();
        let target = TargetIdentity {
            security_binding: vec![1],
            effective_user: vec![2],
            filesystem_namespace: vec![3],
            container: None,
        };
        let service = LocalFileService::new(target.clone(), base.join("private")).unwrap();
        let file = FileRef {
            target: target.clone(),
            path: target_path(&project),
            resolved_identity: None,
        };
        let m = fs::symlink_metadata(&project).unwrap();
        let old_digest = digest(&super::super::watcher::reference_fingerprint(&project).unwrap());
        let expected = FileVersion {
            target,
            opaque_token: old_digest.to_vec(),
            content_digest: old_digest,
            file_identity: [m.dev().to_be_bytes(), m.ino().to_be_bytes()].concat(),
        };
        let before = service.path_version(file.clone()).unwrap();
        assert_eq!(before, expected);
        fs::write(&alias, b"external longer change").unwrap();
        let after = service.path_version(file.clone()).unwrap();
        assert_ne!(before, after);
        assert_eq!(
            after.content_digest,
            digest(&super::super::watcher::reference_fingerprint(&project).unwrap())
        );
        let receipt = service.mutate_sync(FileMutationRequest {
            operation: OperationID([243; 16]),
            file,
            expected: ExpectedPathState::Present(before),
            command: FileMutation::Delete,
        });
        let OperationState::Failed(failure) = receipt.state else {
            panic!("stale destructive request was not refused")
        };
        assert_eq!(failure.error.code, ErrorCode::StaleRevision);
        assert_eq!(failure.effect, FailureEffect::ProvenNoEffect);
        assert!(project.is_dir());
        assert_eq!(
            fs::read(project.join("sub/file")).unwrap(),
            b"external longer change"
        );
        assert_eq!(fs::read(project.join("keep")).unwrap(), b"keep");
        assert_eq!(fs::read(alias).unwrap(), b"external longer change");
    }
}
