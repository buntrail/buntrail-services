use super::local::*;
use buntrail_core::contracts::*;
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(super) struct Plan {
    pub destination: PathBuf,
    pub info: Option<(PathBuf, String)>,
}
#[cfg(any(target_os = "linux", test))]
pub(super) fn info_text(original: &Path, date: &str) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut encoded = String::new();
    for &b in original.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || b"/-._~".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    format!("[Trash Info]\nPath={encoded}\nDeletionDate={date}\n")
}
fn secure_directory(path: &Path) -> Result<(), CoreError> {
    secure_directory_with_sync(path, &|directory| {
        fs::File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(io_error)
    })
}
fn secure_directory_with_sync(
    path: &Path,
    sync: &impl Fn(&Path) -> Result<(), CoreError>,
) -> Result<(), CoreError> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .map_err(io_error)?,
        Err(e) => return Err(io_error(e)),
        _ => {}
    }
    let m = fs::symlink_metadata(path).map_err(io_error)?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(io_error(
            "Trash directory must be a private owned directory, not a symlink",
        ));
    }
    // The recoverable namespace must be durable before the original parent is unlinked.
    sync(path)?;
    sync(
        path.parent()
            .ok_or_else(|| io_error("Trash directory has no parent"))?,
    )?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn date() -> Result<String, CoreError> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io_error)?
        .as_secs() as libc::time_t;
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    if unsafe { libc::localtime_r(&seconds, &mut tm) }.is_null() {
        return Err(io_error("Trash date unavailable"));
    }
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}
pub(super) fn prepare(original: &Path, operation: OperationID) -> Result<Plan, CoreError> {
    let metadata = fs::symlink_metadata(original).map_err(io_error)?;
    if metadata.is_dir() && fs::read_dir(original).map_err(io_error)?.next().is_some() {
        return Err(io_error(
            "Only files and empty folders can be moved to Trash",
        ));
    }
    let home = PathBuf::from(std::env::var_os("HOME").ok_or_else(|| io_error("Home unavailable"))?);
    if !home.is_absolute() {
        return Err(io_error("Home must be absolute"));
    }
    let suffix = operation
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut name = original
        .file_name()
        .ok_or_else(|| io_error("Missing file name"))?
        .to_os_string();
    name.push(format!(".{suffix}"));
    #[cfg(target_os = "macos")]
    {
        let trash = home.join(".Trash");
        secure_directory(&trash)?;
        if fs::symlink_metadata(&trash).map_err(io_error)?.dev() != metadata.dev() {
            return Err(io_error("Trash unavailable for this volume"));
        }
        Ok(Plan {
            destination: trash.join(name),
            info: None,
        })
    }
    #[cfg(target_os = "linux")]
    {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".local/share"));
        // Create standard data parents only below the verified home directory.
        if !data.exists() {
            if !data.starts_with(&home) {
                return Err(io_error("Trash data directory is unavailable"));
            }
            let relative = data.strip_prefix(&home).map_err(io_error)?;
            let mut current = home.clone();
            for part in relative.components() {
                if !matches!(part, std::path::Component::Normal(_)) {
                    return Err(io_error("Invalid Trash data path"));
                }
                current.push(part);
                secure_directory(&current)?;
            }
        }
        let data_meta = fs::symlink_metadata(&data).map_err(io_error)?;
        let (trash, relative) = if data_meta.dev() == metadata.dev() {
            (data.join("Trash"), original.to_owned())
        } else {
            let mut top = original
                .parent()
                .ok_or_else(|| io_error("No parent"))?
                .to_owned();
            while let Some(parent) = top.parent() {
                if fs::metadata(parent).map_err(io_error)?.dev() != metadata.dev() {
                    break;
                }
                top = parent.to_owned();
            }
            (
                top.join(format!(".Trash-{}", unsafe { libc::geteuid() })),
                original.strip_prefix(&top).map_err(io_error)?.to_owned(),
            )
        };
        secure_directory(&trash)?;
        secure_directory(&trash.join("files"))?;
        secure_directory(&trash.join("info"))?;
        let mut info_name = name.clone();
        info_name.push(".trashinfo");
        Ok(Plan {
            destination: trash.join("files").join(name),
            info: Some((
                trash.join("info").join(info_name),
                info_text(&relative, &date()?),
            )),
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (home, name);
        Err(io_error("Trash unavailable on this platform"))
    }
}
pub(super) fn write_info(plan: &Plan) -> Result<(), CoreError> {
    if let Some((path, text)) = &plan.info {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(io_error)?;
        file.write_all(text.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(io_error)?;
        fs::File::open(path.parent().unwrap())
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod durability_tests {
    use super::*;
    #[test]
    fn explorer_review_parent_sync_failure_refuses_trash_preparation() {
        let dir = tempfile::tempdir().unwrap();
        let trash = dir.path().join("Trash");
        let result = secure_directory_with_sync(&trash, &|path| {
            if path == dir.path() {
                Err(io_error("injected parent sync failure"))
            } else {
                Ok(())
            }
        });
        assert!(
            result.is_err(),
            "A nondurable directory must never be admitted as a Trash destination"
        );
    }
}
