use crate::files::{io_error, target_path};
use buntrail_core::contracts::*;
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path};
pub fn status(root: &Path, bytes: &[u8], snapshot: &mut GitSnapshot) -> Result<(), CoreError> {
    if !bytes.is_empty() && bytes.last() != Some(&0) {
        return Err(io_error("Incomplete Git status"));
    }
    let mut records = bytes.split(|b| *b == 0).peekable();
    while let Some(record) = records.next() {
        if record.is_empty() {
            continue;
        }
        if record.len() < 4 || record[2] != b' ' {
            return Err(io_error("Invalid Git status record"));
        }
        let name = &record[3..];
        let relative = Path::new(OsStr::from_bytes(name));
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(io_error("Invalid Git path"));
        }
        let previous = if record[..2].iter().any(|b| *b == b'R' || *b == b'C') {
            Some(target_path(
                &root.join(OsStr::from_bytes(
                    records
                        .next()
                        .ok_or_else(|| io_error("Missing rename source"))?,
                )),
            ))
        } else {
            None
        };
        let entry = GitEntry {
            path: target_path(&root.join(relative)),
            previous_path: previous,
            status: String::from_utf8_lossy(&record[..2]).into_owned(),
        };
        if &record[..2] == b"??" {
            snapshot.untracked.push(entry);
        } else if record[..2].contains(&b'U') || &record[..2] == b"AA" || &record[..2] == b"DD" {
            snapshot.conflicts.push(entry);
        } else {
            if record[0] != b' ' {
                snapshot.staged.push(entry.clone());
            }
            if record[1] != b' ' {
                snapshot.unstaged.push(entry);
            }
        }
    }
    Ok(())
}
