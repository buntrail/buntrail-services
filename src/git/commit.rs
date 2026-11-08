use super::{LocalGitService, process, repository::oid};
use crate::files::io_error;
use buntrail_core::contracts::*;
use std::{ffi::OsString, os::unix::ffi::OsStrExt, sync::atomic::AtomicBool};

impl LocalGitService {
    pub fn commit_sync(
        &self,
        query: CommitQuery,
        cancel: &AtomicBool,
    ) -> Result<CommitPage, CoreError> {
        let id = oid(query.oid.as_bytes())?;
        let root = self.validate(&query.worktree, cancel)?;
        let mut args = process::args(&[
            "show",
            "--no-show-signature",
            "-s",
            "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%B%x00",
        ]);
        args.push(id.clone().into());
        args.push("--".into());
        let raw = self.command(&root, &args, cancel)?;
        let fields = raw.split(|b| *b == 0).collect::<Vec<_>>();
        if fields.len() != 7 {
            return Err(io_error("Invalid commit metadata"));
        }
        let parents = fields[1]
            .split(|b| *b == b' ')
            .filter(|v| !v.is_empty())
            .map(oid)
            .collect::<Result<Vec<_>, _>>()?;
        let mut args = process::args(&[
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-status",
            "-r",
            "-z",
            "-M",
        ]);
        if let Some(parent) = parents.first() {
            args.push(parent.into());
        }
        args.push(id.clone().into());
        args.push("--".into());
        let raw = self.command(&root, &args, cancel)?;
        if !raw.is_empty() && !raw.ends_with(&[0]) {
            return Err(io_error("Incomplete commit files"));
        }
        let mut records = raw.split(|b| *b == 0);
        let mut files = vec![];
        let path = |bytes: &[u8]| -> Result<TargetPath, CoreError> {
            if bytes.is_empty()
                || bytes.starts_with(b"/")
                || bytes.split(|b| *b == b'/').any(|p| p == b".." || p == b".")
            {
                return Err(io_error("Invalid commit path"));
            }
            TargetPath::posix([root.as_os_str().as_bytes(), b"/", bytes].concat())
        };
        while let Some(status) = records.next() {
            if status.is_empty() {
                break;
            }
            let first = records
                .next()
                .ok_or_else(|| io_error("Incomplete commit path"))?;
            let (change, previous_path, p) = match status[0] {
                b'R' | b'C' => (
                    DiffChange::Renamed,
                    Some(path(first)?),
                    records
                        .next()
                        .ok_or_else(|| io_error("Missing rename target"))?,
                ),
                b'A' => (DiffChange::Added, None, first),
                b'D' => (DiffChange::Deleted, None, first),
                b'M' | b'T' => (DiffChange::Modified, None, first),
                _ => return Err(io_error("Invalid commit change")),
            };
            files.push(GitCommitFile {
                path: path(p)?,
                previous_path,
                change,
            });
        }
        let offset = usize::try_from(query.cursor.unwrap_or(0)).map_err(io_error)?;
        if offset > files.len() {
            return Err(io_error("Invalid commit file cursor"));
        }
        let end = (offset + 200).min(files.len());
        Ok(CommitPage {
            oid: oid(fields[0])?,
            parents,
            author: String::from_utf8_lossy(fields[2]).into_owned(),
            email: String::from_utf8_lossy(fields[3]).into_owned(),
            authored_at: String::from_utf8_lossy(fields[4]).into_owned(),
            message: String::from_utf8_lossy(fields[5]).into_owned(),
            next_cursor: if end < files.len() {
                Some(end as u64)
            } else {
                None
            },
            files: files[offset..end].to_vec(),
        })
    }
    pub fn commit_diff_sync(
        &self,
        request: DiffRequest,
        cancel: &AtomicBool,
    ) -> Result<DiffSnapshot, CoreError> {
        let DiffSource::Commit(id) = &request.source else {
            return Err(io_error("Expected commit source"));
        };
        let root = self.validate(&request.worktree, cancel)?;
        let mut query = CommitQuery {
            worktree: request.worktree.clone(),
            oid: id.clone(),
            cursor: None,
        };
        let (metadata, file) = loop {
            let page = self.commit_sync(query.clone(), cancel)?;
            if let Some(file) = page.files.iter().find(|f| f.path == request.path).cloned() {
                break (page, file);
            }
            match page.next_cursor {
                Some(cursor) => query.cursor = Some(cursor),
                None => return Err(io_error("File is not changed in this commit")),
            }
        };
        let mut args = process::args(if metadata.parents.is_empty() {
            &["diff-tree", "--root", "--no-commit-id", "-p"][..]
        } else {
            &["diff"][..]
        });
        args.extend(process::args(&[
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--binary",
            "-M",
        ]));
        if let Some(parent) = metadata.parents.first() {
            args.push(parent.into());
        }
        args.push(metadata.oid.into());
        args.push("--".into());
        for path in std::iter::once(&file.path).chain(file.previous_path.iter()) {
            let raw = crate::files::path(path)?;
            let relative = raw.strip_prefix(&root).map_err(io_error)?;
            args.push(OsString::from(relative));
        }
        let output = process::run(&root, &args, cancel)?;
        let content = if output.interrupted {
            DiffContent::Unavailable(
                "Diff exceeded its output/deadline bound or was cancelled".into(),
            )
        } else if !output.success {
            DiffContent::Unavailable(output.diagnostic())
        } else if output
            .stdout
            .split(|b| *b == b'\n')
            .any(|v| v == b"GIT binary patch")
        {
            DiffContent::Binary
        } else if output
            .stdout
            .split(|b| *b == b'\n')
            .any(|v| v.starts_with(b"index ") && v.ends_with(b" 160000"))
        {
            DiffContent::Unavailable("Submodule commit changed".into())
        } else {
            DiffContent::Text
        };
        let bytes = if content == DiffContent::Text {
            output.stdout
        } else {
            vec![]
        };
        Ok(DiffSnapshot {
            source: request.source,
            content,
            change: file.change,
            previous_path: file.previous_path,
            expected: self.state(&root, cancel)?,
            bytes,
        })
    }
}
