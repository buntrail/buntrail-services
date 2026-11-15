use super::{LocalGitService, process, repository::oid};
use crate::files::io_error;
use buntrail_core::contracts::*;
use std::sync::atomic::AtomicBool;

impl LocalGitService {
    pub fn commit_summary_sync(
        &self,
        query: CommitQuery,
        cancel: &AtomicBool,
    ) -> Result<GitCommitSummary, CoreError> {
        if query.cursor.is_some() {
            return Err(io_error("Summary does not accept a file cursor"));
        }
        let id = oid(query.oid.as_bytes())?;
        let root = self.validate(&query.worktree, cancel)?;
        let raw = self.command(
            &root,
            &process::args(&["rev-list", "--parents", "--max-count=1", &id, "--"]),
            cancel,
        )?;
        let ids = raw
            .strip_suffix(b"\n")
            .ok_or_else(|| io_error("Incomplete commit metadata"))?
            .split(|b| *b == b' ')
            .map(oid)
            .collect::<Result<Vec<_>, _>>()?;
        if ids.first() != Some(&id) {
            return Err(io_error("Commit metadata does not match"));
        }
        let mut args = process::args(&[
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--numstat",
            "-r",
            "-z",
            "-M",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
        ]);
        if let Some(parent) = ids.get(1) {
            args.push(parent.into());
        }
        args.push(id.clone().into());
        args.push("--".into());
        let raw = self.command(&root, &args, cancel)?;
        parse_numstat(id, &raw)
    }
}
fn parse_numstat(oid: String, raw: &[u8]) -> Result<GitCommitSummary, CoreError> {
    let mut summary = GitCommitSummary {
        oid,
        changed_file_count: 0,
        insertion_count: 0,
        deletion_count: 0,
        binary_file_count: 0,
    };
    if raw.is_empty() {
        return Ok(summary);
    }
    if !raw.ends_with(&[0]) {
        return Err(io_error("Incomplete commit numstat"));
    }
    let mut records = raw[..raw.len() - 1].split(|b| *b == 0);
    while let Some(record) = records.next() {
        let fields = record.splitn(3, |b| *b == b'\t').collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(io_error("Invalid commit numstat"));
        }
        if fields[2].is_empty() {
            for _ in 0..2 {
                if records.next().is_none_or(|p| p.is_empty()) {
                    return Err(io_error("Incomplete numstat rename"));
                }
            }
        }
        summary.changed_file_count += 1;
        if fields[0] == b"-" && fields[1] == b"-" {
            summary.binary_file_count += 1;
        } else {
            let count = |bytes: &[u8]| -> Result<u64, CoreError> {
                if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
                    return Err(io_error("Invalid numstat count"));
                }
                std::str::from_utf8(bytes)
                    .map_err(io_error)?
                    .parse()
                    .map_err(io_error)
            };
            summary.insertion_count = summary
                .insertion_count
                .checked_add(count(fields[0])?)
                .ok_or_else(|| io_error("Numstat overflow"))?;
            summary.deletion_count = summary
                .deletion_count
                .checked_add(count(fields[1])?)
                .ok_or_else(|| io_error("Numstat overflow"))?;
        }
    }
    Ok(summary)
}
