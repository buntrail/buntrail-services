use super::{LocalGitService, process};
use crate::files::io_error;
use buntrail_core::contracts::*;
use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::Path, sync::atomic::AtomicBool};

impl LocalGitService {
    pub(super) fn sidebar_context(
        &self,
        root: &Path,
        head: &GitHead,
        cancel: &AtomicBool,
    ) -> Result<GitSidebarContext, CoreError> {
        let mut upstream = None;
        if let GitHead::Branch { name, .. } = head {
            let raw = self.command(
                root,
                &process::args(&[
                    "for-each-ref",
                    "--format=%(refname)%00%(upstream:remotename)%00%(upstream:remoteref)",
                    "refs/heads",
                ]),
                cancel,
            )?;
            let reference = name.as_slice();
            for row in raw.split(|b| *b == b'\n').filter(|r| !r.is_empty()) {
                let fields = row.split(|b| *b == 0).collect::<Vec<_>>();
                if fields.len() != 3 {
                    return Err(io_error("Invalid upstream metadata"));
                }
                if fields[0] == reference && !fields[1].is_empty() && !fields[2].is_empty() {
                    upstream = Some(GitUpstream {
                        remote: fields[1].to_vec(),
                        reference: fields[2].to_vec(),
                    });
                }
            }
        }
        let remote = upstream
            .as_ref()
            .map_or(b"origin".as_slice(), |u| u.remote.as_slice());
        let mut args = process::args(&["config", "--null", "--get-all"]);
        args.push(OsStr::from_bytes(&[b"remote.", remote, b".url"].concat()).to_owned());
        let output = process::run(root, &args, cancel)?;
        if output.interrupted {
            return Err(io_error("Repository context inspection interrupted"));
        }
        let github_commit_base_url = if output.success {
            let urls = output.stdout.split(|b| *b == 0).collect::<Vec<_>>();
            if urls.len() == 2 && urls[1].is_empty() {
                github_url(urls[0])
            } else {
                None
            }
        } else {
            None
        };
        Ok(GitSidebarContext {
            upstream,
            github_commit_base_url,
        })
    }
}
fn github_url(raw: &[u8]) -> Option<String> {
    let url = std::str::from_utf8(raw).ok()?;
    let path = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))
        .or_else(|| url.strip_prefix("git@github.com:"))?;
    let path = path.strip_suffix(".git").unwrap_or(path);
    let parts = path.split('/').collect::<Vec<_>>();
    if parts.len() != 2
        || parts.iter().any(|p| {
            p.is_empty()
                || *p == "."
                || *p == ".."
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    {
        return None;
    }
    Some(format!("https://github.com/{path}/commit/"))
}
