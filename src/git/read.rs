use super::*;
use buntrail_core::contracts::*;
use std::sync::atomic::AtomicBool;
impl LocalGitService {
    pub fn read_sync(
        &self,
        worktree: WorktreeIdentity,
        query: GitRead,
        cancel: &AtomicBool,
    ) -> Result<GitReadOutput, CoreError> {
        let root = self.validate(&worktree, cancel)?;
        let args: &[&str] = match query {
            GitRead::Upstream => &[
                "for-each-ref",
                "--format=%(refname)%00%(upstream:remotename)%00%(upstream:remoteref)",
                "refs/heads",
            ],
            GitRead::StatusShort => &["status", "--short", "--branch"],
            GitRead::StatusPorcelain => {
                &["status", "--porcelain=v1", "-z", "--untracked-files=all"]
            }
            GitRead::Head => &["rev-parse", "--abbrev-ref", "HEAD"],
            GitRead::HeadSymbolic => &["symbolic-ref", "--quiet", "--short", "HEAD"],
            GitRead::Inside => &["rev-parse", "--is-inside-work-tree"],
            GitRead::Refs => &[
                "for-each-ref",
                "--format=%(refname)%00%(HEAD)%00%(symref)",
                "refs/heads",
                "refs/remotes",
                "refs/tags",
            ],
            GitRead::Stashes => &["stash", "list", "--format=%gd: %s"],
            GitRead::Remotes => &["remote", "-v"],
            GitRead::Diff => &["diff", "--no-ext-diff", "--no-textconv", "--"],
            GitRead::StagedDiff => &["diff", "--cached", "--no-ext-diff", "--no-textconv", "--"],
            GitRead::Log => &["log", "-30", "--oneline", "--decorate"],
            GitRead::Graph => &["log", "--graph", "--oneline", "--decorate", "--all", "-100"],
        };
        let output = process::run(&root, &process::args(args), cancel)?;
        Ok(GitReadOutput {
            stdout: output.stdout,
            stderr: output.stderr,
            success: output.success,
        })
    }
}
