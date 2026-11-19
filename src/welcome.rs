use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub fn welcome_folder(
    parent: &Path,
    name: Option<&str>,
    repository: Option<&str>,
) -> Result<PathBuf, String> {
    if !parent.is_absolute() {
        return Err("Select an absolute parent directory".into());
    }
    let child = match (name, repository) {
        (Some(name), None) => name,
        (None, Some(url)) => {
            if url.is_empty()
                || url.len() > 8192
                || url.starts_with('-')
                || url.chars().any(char::is_control)
            {
                return Err("Invalid Git repository URL".into());
            }
            let location = url
                .split(['?', '#'])
                .next()
                .unwrap_or("")
                .trim_end_matches('/');
            let location = if let Some((scheme, rest)) = location.split_once("://") {
                if !matches!(scheme, "http" | "https" | "ssh" | "git" | "file") {
                    return Err("Unsupported Git repository URL".into());
                }
                rest.split_once('/')
                    .map(|(_, path)| path)
                    .ok_or("Repository URL needs a path")?
            } else if location.starts_with('/') {
                location
            } else {
                let (host, path) = location
                    .split_once(':')
                    .ok_or("Enter an absolute path or Git repository URL")?;
                if host.is_empty() || host.contains('/') || path.starts_with(':') {
                    return Err("Invalid Git repository URL".into());
                }
                path
            };
            let leaf = location.rsplit(['/', ':']).next().unwrap_or("");
            leaf.strip_suffix(".git").unwrap_or(leaf)
        }
        _ => return Err("Provide one folder name or repository URL".into()),
    };
    if child.is_empty()
        || matches!(child, "." | "..")
        || child.contains('/')
        || child.chars().any(char::is_control)
    {
        return Err("Enter one folder name".into());
    }
    let path = parent.join(child);
    fs::create_dir(&path).map_err(|e| format!("Could not create destination: {e}"))?;
    if let Some(url) = repository {
        let status = Command::new("git")
            .args(["clone", "--", url, "."])
            .current_dir(&path)
            .env("GIT_ALLOW_PROTOCOL", "https:http:ssh:git:file")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !status.is_ok_and(|s| s.success()) {
            return Err(format!(
                "Clone did not complete. Inspect {} before retrying.",
                path.display()
            ));
        }
    }
    Ok(path)
}
