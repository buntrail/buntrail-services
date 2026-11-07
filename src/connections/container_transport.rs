//! Fixed engine argv transfer over the reviewed non-PTY SSH/process owner.
use super::ssh::{Entry, PipePurpose, SshChannel, SshConnector};
use super::{
    container_engine::ContainerEngineClient,
    container_identity::{ContainerBinding, ContainerDescriptor},
    ssh::Probe,
};
use crate::files::io_error;
use buntrail_core::contracts::*;
use std::{
    io::{Read, Write},
    process::Command,
    sync::{Arc, atomic::AtomicBool},
};

pub(crate) const ENGINE_ENTRY: &str = r#"set -eu
IFS= read -r engine
case "$engine" in docker|podman) ;; *) exit 1;; esac
IFS= read -r pinned
case "$pinned" in 1) unset DOCKER_CONTEXT DOCKER_HOST DOCKER_TLS DOCKER_TLS_VERIFY DOCKER_CERT_PATH CONTAINER_CONNECTION CONTAINER_HOST CONTAINER_SSHKEY;; 0) ;; *) exit 1;; esac
IFS= read -r count
case "$count" in ''|*[!0-9]*) exit 1;; esac
[ "$count" -le 128 ]
set --
while [ "$count" -gt 0 ]; do
 IFS= read -r encoded
 [ "${#encoded}" -le 87384 ]
 decoded=$(printf '%s' "$encoded" | base64 -d && printf '.') || exit 1
 set -- "$@" "${decoded%.}"
 count=$((count-1))
done
exec "$engine" "$@"
"#;
pub(crate) const ENVIRONMENT_ENTRY: &str = r#"set -eu
for value in "${DOCKER_CONTEXT-}" "${DOCKER_HOST-}" "${DOCKER_TLS-}" "${DOCKER_TLS_VERIFY-}" "${DOCKER_CERT_PATH-}" "${DOCKER_CONFIG-}" "${CONTAINER_CONNECTION-}" "${CONTAINER_HOST-}" "${CONTAINER_SSHKEY-}" "${HOME-}"; do
 printf '%s' "$value" | base64 | tr -d '\n'
 printf '\n'
done
"#;
pub(crate) const HOME_ENTRY: &str = r#"set -eu
LC_ALL=C
export LC_ALL
uid=$(id -u)
case "$uid" in ''|*[!0-9]*) exit 1;; esac
[ "${#uid}" -le 20 ]
command -v getent >/dev/null 2>&1 || exit 1
entry=$({ getent passwd "$uid" 2>/dev/null && printf 'BUNTRAIL_HOME_OK\n'; } | head -c 65537)
[ -n "$entry" ] && [ "${#entry}" -le 65536 ]
case "$entry" in *'
BUNTRAIL_HOME_OK') entry=${entry%'
BUNTRAIL_HOME_OK'};; *) exit 1;; esac
case "$entry" in *'
'*) exit 1;; esac
IFS=: read -r account password found_uid group gecos home shell <<EOF
$entry
EOF
[ -n "$account" ] && [ "$found_uid" = "$uid" ]
case "$shell" in *:*) exit 1;; esac
case "$home" in /*) ;; *) exit 1;; esac
[ "${#home}" -le 4096 ]
printf '%s' "$home" | base64 | tr -d '\n'
printf '\n'
"#;
const ROUTING: [&str; 9] = [
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "DOCKER_TLS",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
    "DOCKER_CONFIG",
    "CONTAINER_CONNECTION",
    "CONTAINER_HOST",
    "CONTAINER_SSHKEY",
];
const CONTAINER_PROBE: &str = r#"set -eu
uname -s
uname -m
if getconf GNU_LIBC_VERSION >/dev/null 2>&1; then printf 'gnu\n'; elif ldd --version 2>&1 | grep -q musl; then printf 'musl\n'; else printf 'unknown\n'; fi
id -u
stat -c '%d %i' /
[ -n "${HOME-}" ] && [ "${HOME#/}" != "$HOME" ] && [ -d "$HOME" ] && [ ! -L "$HOME" ]
[ "$(stat -c '%u' "$HOME")" = "$(id -u)" ] && [ -w "$HOME" ] && [ -x "$HOME" ]
"#;
#[derive(Clone)]
pub struct ContainerConnector {
    pub client: ContainerEngineClient,
    pub selected: ContainerDescriptor,
    pub binding: ContainerBinding,
}

#[cfg(all(test, unix))]
mod tests {
    use super::{ENGINE_ENTRY, ENVIRONMENT_ENTRY, HOME_ENTRY};
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::{
        io::Write,
        os::unix::fs::PermissionsExt,
        process::{Command, Output, Stdio},
    };

    fn dispatch(directory: &std::path::Path, input: &[u8]) -> Output {
        let mut child = Command::new("/bin/sh")
            .args(["-c", ENGINE_ENTRY])
            .current_dir(directory)
            .env("PATH", format!("{}:/usr/bin:/bin", directory.display()))
            .env("DOCKER_HOST", "ambient endpoint")
            .env("CONTAINER_HOST", "ambient podman")
            .env("DOCKER_CONFIG", "/ordinary credential config")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }

    fn fixture() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let engine = directory.path().join("docker");
        std::fs::write(&engine, b"#!/bin/sh\nprintf '%s\\0' \"${DOCKER_HOST-unset}\" \"${CONTAINER_HOST-unset}\" \"${DOCKER_CONFIG-unset}\" \"$@\"\ncat\n").unwrap();
        std::fs::set_permissions(engine, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    #[test]
    fn fixed_dispatch_preserves_hostile_argv_and_stdin_without_shell_evaluation() {
        let directory = fixture();
        let arguments = [
            "",
            "quoted ' \" ",
            "line\n\n",
            "$(touch SHOULD_NOT_EXIST); `touch ALSO_NOT`",
            "用户",
            "--user=1000:1000",
        ];
        let mut input = format!("docker\n1\n{}\n", arguments.len()).into_bytes();
        for argument in arguments {
            input.extend_from_slice(STANDARD.encode(argument).as_bytes());
            input.push(b'\n');
        }
        input.extend_from_slice(b"inner-entry\nraw\0bytes");
        let output = dispatch(directory.path(), &input);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut expected = b"unset\0unset\0/ordinary credential config\0".to_vec();
        for argument in arguments {
            expected.extend_from_slice(argument.as_bytes());
            expected.push(0);
        }
        expected.extend_from_slice(b"inner-entry\nraw\0bytes");
        assert_eq!(output.stdout, expected);
        assert!(!directory.path().join("SHOULD_NOT_EXIST").exists());
        assert!(!directory.path().join("ALSO_NOT").exists());
    }

    #[test]
    fn fixed_dispatch_refuses_malformed_or_oversized_framing_before_engine_exec() {
        let directory = fixture();
        let oversized = format!("docker\n1\n1\n{}\n", "A".repeat(87385));
        for input in [
            "evil\n1\n0\n",
            "docker\nx\n0\n",
            "docker\n1\n-1\n",
            "docker\n1\n129\n",
            "docker\n1\n1\n!\n",
            "docker\n1\n1\n",
            &oversized,
        ] {
            let output = dispatch(directory.path(), input.as_bytes());
            assert!(!output.status.success());
            assert!(
                output.stdout.is_empty(),
                "Engine must not execute for malformed input"
            );
        }
    }

    #[test]
    fn fixed_environment_reads_selected_host_home_without_modifying_it() {
        let result = Command::new("/bin/sh")
            .args(["-c", ENVIRONMENT_ENTRY])
            .env("HOME", "/selected/host/user home")
            .output()
            .unwrap();
        assert!(result.status.success());
        let lines: Vec<_> = result
            .stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(
            STANDARD.decode(lines.last().unwrap()).unwrap(),
            b"/selected/host/user home"
        );
        assert_eq!(
            result.stdout.iter().filter(|byte| **byte == b'\n').count(),
            10
        );
    }

    #[test]
    fn fixed_home_fallback_checks_uid_and_refuses_bad_lookup_without_leaking_passwd() {
        let directory = tempfile::tempdir().unwrap();
        for (name, source) in [
            (
                "id",
                "#!/bin/sh\n[ \"$1\" = -u ] || exit 2\nprintf '1000\\n'\n",
            ),
            (
                "getent",
                "#!/bin/sh\n[ \"$1\" = passwd ] && [ \"$2\" = 1000 ] || exit 2\n/bin/cat \"$NSS_FIXTURE\"\nexit \"${NSS_STATUS-0}\"\n",
            ),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, source).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        for name in ["head", "base64", "tr"] {
            std::os::unix::fs::symlink(format!("/usr/bin/{name}"), directory.path().join(name))
                .unwrap();
        }
        let data = directory.path().join("row");
        for (row, valid) in [
            (
                "user:SECRET_MUST_NOT_LEAK:1000:1000:User:/remote/user home:/bin/sh\n".to_owned(),
                true,
            ),
            (
                "user:SECRET_MUST_NOT_LEAK:1001:1000:User:/remote/home:/bin/sh\n".to_owned(),
                false,
            ),
            ("user:x:1000:1000:User:relative:/bin/sh\n".to_owned(), false),
            (
                "user:x:1000:1000:User:/remote/home:/bin/sh\nother:x:1000:1000::/other:/bin/sh\n"
                    .to_owned(),
                false,
            ),
            (
                format!("user:x:1000:1000:User:/{}:/bin/sh\n", "a".repeat(4096)),
                false,
            ),
        ] {
            std::fs::write(&data, row).unwrap();
            let result = Command::new("/bin/sh")
                .args(["-c", HOME_ENTRY])
                .env("PATH", directory.path())
                .env("NSS_FIXTURE", &data)
                .output()
                .unwrap();
            assert_eq!(result.status.success(), valid);
            assert!(!String::from_utf8_lossy(&result.stdout).contains("SECRET_MUST_NOT_LEAK"));
            assert!(!String::from_utf8_lossy(&result.stderr).contains("SECRET_MUST_NOT_LEAK"));
            if valid {
                assert_eq!(
                    STANDARD.decode(result.stdout.trim_ascii()).unwrap(),
                    b"/remote/user home"
                );
            } else {
                assert!(result.stdout.is_empty());
            }
        }
        std::fs::write(&data, "user:x:1000:1000:User:/remote/home:/bin/sh\n").unwrap();
        let failed_lookup = Command::new("/bin/sh")
            .args(["-c", HOME_ENTRY])
            .env("PATH", directory.path())
            .env("NSS_FIXTURE", &data)
            .env("NSS_STATUS", "1")
            .output()
            .unwrap();
        assert!(
            !failed_lookup.status.success(),
            "failed lookup must not become valid through head"
        );
        assert!(failed_lookup.stdout.is_empty());
        std::fs::remove_file(directory.path().join("getent")).unwrap();
        assert!(
            !Command::new("/bin/sh")
                .args(["-c", HOME_ENTRY])
                .env("PATH", directory.path())
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}
impl ContainerConnector {
    pub fn new(
        client: ContainerEngineClient,
        mut selected: ContainerDescriptor,
    ) -> Result<Self, CoreError> {
        let (probe, uid) = Self::probe_selected(&client, &selected)?;
        let binding = ContainerBinding::new(&selected, client.host.binding().to_vec(), uid)?;
        selected.actual_uid = Some(uid);
        selected.architecture = Some(probe.architecture);
        Ok(Self {
            client,
            selected,
            binding,
        })
    }
    fn run_channel(mut channel: SshChannel, input: &[u8]) -> Result<(Vec<u8>, String), CoreError> {
        let result = (|| {
            channel.stream.write_all(input).map_err(io_error)?;
            channel.finish_input()?;
            let mut bytes = vec![];
            (&mut channel.stream)
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            if bytes.len() > 65536 {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "Container helper response exceeded its bound",
                ));
            }
            channel.finish()?;
            Ok((bytes, channel.peer_key.clone()))
        })();
        if result.is_err() {
            channel.request_stop();
            let _ = channel.finish();
        }
        result
    }
    fn peer(client: &ContainerEngineClient) -> String {
        use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
        use sha2::{Digest, Sha256};
        format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(client.host.binding()))
        )
    }
    fn probe_selected(
        client: &ContainerEngineClient,
        selected: &ContainerDescriptor,
    ) -> Result<(Probe, u32), CoreError> {
        let response = client
            .exec(selected, CONTAINER_PROBE, PipePurpose::Request)
            .and_then(|channel| Self::run_channel(channel, &[]));
        let (bytes, _) = response.map_err(|error| {
            if error.code==ErrorCode::TargetChanged {return error;}
            CoreError::new(error.code, "Container requires a running supported Linux target, shell/probe tools and a writable user-owned executable home/cache; distroless/read-only targets are unsupported")
        })?;
        let text = std::str::from_utf8(&bytes).map_err(io_error)?;
        let mut lines = text.lines();
        if lines.next() != Some("Linux") {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "Container target must be Linux",
            ));
        }
        let architecture = lines
            .next()
            .ok_or_else(|| io_error("Missing container architecture"))?
            .into();
        let libc = lines
            .next()
            .ok_or_else(|| io_error("Missing container libc"))?
            .into();
        let uid = lines
            .next()
            .unwrap_or("")
            .parse::<u32>()
            .map_err(io_error)?;
        let root = lines
            .next()
            .unwrap_or("")
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(io_error)?;
        if root.len() != 2 || lines.next().is_some() {
            return Err(io_error("Invalid container root properties"));
        }
        Ok((
            Probe {
                os: "linux".into(),
                peer_key: Self::peer(client),
                architecture,
                libc,
                identity: Some(selected.target(client.host.binding(), uid)?),
            },
            uid,
        ))
    }
    pub fn probe(&self) -> Result<Probe, CoreError> {
        let (probe, uid) = Self::probe_selected(&self.client, &self.selected)?;
        if self.binding.target_for_uid(uid)? != probe.identity.clone().unwrap() {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Container identity changed",
            ));
        }
        Ok(probe)
    }
    pub(crate) fn start(&self, entry: Entry) -> Result<SshChannel, CoreError> {
        let (script, purpose) = match entry {
            Entry::Bootstrap => (super::bootstrap::INSTALL_ENTRY, PipePurpose::Bootstrap),
            Entry::Bridge => (super::bootstrap::BRIDGE_ENTRY, PipePurpose::Bridge),
            _ => return Err(io_error("Invalid container helper entry")),
        };
        let mut channel = self.client.exec(&self.selected, script, purpose)?;
        channel.peer_key = Self::peer(&self.client);
        Ok(channel)
    }
    pub(crate) fn run(&self, entry: Entry, input: Vec<u8>) -> Result<(Vec<u8>, String), CoreError> {
        Self::run_channel(self.start(entry)?, &input)
    }
}

#[derive(Clone)]
pub enum EngineHost {
    Local {
        binding: Vec<u8>,
        cancel: Arc<AtomicBool>,
    },
    Ssh {
        binding: Vec<u8>,
        peer: String,
        connector: SshConnector,
    },
}
impl EngineHost {
    pub fn local(cancel: Arc<AtomicBool>) -> Result<Self, CoreError> {
        Ok(Self::Local {
            binding: super::local::identity()?.security_binding,
            cancel,
        })
    }
    pub fn ssh(connector: SshConnector) -> Result<Self, CoreError> {
        let probe = connector.probe()?;
        let binding = probe
            .identity
            .ok_or_else(|| {
                CoreError::new(
                    ErrorCode::Unavailable,
                    "Container engine SSH host must be supported Linux",
                )
            })?
            .security_binding;
        Ok(Self::Ssh {
            binding,
            peer: probe.peer_key,
            connector,
        })
    }
    pub fn binding(&self) -> &[u8] {
        match self {
            Self::Local { binding, .. } | Self::Ssh { binding, .. } => binding,
        }
    }
    pub(crate) fn check_cancelled(&self) -> Result<(), CoreError> {
        let cancelled = match self {
            Self::Local { cancel, .. } => cancel.load(std::sync::atomic::Ordering::SeqCst),
            Self::Ssh { connector, .. } => connector.is_cancelled(),
        };
        if cancelled {
            Err(CoreError::new(
                ErrorCode::Cancelled,
                "Container request cancelled before dispatch",
            ))
        } else {
            Ok(())
        }
    }
    pub(crate) fn environment(&self) -> Result<Vec<String>, CoreError> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        match self {
            Self::Local { .. } => ROUTING
                .iter()
                .copied()
                .chain(std::iter::once("HOME"))
                .map(|name| {
                    std::env::var(name)
                        .or_else(|e| match e {
                            std::env::VarError::NotPresent => Ok(String::new()),
                            _ => Err(e),
                        })
                        .map_err(io_error)
                })
                .collect(),
            Self::Ssh {
                connector, peer, ..
            } => {
                let (bytes, _) = connector.run(Entry::EngineEnvironment, vec![], Some(peer))?;
                let text = std::str::from_utf8(&bytes).map_err(io_error)?;
                let values = text
                    .lines()
                    .map(|line| {
                        String::from_utf8(STANDARD.decode(line).map_err(io_error)?)
                            .map_err(io_error)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if values.len() != ROUTING.len() + 1
                    || values
                        .iter()
                        .any(|v| v.len() > 4096 || v.chars().any(char::is_control))
                {
                    return Err(CoreError::new(
                        ErrorCode::Unavailable,
                        "Invalid engine routing environment",
                    ));
                }
                Ok(values)
            }
        }
    }
    pub(crate) fn home_directory(&self, supplied: &str) -> Result<String, CoreError> {
        let unavailable = || {
            CoreError::new(
                ErrorCode::Unavailable,
                "Cannot resolve selected engine host home for Docker TLS certificates; HOME or an existing account lookup is required when no Docker config/certificate directory is selected",
            )
        };
        let home = if !supplied.is_empty() {
            supplied.to_owned()
        } else {
            match self {
                Self::Local { .. } => std::env::home_dir()
                    .and_then(|path| path.to_str().map(str::to_owned))
                    .ok_or_else(unavailable)?,
                Self::Ssh {
                    connector, peer, ..
                } => {
                    use base64::{Engine, engine::general_purpose::STANDARD};
                    let (bytes, _) = connector
                        .run(Entry::EngineHome, vec![], Some(peer))
                        .map_err(|error| {
                            if error.code == ErrorCode::Cancelled {
                                error
                            } else {
                                unavailable()
                            }
                        })?;
                    if bytes.len() > 5465 {
                        return Err(unavailable());
                    }
                    let decoded = STANDARD
                        .decode(bytes.trim_ascii())
                        .map_err(|_| unavailable())?;
                    String::from_utf8(decoded).map_err(|_| unavailable())?
                }
            }
        };
        if !home.starts_with('/') || home.len() > 4096 || home.chars().any(char::is_control) {
            return Err(unavailable());
        }
        Ok(home)
    }
    pub(crate) fn start(
        &self,
        engine: &ContainerEngine,
        args: &[String],
        pinned: bool,
        purpose: PipePurpose,
    ) -> Result<SshChannel, CoreError> {
        self.check_cancelled()?;
        if args.len() > 128
            || args
                .iter()
                .any(|s| s.len() > 65536 || s.as_bytes().contains(&0))
        {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "Engine arguments exceeded their bound",
            ));
        }
        let name = match engine {
            ContainerEngine::Docker => "docker",
            ContainerEngine::Podman => "podman",
        };
        match self {
            Self::Local { cancel, .. } => {
                let mut command = Command::new(name);
                command.args(args);
                if pinned {
                    for name in ROUTING.iter().filter(|n| **n != "DOCKER_CONFIG") {
                        command.env_remove(name);
                    }
                }
                super::ssh::local_pipe(command, cancel.clone(), purpose)
            }
            Self::Ssh {
                peer, connector, ..
            } => {
                use base64::{Engine, engine::general_purpose::STANDARD};
                let mut channel = connector.start(Entry::Engine(purpose), Some(peer))?;
                let prefix = format!(
                    "{name}\n{}\n{}\n{}",
                    u8::from(pinned),
                    args.len(),
                    args.iter()
                        .map(|s| format!("{}\n", STANDARD.encode(s.as_bytes())))
                        .collect::<String>()
                );
                if prefix.len() > 1048576 {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "Engine argument envelope exceeded its bound",
                    ));
                }
                channel
                    .stream
                    .write_all(prefix.as_bytes())
                    .map_err(io_error)?;
                Ok(channel)
            }
        }
    }
    pub(crate) fn run(
        &self,
        engine: &ContainerEngine,
        args: &[String],
        pinned: bool,
    ) -> Result<Vec<u8>, CoreError> {
        let mut channel = self.start(engine, args, pinned, PipePurpose::Request)?;
        let result = (|| {
            channel.finish_input()?;
            let mut bytes = Vec::new();
            (&mut channel.stream)
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            if bytes.len() > 65536 {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "Engine response exceeded its bound; narrow the selection",
                ));
            }
            channel.finish()?;
            Ok(bytes)
        })();
        if result.is_err() {
            channel.request_stop();
            let _ = channel.finish();
        }
        result
    }
}
