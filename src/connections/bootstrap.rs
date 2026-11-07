//! Verified package/cache primitives shared by the SSH installer and helper.
mod bundled;
use crate::files::{io_error, private_directory};
pub use bundled::BundledPackages;
use buntrail_core::contracts::*;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
pub const MAX_ARTIFACT_BYTES: usize = 128 * 1024 * 1024;
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Platform {
    LinuxX86Gnu,
    LinuxX86Musl,
    LinuxArmGnu,
    LinuxArmMusl,
}
#[derive(Clone)]
pub struct Artifact {
    bytes: Arc<[u8]>,
    sha256: String,
}
impl Artifact {
    /// `expected` comes from the application's trusted package manifest, never the remote peer.
    pub fn verified(bytes: Vec<u8>, expected: &str) -> Result<Self, CoreError> {
        if bytes.len() > MAX_ARTIFACT_BYTES || hex(&Sha256::digest(&bytes)) != expected {
            return Err(invalid(
                "Helper package checksum or size does not match the trusted manifest",
            ));
        }
        Ok(Self {
            bytes: bytes.into(),
            sha256: expected.into(),
        })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}
#[derive(Clone)]
pub struct HelperPackage {
    pub platform: Platform,
    pub helper: Artifact,
    pub search: Artifact,
}
impl HelperPackage {
    pub fn validate(&self) -> Result<(), CoreError> {
        let machine: u16 = match self.platform {
            Platform::LinuxX86Gnu | Platform::LinuxX86Musl => 62,
            _ => 183,
        };
        for artifact in [&self.helper, &self.search] {
            let b = artifact.bytes();
            if b.len() < 64 || &b[..6] != b"\x7fELF\x02\x01" || b[18..20] != machine.to_le_bytes() {
                return Err(invalid(
                    "Helper package is not a matching Linux ELF64 artifact",
                ));
            }
        }
        Ok(())
    }
    pub fn cache_key(&self) -> String {
        format!("{}-{}", self.helper.sha256, self.search.sha256)
    }
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn invalid(message: &str) -> CoreError {
    CoreError::new(ErrorCode::Unavailable, message)
}
fn verified_file(path: &Path, artifact: &Artifact) -> Result<(), CoreError> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(io_error)?;
    let m = f.metadata().map_err(io_error)?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o700
        || m.nlink() != 1
        || m.len() != artifact.bytes.len() as u64
    {
        return Err(invalid(
            "Existing helper package is unsafe; it was not replaced",
        ));
    }
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = f.read(&mut bytes).map_err(io_error)?;
        if n == 0 {
            break;
        }
        hash.update(&bytes[..n]);
    }
    if hex(&hash.finalize()) != artifact.sha256 {
        return Err(invalid(
            "Existing helper package is incompatible or corrupt; it was not replaced",
        ));
    }
    Ok(())
}
pub fn install_package(cache: &Path, package: &HelperPackage) -> Result<PathBuf, CoreError> {
    package.validate()?;
    private_directory(cache)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(cache.join("install.lock"))
        .map_err(io_error)?;
    let m = lock.metadata().map_err(io_error)?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
    {
        return Err(invalid("Unsafe helper install lock"));
    }
    lock.lock().map_err(io_error)?;
    let destination = cache.join(package.cache_key());
    if fs::symlink_metadata(&destination).is_ok() {
        private_directory(&destination)?;
        verified_file(&destination.join("buntrail-helper"), &package.helper)?;
        verified_file(&destination.join("rg"), &package.search)?;
        return Ok(destination);
    }
    let staging = tempfile::Builder::new()
        .prefix(".install-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(cache)
        .map_err(io_error)?;
    for (name, artifact) in [
        ("buntrail-helper", &package.helper),
        ("rg", &package.search),
    ] {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(staging.path().join(name))
            .map_err(io_error)?;
        f.write_all(artifact.bytes()).map_err(io_error)?;
        f.sync_all().map_err(io_error)?;
    }
    File::open(staging.path())
        .and_then(|f| f.sync_all())
        .map_err(io_error)?;
    fs::rename(staging.path(), &destination).map_err(io_error)?;
    File::open(cache)
        .and_then(|f| f.sync_all())
        .map_err(io_error)?;
    Ok(destination)
}
pub(crate) const INSTALL_ENTRY: &str = r#"set -eu
umask 077
[ "$(uname -s)" = Linux ] || { printf 'Supported Linux target required\n' >&2; exit 1; }
cache="$HOME/.buntrail-app"
if ! mkdir -m 700 "$cache" 2>/dev/null; then [ -d "$cache" ] && [ ! -L "$cache" ]; fi
[ "$(stat -c '%u:%a' "$cache")" = "$(id -u):700" ]
IFS= read -r hash
IFS= read -r length
case "$hash" in *[!0-9a-f]*|'') exit 1;; esac
[ "${#hash}" = 64 ]
case "$length" in *[!0-9]*|'') exit 1;; esac
[ "${#length}" -le 9 ] && [ "$length" -le 178956972 ]
temporary=$(mktemp -d "$cache/.upload.XXXXXXXXXX")
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
dd bs=65536 count="$length" iflag=count_bytes,fullblock | base64 -d > "$temporary/buntrail-helper"
actual=$(sha256sum "$temporary/buntrail-helper")
[ "${actual%% *}" = "$hash" ]
chmod 700 "$temporary/buntrail-helper"
"$temporary/buntrail-helper" ssh-install
"#;
pub(crate) const BRIDGE_ENTRY: &str = r#"set -eu
[ "$(uname -s)" = Linux ] || exit 1
IFS= read -r key
case "$key" in *[!0-9a-f-]*|'') exit 1;; esac
helper_hash=${key%-*}
search_hash=${key#*-}
[ "${#helper_hash}" = 64 ] && [ "${#search_hash}" = 64 ]
cache="$HOME/.buntrail-app"
[ -d "$cache" ] && [ ! -L "$cache" ]
[ "$(stat -c '%u:%a' "$cache")" = "$(id -u):700" ]
version="$cache/$key"
[ -d "$version" ] && [ ! -L "$version" ]
[ "$(stat -c '%u:%a' "$version")" = "$(id -u):700" ]
for name in buntrail-helper rg; do
 [ -f "$version/$name" ] && [ ! -L "$version/$name" ]
 [ "$(stat -c '%u:%a' "$version/$name")" = "$(id -u):700" ]
done
actual=$(sha256sum "$version/buntrail-helper")
[ "${actual%% *}" = "$helper_hash" ]
actual=$(sha256sum "$version/rg")
[ "${actual%% *}" = "$search_hash" ]
exec "$version/buntrail-helper" ssh-bridge
"#;
pub(crate) fn valid_peer_key(key: &str) -> bool {
    key.strip_prefix("SHA256:").is_some_and(|value| {
        value.len() == 43
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    })
}
pub fn ssh_identity(mut target: TargetIdentity, peer: &str) -> Result<TargetIdentity, CoreError> {
    if !valid_peer_key(peer) {
        return Err(invalid("Invalid verified SSH peer binding"));
    }
    let mut hash = Sha256::new();
    hash.update(b"buntrail-ssh-target-v1\0");
    for bytes in [peer.as_bytes(), target.security_binding.as_slice()] {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    target.security_binding = hash.finalize().to_vec();
    Ok(target)
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct DescriptorWire {
    pub target: TargetIdentity,
    pub platform: Platform,
    pub helper_path: String,
    pub helper_sha256: String,
    pub search_sha256: String,
    pub major: u16,
    pub minor: u16,
}
pub struct HelperDescriptor {
    pub target: TargetIdentity,
    pub platform: Platform,
    pub path: TargetPath,
    pub helper_sha256: String,
    pub search_sha256: String,
    pub peer_key: String,
}
pub fn verify_descriptor(
    wire: DescriptorWire,
    target: &TargetIdentity,
    package: &HelperPackage,
    peer: &str,
) -> Result<HelperDescriptor, CoreError> {
    use base64::Engine;
    if &wire.target != target {
        return Err(CoreError::new(
            ErrorCode::TargetChanged,
            "Verified SSH target changed during bootstrap",
        ));
    }
    if wire.major != 1
        || wire.minor != 0
        || wire.platform != package.platform
        || wire.helper_sha256 != package.helper.sha256
        || wire.search_sha256 != package.search.sha256
        || !valid_peer_key(peer)
    {
        return Err(invalid(
            "Remote helper metadata does not match the trusted package/protocol",
        ));
    }
    let path = base64::engine::general_purpose::STANDARD
        .decode(&wire.helper_path)
        .map_err(io_error)?;
    if path.len() > 65536 {
        return Err(invalid("Remote helper path exceeded its bound"));
    }
    Ok(HelperDescriptor {
        target: wire.target,
        platform: wire.platform,
        path: TargetPath::posix(path)?,
        helper_sha256: wire.helper_sha256,
        search_sha256: wire.search_sha256,
        peer_key: peer.into(),
    })
}
impl Platform {
    pub fn current() -> Result<Self, CoreError> {
        if !cfg!(target_os = "linux") {
            return Err(invalid(
                "SSH helper installation requires a supported Linux target",
            ));
        }
        match (std::env::consts::ARCH, cfg!(target_env = "musl")) {
            ("x86_64", false) => Ok(Self::LinuxX86Gnu),
            ("x86_64", true) => Ok(Self::LinuxX86Musl),
            ("aarch64", false) => Ok(Self::LinuxArmGnu),
            ("aarch64", true) => Ok(Self::LinuxArmMusl),
            _ => Err(invalid("Unsupported Linux helper architecture")),
        }
    }
    pub fn from_probe(probe: &super::ssh::Probe) -> Result<Self, CoreError> {
        match (
            probe.os.as_str(),
            probe.architecture.as_str(),
            probe.libc.as_str(),
        ) {
            ("linux", "x86_64", "gnu") => Ok(Self::LinuxX86Gnu),
            ("linux", "x86_64", "musl") => Ok(Self::LinuxX86Musl),
            ("linux", "aarch64", "gnu") => Ok(Self::LinuxArmGnu),
            ("linux", "aarch64", "musl") => Ok(Self::LinuxArmMusl),
            _ => Err(invalid(
                "Choose a supported Linux x86_64/arm64 glibc/musl SSH target",
            )),
        }
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BootstrapInput {
    pub platform: Platform,
    pub helper_sha256: String,
    pub search_sha256: String,
    pub search_base64: String,
    pub peer_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<super::container_identity::ContainerBinding>,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BridgeInput {
    pub peer_key: String,
    pub expected_target: TargetIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<super::container_identity::ContainerBinding>,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct BridgePrelude {
    pub target: TargetIdentity,
    pub ssh_auth_sock: Option<String>,
}
impl BridgePrelude {
    pub fn current(
        target: TargetIdentity,
        socket: Option<&std::ffi::OsStr>,
    ) -> Result<Self, CoreError> {
        use base64::Engine;
        use std::os::unix::ffi::OsStrExt;
        let ssh_auth_sock = socket
            .filter(|s| !s.is_empty())
            .map(|s| {
                if s.len() > 4096 {
                    return Err(invalid("Authentication socket path exceeded its bound"));
                }
                TargetPath::posix(s.as_bytes().to_vec())?;
                Ok(base64::engine::general_purpose::STANDARD.encode(s.as_bytes()))
            })
            .transpose()?;
        Ok(Self {
            target,
            ssh_auth_sock,
        })
    }
    pub fn authentication(
        self,
        expected: &TargetIdentity,
    ) -> Result<Option<TargetPath>, CoreError> {
        use base64::Engine;
        if &self.target != expected {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "SSH bridge target changed",
            ));
        }
        self.ssh_auth_sock
            .map(|s| {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(s)
                    .map_err(io_error)?;
                if bytes.len() > 4096 {
                    return Err(invalid("Authentication socket path exceeded its bound"));
                }
                TargetPath::posix(bytes)
            })
            .transpose()
    }
}

/// Bootstrap readiness is not environment readiness; protocol/runtime/capabilities still need negotiation.
pub struct HelperBootstrapper {
    connector: BootstrapConnector,
    package: HelperPackage,
}
enum BootstrapConnector {
    Ssh(super::ssh::SshConnector),
    Container(Box<super::container_transport::ContainerConnector>),
}
impl BootstrapConnector {
    fn probe(&self) -> Result<super::ssh::Probe, CoreError> {
        match self {
            Self::Ssh(c) => c.probe(),
            Self::Container(c) => c.probe(),
        }
    }
    fn run(
        &self,
        entry: super::ssh::Entry,
        input: Vec<u8>,
        peer: Option<&str>,
    ) -> Result<(Vec<u8>, String), CoreError> {
        match self {
            Self::Ssh(c) => c.run(entry, input, peer),
            Self::Container(c) => c.run(entry, input),
        }
    }
    fn start(
        &self,
        entry: super::ssh::Entry,
        peer: Option<&str>,
    ) -> Result<super::ssh::SshChannel, CoreError> {
        match self {
            Self::Ssh(c) => c.start(entry, peer),
            Self::Container(c) => c.start(entry),
        }
    }
    fn binding(&self) -> Option<super::container_identity::ContainerBinding> {
        match self {
            Self::Ssh(_) => None,
            Self::Container(c) => Some(c.binding.clone()),
        }
    }
}
pub struct SshBridge {
    pub channel: super::ssh::SshChannel,
    pub authentication: Option<TargetPath>,
}
impl HelperBootstrapper {
    pub fn new(
        connector: super::ssh::SshConnector,
        package: HelperPackage,
    ) -> Result<Self, CoreError> {
        package.validate()?;
        Ok(Self {
            connector: BootstrapConnector::Ssh(connector),
            package,
        })
    }
    pub fn container(
        connector: super::container_transport::ContainerConnector,
        package: HelperPackage,
    ) -> Result<Self, CoreError> {
        package.validate()?;
        Ok(Self {
            connector: BootstrapConnector::Container(Box::new(connector)),
            package,
        })
    }
    pub fn ensure_available(
        &self,
        target: TargetIdentity,
    ) -> async_types::ServiceFuture<'_, Result<HelperDescriptor, CoreError>> {
        Box::pin(async move { self.ensure_on_worker(target) })
    }
    fn ensure_on_worker(&self, target: TargetIdentity) -> Result<HelperDescriptor, CoreError> {
        use base64::{Engine, engine::general_purpose::STANDARD as B64};
        let observed = self.connector.probe()?;
        if Platform::from_probe(&observed)? != self.package.platform {
            return Err(invalid(
                "No matching trusted helper package for this target",
            ));
        }
        if observed.identity.as_ref() != Some(&target) {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Verified SSH target changed",
            ));
        }
        let helper = B64.encode(self.package.helper.bytes());
        let mut input =
            format!("{}\n{}\n", self.package.helper.sha256(), helper.len()).into_bytes();
        input.extend_from_slice(helper.as_bytes());
        input.extend_from_slice(
            &serde_json::to_vec(&BootstrapInput {
                platform: self.package.platform.clone(),
                helper_sha256: self.package.helper.sha256().into(),
                search_sha256: self.package.search.sha256().into(),
                search_base64: B64.encode(self.package.search.bytes()),
                peer_key: observed.peer_key.clone(),
                container: self.connector.binding(),
            })
            .map_err(io_error)?,
        );
        let (bytes, _) = self.connector.run(
            super::ssh::Entry::Bootstrap,
            input,
            Some(&observed.peer_key),
        )?;
        let wire = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("Malformed SSH helper descriptor"))?;
        verify_descriptor(wire, &target, &self.package, &observed.peer_key)
    }
    pub fn bridge(&self, descriptor: &HelperDescriptor) -> Result<SshBridge, CoreError> {
        if descriptor.platform != self.package.platform
            || descriptor.helper_sha256 != self.package.helper.sha256
            || descriptor.search_sha256 != self.package.search.sha256
        {
            return Err(invalid("Helper descriptor belongs to another package"));
        }
        let mut channel = self
            .connector
            .start(super::ssh::Entry::Bridge, Some(&descriptor.peer_key))?;
        let result = (|| {
            channel
                .stream
                .set_read_timeout(Some(std::time::Duration::from_secs(120)))
                .map_err(io_error)?;
            channel
                .stream
                .set_write_timeout(Some(std::time::Duration::from_secs(120)))
                .map_err(io_error)?;
            writeln!(channel.stream, "{}", self.package.cache_key()).map_err(io_error)?;
            let input = serde_json::to_vec(&BridgeInput {
                peer_key: descriptor.peer_key.clone(),
                expected_target: descriptor.target.clone(),
                container: self.connector.binding(),
            })
            .map_err(io_error)?;
            channel
                .stream
                .write_all(&input)
                .and_then(|_| channel.stream.write_all(b"\n"))
                .map_err(io_error)?;
            let prelude: BridgePrelude =
                serde_json::from_slice(&read_line(&mut channel.stream)?)
                    .map_err(|_| invalid("Malformed SSH bridge startup response"))?;
            let authentication = prelude.authentication(&descriptor.target)?;
            channel.stream.set_read_timeout(None).map_err(io_error)?;
            channel.stream.set_write_timeout(None).map_err(io_error)?;
            Ok(authentication)
        })();
        let authentication = match result {
            Ok(value) => value,
            Err(error) => {
                channel.request_stop();
                let _ = channel.finish();
                return Err(error);
            }
        };
        channel.complete_startup();
        Ok(SshBridge {
            channel,
            authentication,
        })
    }
}
/// Read exactly the startup line, never buffering away the first protocol bytes.
pub fn read_line(reader: &mut impl Read) -> Result<Vec<u8>, CoreError> {
    let mut bytes = Vec::new();
    let mut byte = [0];
    while bytes.len() < 65536 {
        reader.read_exact(&mut byte).map_err(io_error)?;
        if byte[0] == b'\n' {
            return Ok(bytes);
        }
        bytes.push(byte[0]);
    }
    Err(invalid("SSH startup line exceeded its bound"))
}
/// Runs only in the verified uploaded helper, on the target; no project path is accepted.
pub fn install_uploaded(input: BootstrapInput) -> Result<DescriptorWire, CoreError> {
    use base64::{Engine, engine::general_purpose::STANDARD as B64};
    if input.platform != Platform::current()? {
        return Err(invalid(
            "Uploaded helper does not match the target platform",
        ));
    }
    let executable = std::env::current_exe().map_err(io_error)?;
    let mut helper = Vec::new();
    File::open(executable)
        .map_err(io_error)?
        .take((MAX_ARTIFACT_BYTES + 1) as u64)
        .read_to_end(&mut helper)
        .map_err(io_error)?;
    let package = HelperPackage {
        platform: input.platform.clone(),
        helper: Artifact::verified(helper, &input.helper_sha256)?,
        search: Artifact::verified(
            B64.decode(input.search_base64).map_err(io_error)?,
            &input.search_sha256,
        )?,
    };
    let home =
        std::env::var_os("HOME").ok_or_else(|| invalid("Target home directory unavailable"))?;
    let cache = PathBuf::from(home).join(".buntrail-app");
    if !cache.is_absolute() {
        return Err(invalid("Target home directory must be absolute"));
    }
    let path = install_package(&cache, &package)?.join("buntrail-helper");
    use std::os::unix::ffi::OsStrExt;
    Ok(DescriptorWire {
        target: if let Some(binding) = input.container {
            binding.current_target()?
        } else {
            ssh_identity(super::local::identity()?, &input.peer_key)?
        },
        platform: input.platform,
        helper_path: B64.encode(path.as_os_str().as_bytes()),
        helper_sha256: input.helper_sha256,
        search_sha256: input.search_sha256,
        major: 1,
        minor: 0,
    })
}
