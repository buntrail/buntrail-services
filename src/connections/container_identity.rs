//! Engine metadata is discovery evidence; only an exec probe verifies the effective UID.
use buntrail_core::contracts::*;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ContainerState {
    Running,
    Stopped,
    Paused,
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ContainerDescriptor {
    pub engine_endpoint: Vec<u8>,
    pub immutable_id: String,
    pub name: String,
    pub state: ContainerState,
    pub configured_user: String,
    pub requested_user: Option<String>,
    pub actual_uid: Option<u32>,
    pub architecture: Option<String>,
    pub start_generation: Option<Vec<u8>>,
}

fn invalid(message: &str) -> CoreError {
    CoreError::new(ErrorCode::InvalidArgument, message)
}
fn valid_start(start: Option<&[u8]>) -> bool {
    start.is_some_and(|value| {
        !value.is_empty() && value.len() <= 256 && !value.starts_with(b"0001-")
    })
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerBinding {
    pub host_security_binding: Vec<u8>,
    pub container: ContainerIdentity,
    pub uid: u32,
    pub start_generation: Option<Vec<u8>>,
}
impl ContainerBinding {
    pub fn new(
        descriptor: &ContainerDescriptor,
        host_security_binding: Vec<u8>,
        uid: u32,
    ) -> Result<Self, CoreError> {
        if descriptor.state != ContainerState::Running
            || !valid_start(descriptor.start_generation.as_deref())
        {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "A verified running container start is required before helper startup",
            ));
        }
        descriptor.target(&host_security_binding, uid)?;
        Ok(Self {
            host_security_binding,
            container: ContainerIdentity {
                engine_endpoint: descriptor.engine_endpoint.clone(),
                immutable_id: descriptor.immutable_id.as_bytes().to_vec(),
            },
            uid,
            start_generation: descriptor.start_generation.clone(),
        })
    }
    pub fn target_for_uid(&self, uid: u32) -> Result<TargetIdentity, CoreError> {
        if uid != self.uid
            || self.container.immutable_id.len() != 64
            || !self
                .container
                .immutable_id
                .iter()
                .all(u8::is_ascii_hexdigit)
            || self.container.engine_endpoint.is_empty()
            || self.container.engine_endpoint.len() > 65536
            || !valid_start(self.start_generation.as_deref())
        {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Container user or binding changed at helper startup",
            ));
        }
        let d = ContainerDescriptor {
            engine_endpoint: self.container.engine_endpoint.clone(),
            immutable_id: String::from_utf8(self.container.immutable_id.clone())
                .map_err(|_| invalid("Invalid container ID"))?,
            name: String::new(),
            state: ContainerState::Running,
            configured_user: String::new(),
            requested_user: None,
            actual_uid: Some(uid),
            architecture: None,
            start_generation: self.start_generation.clone(),
        };
        d.target(&self.host_security_binding, uid)
    }
    pub fn current_target(&self) -> Result<TargetIdentity, CoreError> {
        if !cfg!(target_os = "linux") {
            return Err(CoreError::new(
                ErrorCode::Unavailable,
                "Container helper requires supported Linux",
            ));
        }
        let root = std::fs::metadata("/").map_err(crate::files::io_error)?;
        if !root.is_dir() {
            return Err(invalid("Container filesystem root is unavailable"));
        }
        self.target_for_uid(unsafe { libc::geteuid() })
    }
}
impl ContainerDescriptor {
    pub fn decode(
        endpoint: Vec<u8>,
        bytes: &[u8],
        requested_user: Option<String>,
    ) -> Result<Self, CoreError> {
        if endpoint.is_empty() || endpoint.len() > 65536 || bytes.len() > 65536 {
            return Err(invalid("Container metadata exceeded its bound"));
        }
        let v: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| invalid("Malformed container metadata"))?;
        let id = v
            .get("Id")
            .or_else(|| v.get("ID"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid("Container ID is missing"))?;
        if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("A full immutable container ID is required"));
        }
        let name = v
            .get("Name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid("Container name is missing"))?;
        if name.len() > 4096 || name.chars().any(char::is_control) {
            return Err(invalid("Invalid container name"));
        }
        let state = match v.pointer("/State/Status").and_then(|v| v.as_str()) {
            Some("running")
                if v.pointer("/State/Running").and_then(|v| v.as_bool()) == Some(true) =>
            {
                ContainerState::Running
            }
            Some("created" | "configured" | "exited" | "stopped") => ContainerState::Stopped,
            Some("paused") => ContainerState::Paused,
            _ => ContainerState::Unsupported,
        };
        let configured_user = v
            .pointer("/Config/User")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        for user in [Some(configured_user.as_str()), requested_user.as_deref()]
            .into_iter()
            .flatten()
        {
            if user.len() > 4096 || user.chars().any(char::is_control) || user.starts_with('-') {
                return Err(invalid("Invalid container user"));
            }
        }
        let start_generation = v
            .pointer("/State/StartedAt")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && !s.starts_with("0001-"))
            .map(|s| s.as_bytes().to_vec());
        if start_generation.as_ref().is_some_and(|s| s.len() > 256) {
            return Err(invalid("Invalid container start generation"));
        }
        if state == ContainerState::Running && !valid_start(start_generation.as_deref()) {
            return Err(invalid(
                "Running container has no verified start generation; refresh and verify the original container before connecting",
            ));
        }
        let architecture = v
            .get("Architecture")
            .and_then(|s| s.as_str())
            .map(str::to_owned);
        if architecture
            .as_ref()
            .is_some_and(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(invalid("Invalid container architecture"));
        }
        Ok(Self {
            engine_endpoint: endpoint,
            immutable_id: id.to_owned(),
            name: name.trim_start_matches('/').into(),
            state,
            configured_user,
            requested_user,
            actual_uid: None,
            architecture,
            start_generation,
        })
    }
    pub fn revalidate(&self, current: &Self) -> Result<(), CoreError> {
        if self.engine_endpoint != current.engine_endpoint
            || self.immutable_id != current.immutable_id
            || self.requested_user != current.requested_user
            || self.configured_user != current.configured_user
            || self
                .actual_uid
                .zip(current.actual_uid)
                .is_some_and(|(before, now)| before != now)
        {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Container endpoint, immutable ID or selected user changed; select and verify the target again",
            ));
        }
        Ok(())
    }
    pub fn target(
        &self,
        host_security_binding: &[u8],
        uid: u32,
    ) -> Result<TargetIdentity, CoreError> {
        if host_security_binding.is_empty() || host_security_binding.len() > 65536 {
            return Err(invalid("Verified engine host binding is required"));
        }
        let mut namespace = Sha256::new();
        namespace.update(b"buntrail-container-filesystem-v1\0");
        for bytes in [
            self.engine_endpoint.as_slice(),
            self.immutable_id.as_bytes(),
        ] {
            namespace.update((bytes.len() as u64).to_be_bytes());
            namespace.update(bytes);
        }
        Ok(TargetIdentity {
            security_binding: host_security_binding.to_vec(),
            effective_user: uid.to_be_bytes().to_vec(),
            filesystem_namespace: namespace.finalize().to_vec(),
            container: Some(ContainerIdentity {
                engine_endpoint: self.engine_endpoint.clone(),
                immutable_id: self.immutable_id.as_bytes().to_vec(),
            }),
        })
    }
}
