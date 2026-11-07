//! Bounded discovery and explicit same-ID start. Names never grant lifecycle authority.
use super::{
    container_identity::{ContainerDescriptor, ContainerState},
    container_transport::EngineHost,
};
use buntrail_core::contracts::*;
use serde_json::{Value, json};

const NATIVE_INFO: &str = "{\"Store\":{{json .Store}},\"Rootless\":{{.Host.Security.Rootless}}}";
const INSPECT: &str = "{\"Id\":{{json .Id}},\"Name\":{{json .Name}},\"Image\":{{json .Image}},\"State\":{\"Status\":{{json .State.Status}},\"Running\":{{.State.Running}},\"StartedAt\":{{json .State.StartedAt}}},\"Config\":{\"User\":{{json .Config.User}}}}";
fn invalid(message: &str) -> CoreError {
    CoreError::new(ErrorCode::Unavailable, message)
}
// Exact-filter observation only. The caller preserves inspect failure unless absence is proven.
fn filtered_id_absent(bytes: &[u8], selected: &str) -> Result<bool, CoreError> {
    if bytes.len() > 65536 {
        return Err(invalid("Filtered container inventory exceeded its bound"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| invalid("Invalid filtered container inventory"))?;
    let mut ids = text.lines();
    match (ids.next(), ids.next()) {
        (None, None) => Ok(true),
        (Some(id), None)
            if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) && id == selected =>
        {
            Ok(false)
        }
        _ => Err(invalid(
            "Unexpected filtered container inventory; pinned absence is unconfirmed",
        )),
    }
}
fn parsed(bytes: &[u8]) -> Result<Value, CoreError> {
    if bytes.len() > 65536 {
        return Err(invalid("Engine metadata exceeded its bound"));
    }
    serde_json::from_slice(bytes).map_err(|_| invalid("Malformed engine metadata"))
}
fn text(v: &Value, key: &str) -> Result<String, CoreError> {
    let s = v
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Required engine metadata is missing"))?;
    if s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control) {
        return Err(invalid("Invalid engine metadata"));
    }
    Ok(s.to_owned())
}
fn url(s: &str) -> Result<(), CoreError> {
    if s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control) {
        return Err(invalid("Invalid engine endpoint"));
    }
    // URI userinfo passwords must not be copied into process argv or diagnostics.
    if s.split_once("://")
        .and_then(|(_, s)| s.split_once('@'))
        .is_some_and(|(u, _)| u.contains(':'))
    {
        return Err(invalid(
            "Engine URI credentials require a normal credential/key configuration; passwords in URI are unsupported",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedEngine {
    pub endpoint: Vec<u8>,
    pub arguments: Vec<String>,
}
impl PinnedEngine {
    pub fn podman_native(bytes: &[u8]) -> Result<Self, CoreError> {
        let v = parsed(bytes)?;
        let s = v
            .get("Store")
            .ok_or_else(|| invalid("Podman storage metadata missing"))?;
        let root = text(s, "graphRoot")?;
        let run = text(s, "runRoot")?;
        let driver = text(s, "graphDriverName")?;
        let volume = text(s, "volumePath")?;
        if !root.starts_with('/') || !run.starts_with('/') || !volume.starts_with('/') {
            return Err(invalid("Absolute Podman storage paths are required"));
        }
        let rootless = v
            .get("Rootless")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("Podman rootless identity missing"))?;
        let transient = s
            .get("transientStore")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("Podman storage mode missing"))?;
        let options = s
            .get("graphOptions")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("Podman effective storage options missing"))?;
        let mut arguments = vec![
            "--remote=false".into(),
            "--root".into(),
            root.clone(),
            "--runroot".into(),
            run.clone(),
            "--storage-driver".into(),
            driver.clone(),
        ];
        for (key, value) in options {
            // Derived/repeated diagnostics cannot faithfully reproduce the source options.
            let repeated = key.ends_with("imagestore") || key.ends_with("additionalImageStores");
            let value = value.as_str().filter(|_| !repeated).ok_or_else(|| {
                invalid("Podman custom storage options cannot be faithfully pinned; select a configured remote connection or a supported storage configuration")
            })?;
            if key.is_empty()
                || key.len() + value.len() > 4096
                || key.contains(['\n', '\0', '='])
                || value.contains(['\n', '\0'])
            {
                return Err(invalid("Invalid Podman storage option"));
            }
            arguments.extend(["--storage-opt".into(), format!("{key}={value}")]);
        }
        arguments.extend([
            "--volumepath".into(),
            volume.clone(),
            format!("--transient-store={transient}"),
        ]);
        let endpoint = serde_json::to_vec(&json!({
            "engine": "podman-native",
            "rootless": rootless,
            "root": root,
            "run": run,
            "driver": driver,
            "options": options,
            "volume": volume,
            "transient": transient,
        }))
        .map_err(|_| invalid("Engine identity encoding failed"))?;
        Ok(Self {
            endpoint,
            arguments,
        })
    }
}

#[derive(Clone)]
pub struct ContainerEngineClient {
    pub host: EngineHost,
    pub engine: ContainerEngine,
    pub context: Option<String>,
    pub user: Option<String>,
    pub pinned: PinnedEngine,
}
#[derive(Debug)]
pub enum StartOutcome {
    Started(ContainerDescriptor),
    StartedUnsupported {
        selected: ContainerDescriptor,
        error: CoreError,
    },
    Failed(CoreError),
    Uncertain {
        selected: ContainerDescriptor,
        error: CoreError,
    },
}

impl ContainerEngineClient {
    pub fn new(
        host: EngineHost,
        engine: ContainerEngine,
        context: Option<String>,
        user: Option<String>,
    ) -> Result<Self, CoreError> {
        for value in [context.as_deref(), user.as_deref()].into_iter().flatten() {
            if value.is_empty()
                || value.len() > 4096
                || value.starts_with('-')
                || value.chars().any(char::is_control)
            {
                return Err(invalid(
                    "Choose a bounded engine context and container user",
                ));
            }
        }
        let pinned = Self::discover(&host, &engine, context.as_deref())?;
        Ok(Self {
            host,
            engine,
            context,
            user,
            pinned,
        })
    }
    fn discover(
        host: &EngineHost,
        engine: &ContainerEngine,
        context: Option<&str>,
    ) -> Result<PinnedEngine, CoreError> {
        let env = host.environment()?;
        if env
            .iter()
            .any(|s| s.len() > 4096 || s.chars().any(char::is_control))
        {
            return Err(invalid("Engine routing environment exceeded its bound"));
        }
        match engine {
            ContainerEngine::Docker => {
                let selected = context.or((!env[0].is_empty()).then_some(env[0].as_str()));
                let mut arguments = vec![];
                let (endpoint, tls_path, material, skip) =
                    if selected.is_none() && !env[1].is_empty() {
                        let certificates = if !env[4].is_empty() {
                            env[4].clone()
                        } else if !env[5].is_empty() {
                            env[5].clone()
                        } else if !env[2].is_empty() || !env[3].is_empty() {
                            format!("{}/.docker", host.home_directory(&env[9])?)
                        } else {
                            String::new()
                        };
                        (
                            env[1].clone(),
                            certificates,
                            !env[2].is_empty() || !env[3].is_empty(),
                            env[3].is_empty(),
                        )
                    } else {
                        let current = if let Some(c) = selected {
                            c.to_owned()
                        } else {
                            String::from_utf8(host.run(
                                engine,
                                &["context".into(), "show".into()],
                                false,
                            )?)
                            .map_err(|_| invalid("Invalid Docker context"))?
                            .trim()
                            .to_owned()
                        };
                        let v = parsed(&host.run(
                            engine,
                            &[
                                "context".into(),
                                "inspect".into(),
                                current,
                                "--format".into(),
                                "{{json .}}".into(),
                            ],
                            false,
                        )?)?;
                        let e = v
                            .pointer("/Endpoints/docker")
                            .ok_or_else(|| invalid("Docker context endpoint missing"))?;
                        let has_material = v
                            .pointer("/TLSMaterial/docker")
                            .and_then(Value::as_array)
                            .is_some_and(|a| !a.is_empty());
                        let path = v
                            .pointer("/Storage/TLSPath")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        (
                            text(e, "Host")?,
                            if has_material {
                                format!("{path}/docker")
                            } else {
                                String::new()
                            },
                            has_material,
                            e.get("SkipTLSVerify")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                        )
                    };
                url(&endpoint)?;
                arguments.extend(["--host".into(), endpoint.clone()]);
                if material {
                    if !tls_path.starts_with('/') {
                        return Err(invalid(
                            "Docker context TLS material paths are unavailable; preserve the existing configuration",
                        ));
                    }
                    arguments.push(if skip { "--tls" } else { "--tlsverify" }.into());
                    for (flag, name) in [
                        ("--tlscacert", "ca.pem"),
                        ("--tlscert", "cert.pem"),
                        ("--tlskey", "key.pem"),
                    ] {
                        arguments.extend([flag.into(), format!("{tls_path}/{name}")]);
                    }
                } else {
                    arguments.push("--tls=false".into());
                }
                Ok(PinnedEngine {
                    endpoint: serde_json::to_vec(&json!({
                        "engine": "docker",
                        "host": endpoint,
                        "tls": material,
                        "skip": skip,
                        "tlsPath": tls_path,
                        "config": env[5],
                    }))
                    .map_err(|_| invalid("Engine identity encoding failed"))?,
                    arguments,
                })
            }
            ContainerEngine::Podman => {
                let selected = context.or((!env[6].is_empty()).then_some(env[6].as_str()));
                let list = parsed(&host.run(
                    engine,
                    &[
                        "system".into(),
                        "connection".into(),
                        "list".into(),
                        "--format".into(),
                        "json".into(),
                    ],
                    false,
                )?)?;
                let entries = list
                    .as_array()
                    .ok_or_else(|| invalid("Invalid Podman connection inventory"))?;
                let connection = selected
                    .map(|name| {
                        entries
                            .iter()
                            .find(|v| v.get("Name").and_then(Value::as_str) == Some(name))
                            .ok_or_else(|| invalid("Selected Podman connection is missing"))
                    })
                    .transpose()?;
                let remote = connection.is_some()
                    || !env[7].is_empty()
                    || cfg!(target_os = "macos") && matches!(host, EngineHost::Local { .. });
                if remote {
                    let connection = if selected.is_none() && !env[7].is_empty() {
                        None
                    } else {
                        connection.or_else(|| {
                            entries
                                .iter()
                                .find(|v| v.get("Default").and_then(Value::as_bool) == Some(true))
                        })
                    };
                    let endpoint = if selected.is_none() && !env[7].is_empty() {
                        env[7].clone()
                    } else {
                        connection
                            .map(|c| text(c, "URI"))
                            .transpose()?
                            .ok_or_else(|| {
                                invalid("A configured running Podman connection is required; no machine is started automatically")
                            })?
                    };
                    url(&endpoint)?;
                    let mut arguments =
                        vec!["--remote=true".into(), "--url".into(), endpoint.clone()];
                    for (key, flag) in [
                        ("Identity", "--identity"),
                        ("TLSCA", "--tls-ca"),
                        ("TLSCert", "--tls-cert"),
                        ("TLSKey", "--tls-key"),
                    ] {
                        let path = if key == "Identity" && connection.is_none() {
                            env[8].as_str()
                        } else {
                            connection
                                .and_then(|v| v.get(key))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                        };
                        if !path.is_empty() {
                            if !path.starts_with('/')
                                || path.len() > 4096
                                || path.chars().any(char::is_control)
                            {
                                return Err(invalid(
                                    "Podman credential paths must be bounded absolute paths",
                                ));
                            }
                            arguments.extend([flag.into(), path.into()]);
                        }
                    }
                    Ok(PinnedEngine {
                        endpoint: serde_json::to_vec(
                            &json!({"engine":"podman-remote","uri":endpoint,"arguments":arguments}),
                        )
                        .unwrap(),
                        arguments,
                    })
                } else {
                    let pinned = PinnedEngine::podman_native(&host.run(
                        engine,
                        &[
                            "--remote=false".into(),
                            "info".into(),
                            "--format".into(),
                            NATIVE_INFO.into(),
                        ],
                        false,
                    )?)?;
                    let mut args = pinned.arguments.clone();
                    args.extend(["info".into(), "--format".into(), NATIVE_INFO.into()]);
                    let confirmed = PinnedEngine::podman_native(&host.run(engine, &args, true)?)?;
                    if confirmed != pinned {
                        return Err(invalid(
                            "Pinned Podman storage differs from normal discovery; no container action was issued",
                        ));
                    }
                    Ok(pinned)
                }
            }
        }
    }
    pub fn validate_routing(&self) -> Result<(), CoreError> {
        if Self::discover(&self.host, &self.engine, self.context.as_deref())? != self.pinned {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Engine context, endpoint or storage configuration changed; select the target again",
            ));
        }
        Ok(())
    }
    fn run(&self, args: Vec<String>) -> Result<Vec<u8>, CoreError> {
        let mut command = self.pinned.arguments.clone();
        command.extend(args);
        self.host.run(&self.engine, &command, true)
    }
    pub fn list(&self) -> Result<Vec<ContainerDescriptor>, CoreError> {
        self.validate_routing()?;
        let bytes = self.run(vec![
            "ps".into(),
            "--all".into(),
            "--no-trunc".into(),
            "--format".into(),
            "{{.ID}}".into(),
        ])?;
        let ids = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("Invalid container inventory"))?
            .lines()
            .collect::<Vec<_>>();
        if ids.len() > 100 {
            return Err(invalid(
                "Container inventory exceeds 100 entries; choose an exact container ID",
            ));
        }
        ids.into_iter().map(|id| self.resolve(id)).collect()
    }
    pub fn resolve(&self, selector: &str) -> Result<ContainerDescriptor, CoreError> {
        self.observe_selected(selector)?.ok_or_else(||invalid("The selected immutable container ID is missing or no longer visible in this engine context; refresh discovery. A replacement with the same name is a different target"))
    }
    /// None is only a successful exact-filter observation that this pinned subject is not visible.
    fn observe_selected(&self, selector: &str) -> Result<Option<ContainerDescriptor>, CoreError> {
        if selector.is_empty()
            || selector.len() > 4096
            || selector.starts_with('-')
            || selector.chars().any(char::is_control)
        {
            return Err(invalid("Choose a bounded container name or immutable ID"));
        }
        let format = if self.engine == ContainerEngine::Podman {
            INSPECT.replace(".Id", ".ID")
        } else {
            INSPECT.into()
        };
        let bytes = match self.run(vec![
            "container".into(),
            "inspect".into(),
            "--format".into(),
            format,
            selector.into(),
        ]) {
            Ok(bytes) => bytes,
            Err(error) => {
                if selector.len() == 64
                    && selector.bytes().all(|b| b.is_ascii_hexdigit())
                    && let Ok(ids) = self.run(vec![
                        "ps".into(),
                        "--all".into(),
                        "--no-trunc".into(),
                        "--filter".into(),
                        format!("id={selector}"),
                        "--format".into(),
                        "{{.ID}}".into(),
                    ])
                    && filtered_id_absent(&ids, selector).is_ok_and(|absent| absent)
                {
                    return Ok(None);
                }
                return Err(CoreError::new(
                    error.code,
                    "Container inspect failed; the target may be missing or engine permissions may deny access",
                ));
            }
        };
        let mut metadata = parsed(&bytes)?;
        if let Some(image) = metadata.get("Image").and_then(Value::as_str) {
            let id = image.strip_prefix("sha256:").unwrap_or(image);
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid("Invalid immutable container image ID"));
            }
            let architecture = parsed(&self.run(vec![
                "image".into(),
                "inspect".into(),
                "--format".into(),
                "{{json .Architecture}}".into(),
                image.into(),
            ])?)?;
            metadata["Architecture"] = architecture;
        }
        ContainerDescriptor::decode(
            self.pinned.endpoint.clone(),
            &serde_json::to_vec(&metadata).map_err(|_| invalid("Invalid engine metadata"))?,
            self.user.clone(),
        )
        .map(Some)
    }
    pub fn start(&self, selected: &ContainerDescriptor) -> StartOutcome {
        let before = (|| {
            self.host.check_cancelled()?;
            self.validate_routing()?;
            let observed = match self.resolve(&selected.immutable_id) {
                Ok(v) => v,
                Err(error) => {
                    if let Ok(named) = self.resolve(&selected.name) {
                        selected.revalidate(&named)?;
                    }
                    return Err(error);
                }
            };
            selected.revalidate(&observed)?;
            if observed.state != ContainerState::Stopped {
                return Err(invalid(
                    "Only the chosen stopped existing container can be started",
                ));
            }
            self.host.check_cancelled()?;
            Ok(observed)
        })();
        let before = match before {
            Ok(v) => v,
            Err(e) => return StartOutcome::Failed(e),
        };
        let result = self.run(vec!["start".into(), selected.immutable_id.clone()]);
        let current = self.resolve(&selected.immutable_id).and_then(|v| {
            selected.revalidate(&v)?;
            Ok(v)
        });
        match (result, current) {
            (Ok(_), Ok(v)) if v.state == ContainerState::Running => {
                match super::container_transport::ContainerConnector::new(self.clone(), v.clone()) {
                    Ok(connector) => StartOutcome::Started(connector.selected),
                    Err(error) => StartOutcome::StartedUnsupported { selected: v, error },
                }
            }
            (Err(_), Ok(v))
                if v.state == ContainerState::Stopped
                    && v.start_generation == before.start_generation =>
            {
                StartOutcome::Failed(invalid(
                    "Engine did not start the chosen container; verify engine permissions. The inspected stopped state/start generation are unchanged",
                ))
            }
            (Err(error), _) => StartOutcome::Uncertain {
                selected: selected.clone(),
                error,
            },
            (_, Err(error)) => StartOutcome::Uncertain {
                selected: selected.clone(),
                error,
            },
            _ => StartOutcome::Uncertain {
                selected: selected.clone(),
                error: invalid(
                    "Start was dispatched but current running state is unconfirmed; inspect the original ID without retry",
                ),
            },
        }
    }
    pub(crate) fn exec(
        &self,
        selected: &ContainerDescriptor,
        script: &str,
        purpose: super::ssh::PipePurpose,
    ) -> Result<super::ssh::SshChannel, CoreError> {
        self.validate_routing()?;
        let observed = self.observe_selected(&selected.immutable_id)?.ok_or_else(||CoreError::new(ErrorCode::TargetChanged,"Pinned container binding is missing or no longer visible in this engine context; reconcile the original subject before choosing a target"))?;
        selected.revalidate(&observed)?;
        if observed.state != ContainerState::Running {
            return Err(invalid(
                "Container is stopped, paused or unavailable; use the explicit Start container action for a stopped target",
            ));
        }
        if selected.start_generation != observed.start_generation {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "Container restarted during connection; reconcile current identity/runtime before continuing",
            ));
        }
        let mut args = self.pinned.arguments.clone();
        args.extend(["exec".into(), "--interactive".into()]);
        if let Some(user) = self.user.as_ref() {
            args.extend(["--user".into(), user.clone()]);
        }
        args.extend([
            selected.immutable_id.clone(),
            "sh".into(),
            "-c".into(),
            script.into(),
        ]);
        self.host.start(&self.engine, &args, true, purpose)
    }
}

#[cfg(test)]
mod absence_tests {
    use super::*;
    #[test]
    fn filtered_inventory_requires_bounded_utf8_exact_ids_before_proving_absence() {
        let selected = "a".repeat(64);
        assert!(filtered_id_absent(b"", &selected).unwrap());
        assert!(!filtered_id_absent(format!("{selected}\n").as_bytes(), &selected).unwrap());
        for bytes in [
            b"permission denied\n".to_vec(),
            "b".repeat(64).into_bytes(),
            vec![0xff],
            b"\n".to_vec(),
            format!("{selected}\n{selected}\n").into_bytes(),
            vec![b'x'; 65537],
        ] {
            assert!(
                filtered_id_absent(&bytes, &selected).is_err(),
                "untrusted inventory cannot establish absence: {bytes:?}"
            );
        }
    }
}
