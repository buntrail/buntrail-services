//! Encoding-aware compatibility commands over the authoritative file service.
use crate::{
    connections::local::{identity, new_id},
    files::{self, LoadBudget, LocalFileService},
};
use buntrail_core::{Text, contracts::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileBinding {
    pub file: FileRef,
    pub version: FileVersion,
    pub encoding: Encoding,
}
impl FileBinding {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        if value.len() > 128 * 1024 {
            return Err("File binding exceeds metadata limit".into());
        }
        let value = value
            .strip_prefix("bt2:")
            .ok_or("Reopen this file to obtain its current identity")?;
        let binding: Self = serde_json::from_str(value).map_err(crate::error)?;
        if binding.file.target != binding.version.target {
            return Err("File binding target mismatch".into());
        }
        Ok(binding)
    }
    pub fn token(&self) -> Result<String, String> {
        let mut file = self.file.clone();
        file.resolved_identity = Some(self.version.file_identity.clone());
        let normalized = Self {
            file,
            version: self.version.clone(),
            encoding: self.encoding.clone(),
        };
        Ok(format!(
            "bt2:{}",
            serde_json::to_string(&normalized).map_err(crate::error)?
        ))
    }
}
pub(crate) struct Files {
    pub service: Arc<LocalFileService>,
}
impl Files {
    pub fn new(directory: PathBuf) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .map_err(crate::error)?;
        Ok(Self {
            service: Arc::new(
                LocalFileService::new(identity().map_err(core_error)?, directory)
                    .map_err(core_error)?,
            ),
        })
    }
    fn file(&self, path: &str) -> Result<FileRef, String> {
        let path = std::path::absolute(Path::new(path)).map_err(crate::error)?;
        use std::os::unix::ffi::OsStrExt;
        Ok(FileRef {
            target: self.service.target().clone(),
            path: TargetPath::posix(path.as_os_str().as_bytes().to_vec()).map_err(core_error)?,
            resolved_identity: None,
        })
    }
    pub fn observe(&self, request: &Value) -> Result<Value, String> {
        let file = self.file(crate::string(request, "path")?)?;
        let version = self
            .service
            .path_version(file.clone())
            .map_err(core_error)?;
        Ok(
            json!({"observed":FileBinding {file,version,encoding:Encoding::Utf8 {bom:false}}.token()?}),
        )
    }
    pub fn mutate(&self, request: &Value) -> Result<Value, String> {
        let command = crate::string(request, "command")?;
        let file = self.file(crate::string(request, "path")?)?;
        let expected = if command == "fs.mkdir" {
            ExpectedPathState::Absent
        } else if let Some(observed) = request.get("observed") {
            let binding = FileBinding::parse(observed.as_str().ok_or("observed must be a token")?)?;
            if binding.file.target != file.target || binding.file.path != file.path {
                return Err("Observed node belongs to another target/path".into());
            }
            ExpectedPathState::Present(binding.version)
        } else {
            ExpectedPathState::Present(
                self.service
                    .path_version(file.clone())
                    .map_err(core_error)?,
            )
        };
        let mutation = match command {
            "fs.mkdir" => FileMutation::CreateDirectory,
            "fs.rename" => FileMutation::Move {
                destination: self.file(crate::string(request, "to")?)?.path,
            },
            "fs.remove" => FileMutation::Remove,
            _ => return Err("Invalid file mutation".into()),
        };
        let receipt = self.service.mutate_sync(FileMutationRequest {
            operation: OperationID(new_id().map_err(core_error)?),
            file,
            expected,
            command: mutation,
        });
        match &receipt.state {
            OperationState::Confirmed(MutationResult::FileChanged { .. }) => {
                Ok(json!({"receipt":receipt}))
            }
            OperationState::Failed(f) if f.effect == FailureEffect::ProvenNoEffect => {
                Err(f.error.message.clone())
            }
            _ => Err(format!(
                "File operation {:?} is uncertain; inspect before retrying",
                receipt.id
            )),
        }
    }
    pub fn read(&self, request: &Value) -> Result<Value, String> {
        let snapshot = self
            .service
            .read_sync(self.file(crate::string(request, "path")?)?)
            .map_err(core_error)?;
        if snapshot.size > (files::MAX_DOCUMENT_BYTES * 2 + 4) as u64 {
            return Err("File exceeds editable size".into());
        }
        let _budget = LoadBudget::acquire(
            (snapshot.size as usize)
                .saturating_mul(7)
                .saturating_div(2)
                .saturating_add(1024 * 1024),
        )
        .map_err(core_error)?;
        let bytes = self
            .service
            .source_bytes(&snapshot.source, files::MAX_DOCUMENT_BYTES * 2 + 4, true)
            .map_err(core_error)?;
        let (text, encoding) = files::decode(&bytes).map_err(core_error)?;
        if text.len() > files::MAX_DOCUMENT_BYTES {
            return Err("Decoded text exceeds 64 MiB".into());
        }
        let binding = FileBinding {
            file: snapshot.file,
            version: snapshot.version,
            encoding,
        };
        Ok(json!({"text":text,"version":binding.token()?}))
    }
    pub fn write(&self, request: &Value) -> Result<Value, String> {
        let result = self.save_document(request)?;
        if result.get("version").is_some() {
            return Ok(result);
        }
        let receipt: OperationReceipt =
            serde_json::from_value(result["receipt"].clone()).map_err(crate::error)?;
        match receipt.state {
            OperationState::Failed(failure) => Err(failure.error.message),
            _ => Err("Save outcome is uncertain; retain edits and inspect the operation".into()),
        }
    }
    pub fn save_document(&self, request: &Value) -> Result<Value, String> {
        let binding = FileBinding::parse(crate::string(request, "version")?)?;
        let path = self.file(crate::string(request, "path")?)?;
        if binding.file.target != path.target || binding.file.path != path.path {
            return Err("File or environment no longer matches the observed binding".into());
        }
        let mut snapshot = snapshot(crate::string(request, "text")?, binding.encoding.clone())?;
        snapshot.revision = BufferRevision(
            request
                .get("revision")
                .map(|v| v.as_u64().ok_or("revision must be a nonnegative integer"))
                .transpose()?
                .unwrap_or(0),
        );
        let _budget = files::reserve_encoding(&snapshot).map_err(core_error)?;
        let bytes = files::encode(&snapshot).map_err(core_error)?;
        let operation = match request.get("operation") {
            Some(v) => serde_json::from_value(v.clone()).map_err(crate::error)?,
            None => OperationID(new_id().map_err(core_error)?),
        };
        let receipt = self.service.save_sync(SaveRequest {
            operation,
            file: binding.file.clone(),
            expected_version: Some(binding.version.clone()),
            submitted_revision: snapshot.revision,
            source: ByteSource::Memory(bytes.into()),
        });
        Self::completion(binding, receipt)
    }
    pub fn inspect_save(&self, version: &str, operation: OperationID) -> Result<Value, String> {
        let binding = FileBinding::parse(version)?;
        let receipt = self
            .service
            .inspect_sync(operation, binding.file.target.clone())
            .map_err(core_error)?;
        Self::completion(binding, receipt)
    }
    fn completion(binding: FileBinding, receipt: OperationReceipt) -> Result<Value, String> {
        let version = match &receipt.state {
            OperationState::Confirmed(MutationResult::Saved(saved)) => {
                if saved.version.target != binding.file.target {
                    return Err("Saved file target changed".into());
                }
                Some(
                    FileBinding {
                        version: saved.version.clone(),
                        ..binding
                    }
                    .token()?,
                )
            }
            _ => None,
        };
        let mut result = json!({"receipt":receipt});
        if let Some(version) = version {
            result["version"] = version.into();
        }
        Ok(result)
    }
    pub fn is_local(&self, target: &TargetIdentity) -> bool {
        self.service.target() == target
    }
    pub fn recovery(&self) -> Arc<crate::recovery::store::RecoveryStore> {
        self.service.recovery.clone()
    }
    pub fn create(&self, request: &Value) -> Result<Value, String> {
        let binding = request
            .get("source_version")
            .filter(|v| !v.is_null())
            .map(|value| {
                FileBinding::parse(
                    value
                        .as_str()
                        .ok_or("source_version must be a string or null")?,
                )
            })
            .transpose()?;
        let encoding = match binding {
            Some(binding) => {
                if binding.file.target != *self.service.target() {
                    return Err("Source encoding belongs to another environment".into());
                }
                binding.encoding
            }
            None => Encoding::Utf8 { bom: false },
        };
        let snapshot = snapshot(crate::string(request, "text")?, encoding.clone())?;
        let _budget = files::reserve_encoding(&snapshot).map_err(core_error)?;
        let bytes = files::encode(&snapshot).map_err(core_error)?;
        let file = self.file(crate::string(request, "path")?)?;
        let receipt = self.service.mutate_sync(FileMutationRequest {
            operation: OperationID(new_id().map_err(core_error)?),
            file: file.clone(),
            expected: ExpectedPathState::Absent,
            command: FileMutation::Create {
                source: ByteSource::Memory(bytes.into()),
            },
        });
        match receipt.state {
            OperationState::Confirmed(MutationResult::FileChanged { file, version: Some(version) }) => Ok(json!({"version":FileBinding { file, version, encoding }.token()?})),
            OperationState::Failed(failure) => Err(failure.error.message),
            _ => Err("Creation outcome is uncertain; retain edits and inspect the destination before retrying".into()),
        }
    }
}
fn snapshot(text: &str, encoding: Encoding) -> Result<DocumentSnapshot, String> {
    if text.len() > files::MAX_DOCUMENT_BYTES || text.contains('\0') {
        return Err("Text exceeds 64 MiB or contains binary NUL data".into());
    }
    Ok(DocumentSnapshot {
        document: DocumentID([0; 16]),
        revision: BufferRevision(0),
        text: Arc::new(Text::from(text)),
        encoding,
        line_endings: LineEndings::Mixed,
        language: None,
    })
}
fn core_error(error: CoreError) -> String {
    error.message
}

pub(crate) fn default_directory() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("BUNTRAIL_STATE_DIR") {
        return Ok(PathBuf::from(path));
    }
    let home =
        std::env::var_os("HOME").ok_or("HOME is unavailable; configure Buntrail state storage")?;
    #[cfg(target_os = "macos")]
    let path =
        PathBuf::from(home).join("Library/Application Support/id.bungamungil.buntrail.app/Backend");
    #[cfg(not(target_os = "macos"))]
    let path = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".local/share"))
        .join("buntrail-app/Backend");
    Ok(path)
}

pub(crate) fn rebound_version(
    previous: &str,
    observed: &str,
    path: &str,
) -> Result<String, String> {
    use std::os::unix::ffi::OsStrExt;
    let previous = FileBinding::parse(previous)?;
    let observed = FileBinding::parse(observed)?;
    let path = std::path::absolute(path).map_err(crate::error)?;
    let path = TargetPath::posix(path.as_os_str().as_bytes().to_vec()).map_err(core_error)?;
    if observed.file.path != path
        || observed.file.target != previous.file.target
        || observed.version.file_identity != previous.version.file_identity
        || observed.version.content_digest != previous.version.content_digest
        || observed.encoding != previous.encoding
    {
        return Err("Moved file identity or contents changed; retain edits and revalidate".into());
    }
    observed.token()
}
