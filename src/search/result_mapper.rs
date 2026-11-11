use base64::Engine;
use buntrail_core::contracts::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
pub fn bytes(v: &Value) -> Result<Vec<u8>, CoreError> {
    if let Some(s) = v["text"].as_str() {
        return Ok(s.as_bytes().to_vec());
    }
    if let Some(s) = v["bytes"].as_str() {
        return base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(|_| invalid());
    }
    Err(invalid())
}
pub fn invalid() -> CoreError {
    CoreError::new(
        ErrorCode::Io,
        "Invalid or oversized ripgrep output; results are incomplete",
    )
}
pub fn matches<'a>(
    value: &'a Value,
    root: &FileRef,
) -> Result<impl Iterator<Item = Result<SearchMatch, CoreError>> + 'a, CoreError> {
    let d = &value["data"];
    let path = bytes(&d["path"])?;
    if path.len() > 16384 {
        return Err(invalid());
    }
    use std::os::unix::ffi::OsStrExt;
    let reported = std::path::Path::new(std::ffi::OsStr::from_bytes(&path));
    let path = if reported.is_absolute() {
        TargetPath::posix(path)?
    } else {
        let mut resolved = crate::files::path(&root.path)?;
        for component in reported.components() {
            match component {
                std::path::Component::Normal(part) => resolved.push(part),
                std::path::Component::CurDir => {}
                _ => return Err(invalid()),
            }
        }
        crate::files::target_path(&resolved)
    };
    let preview = bytes(&d["lines"])?;
    if preview.len() > 65536 {
        return Err(invalid());
    }
    let digest: [u8; 32] = Sha256::digest(&preview).into();
    let preview = String::from_utf8(preview).map_err(|_| {
        CoreError::new(
            ErrorCode::Unavailable,
            "Non-UTF-8 result cannot be opened as editable text",
        )
    })?;
    let file = FileRef {
        target: root.target.clone(),
        path,
        resolved_identity: None,
    };
    // Exact searched line digest is evidence; never pretend metadata is a full-file version.
    let version = FileVersion {
        target: root.target.clone(),
        opaque_token: vec![],
        content_digest: digest,
        file_identity: vec![],
    };
    let line = d["line_number"].as_u64().ok_or_else(invalid)?;
    Ok(d["submatches"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(move |s| {
            Ok(SearchMatch {
                file: file.clone(),
                line,
                preview_column_utf8: s["start"].as_u64().ok_or_else(invalid)?,
                preview: preview.clone(),
                searched_version: version.clone(),
                searched_digest: digest,
            })
        }))
}
