use super::local::*;
use buntrail_core::contracts::*;
use std::{fs, os::unix::fs::MetadataExt};

fn identity(metadata: &fs::Metadata) -> Vec<u8> {
    [metadata.dev().to_be_bytes(), metadata.ino().to_be_bytes()].concat()
}
impl LocalFileService {
    /// Target worker only. This observes membership; it does not grant later mutation authority.
    pub fn resolve_sync(
        &self,
        root: FileRef,
        purpose: FileResolvePurpose,
    ) -> Result<FileResolution, CoreError> {
        let original_root = self.validate(&root)?;
        let canonical = fs::canonicalize(&original_root).map_err(io_error)?;
        let root_metadata = fs::metadata(&canonical).map_err(io_error)?;
        if !root_metadata.is_dir() {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "workspace root is not a directory",
            ));
        }
        let root_identity = identity(&root_metadata);
        if root
            .resolved_identity
            .as_ref()
            .is_some_and(|old| old != &root_identity)
        {
            return Err(CoreError::new(
                ErrorCode::StaleRevision,
                "workspace root identity changed",
            ));
        }
        let verified_root = FileRef {
            target: root.target.clone(),
            path: target_path(&canonical),
            resolved_identity: Some(root_identity.clone()),
        };
        let (requested, node, resolved, missing_allowed) = match &purpose {
            FileResolvePurpose::Root => (
                root.path.clone(),
                canonical.clone(),
                canonical.clone(),
                false,
            ),
            FileResolvePurpose::OpenChild(child) | FileResolvePurpose::MutationNode(child) => {
                crate::workspaces::store::validate_child(&verified_root.path, child)?;
                let node = crate::workspaces::store::resolved_parent(child)?;
                let mutation = matches!(purpose, FileResolvePurpose::MutationNode(_));
                let resolved = if mutation {
                    node.clone()
                } else {
                    fs::canonicalize(&node).map_err(io_error)?
                };
                (child.clone(), node, resolved, mutation)
            }
        };
        let metadata = match fs::symlink_metadata(&node) {
            Ok(m) => Some(m),
            Err(e) if missing_allowed && e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error(e)),
        };
        let kind = metadata.as_ref().map(|m| {
            if m.is_symlink() {
                FileKind::Symlink
            } else if m.is_dir() {
                FileKind::Directory
            } else if m.is_file() {
                FileKind::File
            } else {
                FileKind::Other
            }
        });
        let observed_identity = if matches!(purpose, FileResolvePurpose::OpenChild(_)) {
            Some(identity(&fs::metadata(&resolved).map_err(io_error)?))
        } else {
            metadata.as_ref().map(identity)
        };
        let mut file = FileRef {
            target: root.target.clone(),
            path: requested,
            resolved_identity: observed_identity,
        };
        let version = if metadata.as_ref().is_some_and(|m| m.is_file())
            || (matches!(purpose, FileResolvePurpose::OpenChild(_))
                && fs::metadata(&resolved).map_err(io_error)?.is_file())
        {
            let snapshot = self.read_sync(file.clone())?;
            file.resolved_identity = snapshot.file.resolved_identity;
            Some(snapshot.version)
        } else {
            None
        };
        if fs::canonicalize(&original_root).map_err(io_error)? != canonical
            || identity(&fs::metadata(&canonical).map_err(io_error)?) != root_identity
            || (!matches!(purpose, FileResolvePurpose::Root)
                && crate::workspaces::store::resolved_parent(&file.path)? != node)
        {
            return Err(CoreError::new(
                ErrorCode::StaleRevision,
                "path changed during resolution",
            ));
        }
        let current = match fs::symlink_metadata(&node) {
            Ok(m) => Some(identity(&m)),
            Err(e) if missing_allowed && e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error(e)),
        };
        if current != metadata.as_ref().map(identity)
            || (matches!(purpose, FileResolvePurpose::OpenChild(_))
                && fs::canonicalize(&node).map_err(io_error)? != resolved)
        {
            return Err(CoreError::new(
                ErrorCode::StaleRevision,
                "node changed during resolution",
            ));
        }
        Ok(FileResolution {
            root: verified_root,
            file,
            resolved_path: target_path(&resolved),
            kind,
            version,
        })
    }
}
