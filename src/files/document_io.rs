//! Client-local decoding/recovery preparation, independent of the project I/O route.
use super::local::*;
use crate::recovery::store::RecoveryStore;
use buntrail_core::{Text, contracts::*, documents::*};
use std::{io::Read, os::unix::fs::MetadataExt, sync::Arc};

pub fn source_bytes(
    spools: &crate::leases::LeasePool,
    source: &ByteSource,
    maximum: usize,
    verify: bool,
) -> Result<Vec<u8>, CoreError> {
    match source {
        ByteSource::Memory(b) => {
            if verify && b.len() > maximum {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "document exceeds editable size; use bounded reads",
                ));
            }
            Ok(b[..b.len().min(maximum)].to_vec())
        }
        ByteSource::PrivateSpool {
            local_path,
            length,
            digest: expected,
            ..
        } => {
            let p = path(local_path)?;
            let _lease = spools.retain(&p).ok_or_else(|| {
                CoreError::new(ErrorCode::Unavailable, "private spool source was released")
            })?;
            if p.parent() != Some(spools.directory()) {
                return Err(CoreError::new(
                    ErrorCode::InvalidArgument,
                    "spool is not owned by this service",
                ));
            }
            let f = open_regular(&p)?;
            let m = f.metadata().map_err(io_error)?;
            if m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 || m.len() != *length
            {
                return Err(io_error("invalid private spool"));
            }
            if verify && *length > maximum as u64 {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "document exceeds editable size; use bounded reads",
                ));
            }
            let mut bytes = vec![];
            f.take(maximum as u64)
                .read_to_end(&mut bytes)
                .map_err(io_error)?;
            if verify && digest(&bytes) != *expected {
                return Err(io_error("spool digest mismatch"));
            }
            Ok(bytes)
        }
    }
}

/// `recovery = None` revalidates an existing session without allocating a new journal epoch.
pub fn load_snapshot(
    s: FileSnapshot,
    document: DocumentID,
    recovery: Option<&RecoveryStore>,
    spools: &crate::leases::LeasePool,
) -> Result<(LoadedDocument, LoadBudget), CoreError> {
    if s.file.target != s.version.target {
        return Err(CoreError::new(
            ErrorCode::TargetChanged,
            "snapshot version target mismatch",
        ));
    }
    if s.size > (MAX_DOCUMENT_BYTES * 2 + 4) as u64 {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "file exceeds editable size; retain byte source for bounded read-only viewing",
        ));
    }
    let multiplier = if matches!(s.encoding, Encoding::Utf8 { .. }) {
        3
    } else {
        6
    };
    let budget = match LoadBudget::acquire(
        (s.size as usize)
            .saturating_mul(multiplier)
            .saturating_add(1024 * 1024),
    ) {
        Ok(b) => b,
        Err(e) => {
            return Err(e);
        }
    };
    let bytes_result = source_bytes(spools, &s.source, MAX_ENCODED_BYTES, true);
    let bytes = bytes_result?;
    if bytes.len() as u64 != s.size || digest(&bytes) != s.version.content_digest {
        return Err(CoreError::new(
            ErrorCode::InvalidArgument,
            "snapshot bytes differ from target version",
        ));
    }
    let (text, encoding) = decode(&bytes)?;
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "decoded text exceeds editable size; open read-only bytes",
        ));
    }
    let line_endings = line_endings(&text);
    let (journal_epoch, journal_lease) = if let Some(recovery) = recovery {
        let (epoch, lease) = recovery.begin_session(document)?;
        (epoch, Some(lease))
    } else {
        (0, None)
    };
    Ok((
        LoadedDocument {
            document,
            file: s.file,
            version: s.version,
            text: Arc::new(Text::from(text)),
            encoding,
            line_endings,
            read_only: None,
            journal_epoch,
            journal_lease,
        },
        budget,
    ))
}

/// Persist the pending draft before encoding. The returned budget stays alive through dispatch.
pub fn prepare_save(
    recovery: &RecoveryStore,
    prepared: PreparedSave,
) -> Result<(SaveRequest, LoadBudget), CoreError> {
    let r = prepared.recovery;
    if r.version.target != r.file.target {
        return Err(CoreError::new(
            ErrorCode::TargetChanged,
            "draft version target mismatch",
        ));
    }
    recovery.write_sync(r.clone())?;
    let budget = reserve_encoding(&r.snapshot)?;
    let bytes = encode(&r.snapshot)?;
    Ok((
        SaveRequest {
            operation: prepared.operation,
            file: r.file,
            expected_version: Some(r.version),
            submitted_revision: r.snapshot.revision,
            source: ByteSource::Memory(bytes.into()),
        },
        budget,
    ))
}
fn line_endings(s: &str) -> LineEndings {
    let crlf = s.matches("\r\n").count();
    let lf = s.bytes().filter(|b| *b == b'\n').count() - crlf;
    let cr = s.bytes().filter(|b| *b == b'\r').count() - crlf;
    match (crlf > 0, lf > 0, cr > 0) {
        (true, false, false) => LineEndings::CrLf,
        (false, false, true) => LineEndings::Cr,
        (false, _, false) => LineEndings::Lf,
        _ => LineEndings::Mixed,
    }
}
