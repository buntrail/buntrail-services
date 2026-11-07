//! One status entry or original alias at a time; never an aggregate service JSON reply.
use super::*;
use crate::git::observation::ObservationRecord;
const OUTPUT: &[u8; 8] = b"BTOUTP01";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedObservation {
    pub id: [u8; 16],
    pub worktree: WorktreeIdentity,
    pub state: GitExpectedState,
    pub alias_digest: [u8; 32],
    pub retained_bytes: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryGroup {
    Staged = 1,
    Unstaged = 2,
    Untracked = 3,
    Conflict = 4,
}
#[derive(Debug, Clone, PartialEq, Eq)]
// One record is streamed at a time; boxing Alias would allocate for every original alias.
#[allow(clippy::large_enum_variant)]
pub enum ObservationEvent {
    Entry { group: EntryGroup, entry: GitEntry },
    Alias(ObservationRecord),
}
fn aliases_hash() -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"buntrail.original-aliases.v1\0");
    hash
}
fn checked_path(path: &TargetPath, limit: TargetPathLimit) -> io::Result<&[u8]> {
    let b = path_bytes(path)?;
    if b.len() > limit.0 as usize || b.first() != Some(&b'/') || b.contains(&0) {
        return Err(malformed());
    }
    Ok(b)
}
pub struct OutputWriter<W> {
    out: W,
    limit: TargetPathLimit,
    counts: [u64; 5],
    phase: u8,
    hash: Sha256,
    expected: [u8; 32],
    failed: bool,
}
impl<W: Write> OutputWriter<W> {
    pub fn new(
        mut out: W,
        summary: &OwnedObservation,
        limit: TargetPathLimit,
    ) -> Result<Self, CoreError> {
        (|| -> io::Result<()> {
            out.write_all(OUTPUT)?;
            out.write_all(&limit.0.to_be_bytes())?;
            out.write_all(&summary.id)?;
            out.write_all(&summary.retained_bytes.to_be_bytes())?;
            bytes(
                &mut out,
                checked_path(&summary.worktree.canonical_path, limit)?,
            )?;
            bytes(&mut out, &summary.worktree.common_git_directory_identity)?;
            match &summary.state.head {
                GitHead::Branch { name, oid } => {
                    tag(&mut out, 0)?;
                    bytes(&mut out, name)?;
                    bytes(&mut out, oid.as_bytes())?;
                }
                GitHead::Detached(oid) => {
                    tag(&mut out, 1)?;
                    bytes(&mut out, oid.as_bytes())?;
                }
                GitHead::Unborn(name) => {
                    tag(&mut out, 2)?;
                    bytes(&mut out, name)?;
                }
            }
            out.write_all(&summary.state.index_fingerprint)?;
            out.write_all(&summary.state.worktree_fingerprint)?;
            out.write_all(&summary.alias_digest)
        })()
        .map_err(codec_error)?;
        Ok(Self {
            out,
            limit,
            counts: [0; 5],
            phase: 0,
            hash: aliases_hash(),
            expected: summary.alias_digest,
            failed: false,
        })
    }
    pub fn event(&mut self, event: &ObservationEvent) -> Result<(), CoreError> {
        if self.failed {
            return Err(invalid());
        }
        self.failed = true;
        let group = match event {
            ObservationEvent::Entry { group, .. } => *group as u8,
            ObservationEvent::Alias(_) => 5,
        };
        if group < self.phase {
            return Err(invalid());
        }
        self.phase = group;
        self.counts[group as usize - 1] = self.counts[group as usize - 1]
            .checked_add(1)
            .ok_or_else(invalid)?;
        (|| -> io::Result<()> {
            tag(&mut self.out, group)?;
            match event {
                ObservationEvent::Entry { entry, .. } => {
                    bytes(&mut self.out, checked_path(&entry.path, self.limit)?)?;
                    match &entry.previous_path {
                        None => tag(&mut self.out, 0)?,
                        Some(path) => {
                            tag(&mut self.out, 1)?;
                            bytes(&mut self.out, checked_path(path, self.limit)?)?;
                        }
                    }
                    bytes(&mut self.out, entry.status.as_bytes())?;
                }
                ObservationEvent::Alias(record) => {
                    if record.membership.is_none() {
                        return Err(malformed());
                    }
                    checked_path(&record.path, self.limit)?;
                    if let Some(path) = &record.resolved {
                        checked_path(path, self.limit)?;
                    }
                    let digest = record.file_reference.ok_or_else(malformed)?;
                    self.out
                        .write_all(&record.encode().map_err(|_| malformed())?)?;
                    self.hash.update(digest);
                }
            }
            Ok(())
        })()
        .map_err(codec_error)?;
        self.failed = false;
        Ok(())
    }
    pub fn finish(mut self) -> Result<W, CoreError> {
        if self.failed || <[u8; 32]>::from(self.hash.finalize()) != self.expected {
            return Err(invalid());
        }
        tag(&mut self.out, 0).map_err(codec_error)?;
        for count in self.counts {
            self.out.write_all(&count.to_be_bytes()).map_err(io_error)?;
        }
        self.out.write_all(&self.expected).map_err(io_error)?;
        Ok(self.out)
    }
}
pub struct OutputReader<R> {
    input: Option<Input<R>>,
    summary: OwnedObservation,
    limit: TargetPathLimit,
    counts: [u64; 5],
    phase: u8,
    hash: Sha256,
    complete: bool,
    wire_digest: Option<[u8; 32]>,
}
impl<R: Read> OutputReader<R> {
    pub fn new(reader: R, length: u64, target: &TargetIdentity) -> Result<Self, CoreError> {
        let mut input = Input::new(reader, length);
        let (summary, limit) = (|| -> Result<_, CoreError> {
            if &input.fixed::<8>().map_err(codec_error)? != OUTPUT {
                return Err(invalid());
            }
            let limit =
                TargetPathLimit::declared(u32::from_be_bytes(input.fixed().map_err(codec_error)?))?;
            let id = input.fixed().map_err(codec_error)?;
            let retained_bytes = input.number().map_err(codec_error)?;
            let worktree = WorktreeIdentity {
                target: target.clone(),
                canonical_path: TargetPath::posix(
                    input.bounded(limit.0 as u64).map_err(codec_error)?,
                )?,
                common_git_directory_identity: input.bounded(SCALAR).map_err(codec_error)?,
            };
            let head = match input.tag().map_err(codec_error)? {
                0 => GitHead::Branch {
                    name: input.bounded(SCALAR).map_err(codec_error)?,
                    oid: input.string().map_err(codec_error)?,
                },
                1 => GitHead::Detached(input.string().map_err(codec_error)?),
                2 => GitHead::Unborn(input.bounded(SCALAR).map_err(codec_error)?),
                _ => return Err(invalid()),
            };
            let state = GitExpectedState {
                head,
                index_fingerprint: input.fixed().map_err(codec_error)?,
                worktree_fingerprint: input.fixed().map_err(codec_error)?,
            };
            let alias_digest = input.fixed().map_err(codec_error)?;
            Ok((
                OwnedObservation {
                    id,
                    worktree,
                    state,
                    alias_digest,
                    retained_bytes,
                },
                limit,
            ))
        })()?;
        Ok(Self {
            input: Some(input),
            summary,
            limit,
            counts: [0; 5],
            phase: 0,
            hash: aliases_hash(),
            complete: false,
            wire_digest: None,
        })
    }
    /// Events are provisional until EOF, trailer and the transport's whole-body seal validate.
    pub fn next_event(&mut self) -> Result<Option<ObservationEvent>, CoreError> {
        if self.complete {
            return Ok(None);
        }
        let result = self.event();
        if result.is_err() {
            self.input = None;
        }
        result
    }
    fn event(&mut self) -> Result<Option<ObservationEvent>, CoreError> {
        let input = self.input.as_mut().ok_or_else(invalid)?;
        let kind = input.tag().map_err(codec_error)?;
        if kind == 0 {
            for count in self.counts {
                if input.number().map_err(codec_error)? != count {
                    return Err(invalid());
                }
            }
            let digest = input.fixed::<32>().map_err(codec_error)?;
            if digest != self.summary.alias_digest
                || digest != <[u8; 32]>::from(self.hash.clone().finalize())
            {
                return Err(invalid());
            }
            self.wire_digest = Some(self.input.take().unwrap().finish().map_err(codec_error)?);
            self.complete = true;
            return Ok(None);
        }
        if kind < self.phase || kind > 5 {
            return Err(invalid());
        }
        self.phase = kind;
        self.counts[kind as usize - 1] = self.counts[kind as usize - 1]
            .checked_add(1)
            .ok_or_else(invalid)?;
        if kind == 5 {
            let record = ObservationRecord::read_with_path_limit(input, self.limit.0 as usize)?
                .ok_or_else(invalid)?;
            if record.membership.is_none() {
                return Err(invalid());
            }
            self.hash.update(record.file_reference.ok_or_else(invalid)?);
            return Ok(Some(ObservationEvent::Alias(record)));
        }
        let path = TargetPath::posix(input.bounded(self.limit.0 as u64).map_err(codec_error)?)?;
        let previous_path = match input.tag().map_err(codec_error)? {
            0 => None,
            1 => Some(TargetPath::posix(
                input.bounded(self.limit.0 as u64).map_err(codec_error)?,
            )?),
            _ => return Err(invalid()),
        };
        let status = input.string().map_err(codec_error)?;
        let group = match kind {
            1 => EntryGroup::Staged,
            2 => EntryGroup::Unstaged,
            3 => EntryGroup::Untracked,
            4 => EntryGroup::Conflict,
            _ => return Err(invalid()),
        };
        Ok(Some(ObservationEvent::Entry {
            group,
            entry: GitEntry {
                path,
                previous_path,
                status,
            },
        }))
    }
    /// Provisional identity for owner-scoped cleanup only; no observation authority before finish.
    pub fn observation_id(&self) -> [u8; 16] {
        self.summary.id
    }
    /// Compare with the authenticated transport's end seal before using the summary.
    pub fn wire_digest(&self) -> Option<[u8; 32]> {
        self.wire_digest
    }
    pub fn finish(self) -> Result<OwnedObservation, CoreError> {
        if !self.complete {
            return Err(invalid());
        }
        Ok(self.summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::git::observation::ObservationMembership;
    fn fixture() -> (OwnedObservation, ObservationRecord) {
        let r = super::super::tests::original();
        let record = ObservationRecord {
            path: TargetPath::PosixBytes([b"/".as_slice(), &vec![b'x'; 2999]].concat()),
            structural_token: [1; 32],
            resolved: None,
            regular: None,
            membership: Some(ObservationMembership {
                requested_repository: Some([2; 32]),
                resolved_repository: None,
                affected: true,
            }),
            file_reference: Some([3; 32]),
        };
        let mut hash = Sha256::new();
        hash.update(b"buntrail.original-aliases.v1\0");
        hash.update([3; 32]);
        (
            OwnedObservation {
                id: [4; 16],
                worktree: r.worktree,
                state: r.expected,
                alias_digest: hash.finalize().into(),
                retained_bytes: 999,
            },
            record,
        )
    }
    #[test]
    fn output_streams_all_status_groups_and_linux_paths_without_host_path_limit() {
        let (summary, record) = fixture();
        let mut bytes = Vec::new();
        let mut writer = OutputWriter::new(
            &mut bytes,
            &summary,
            TargetPathLimit::declared(4096).unwrap(),
        )
        .expect("owned output must stream");
        for group in [
            EntryGroup::Staged,
            EntryGroup::Unstaged,
            EntryGroup::Untracked,
            EntryGroup::Conflict,
        ] {
            writer
                .event(&ObservationEvent::Entry {
                    group,
                    entry: GitEntry {
                        path: record.path.clone(),
                        previous_path: Some(TargetPath::PosixBytes(b"/old\xff".to_vec())),
                        status: "R ".into(),
                    },
                })
                .unwrap();
        }
        writer
            .event(&ObservationEvent::Alias(record.clone()))
            .unwrap();
        writer.finish().unwrap();
        let mut reader = OutputReader::new(
            super::super::tests::Chunks(&bytes, 7),
            bytes.len() as u64,
            &summary.worktree.target,
        )
        .unwrap();
        for group in [
            EntryGroup::Staged,
            EntryGroup::Unstaged,
            EntryGroup::Untracked,
            EntryGroup::Conflict,
        ] {
            assert!(
                matches!(reader.next_event().unwrap(),Some(ObservationEvent::Entry{group:actual,entry}) if actual==group&&entry.path==record.path)
            );
        }
        assert_eq!(
            reader.next_event().unwrap(),
            Some(ObservationEvent::Alias(record))
        );
        assert_eq!(reader.next_event().unwrap(), None);
        assert_eq!(reader.finish().unwrap(), summary);
        bytes[8..12].copy_from_slice(&1024u32.to_be_bytes());
        let mut reader = OutputReader::new(
            bytes.as_slice(),
            bytes.len() as u64,
            &summary.worktree.target,
        )
        .unwrap();
        assert!(reader.next_event().is_err());
    }
    #[test]
    fn output_exceeds_legacy_32_mib_without_an_aggregate_buffer() {
        use std::io::{Seek, SeekFrom};
        let (summary, record) = fixture();
        let mut file = tempfile::tempfile().unwrap();
        let mut writer = OutputWriter::new(
            &mut file,
            &summary,
            TargetPathLimit::declared(4096).unwrap(),
        )
        .unwrap();
        let event = ObservationEvent::Entry {
            group: EntryGroup::Untracked,
            entry: GitEntry {
                path: record.path.clone(),
                previous_path: None,
                status: "??".into(),
            },
        };
        for _ in 0..12000 {
            writer.event(&event).unwrap();
        }
        writer.event(&ObservationEvent::Alias(record)).unwrap();
        writer.finish().unwrap();
        let length = file.stream_position().unwrap();
        assert!(length > 32 * 1024 * 1024);
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut reader = OutputReader::new(file, length, &summary.worktree.target).unwrap();
        let mut count = 0;
        while reader.next_event().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 12001);
        assert_eq!(reader.finish().unwrap(), summary);
        eprintln!(
            "synthetic owned output: {length} bytes, {count} events; no Git scalability claim"
        );
    }
    #[test]
    fn output_rejects_bad_trailer_truncation_order_type_and_unsupported_path_bound() {
        let (summary, record) = fixture();
        let mut bytes = Vec::new();
        let mut writer = OutputWriter::new(
            &mut bytes,
            &summary,
            TargetPathLimit::declared(4096).unwrap(),
        )
        .unwrap();
        writer
            .event(&ObservationEvent::Alias(record.clone()))
            .unwrap();
        writer.finish().unwrap();
        let decode = |b: &[u8]| -> Result<OwnedObservation, CoreError> {
            let mut r = OutputReader::new(
                super::super::tests::Chunks(b, 1),
                b.len() as u64,
                &summary.worktree.target,
            )?;
            while r.next_event()?.is_some() {}
            r.finish()
        };
        for n in [0, 8, 12, 28, bytes.len() - 1] {
            assert!(decode(&bytes[..n]).is_err());
        }
        let mut changed = bytes.clone();
        let end = changed.len() - 1;
        changed[end] ^= 1;
        assert!(decode(&changed).is_err());
        let mut changed = bytes.clone();
        changed[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&changed).is_err());
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(decode(&changed).is_err());
        let mut writer = OutputWriter::new(
            Vec::new(),
            &summary,
            TargetPathLimit::declared(4096).unwrap(),
        )
        .unwrap();
        writer
            .event(&ObservationEvent::Alias(record.clone()))
            .unwrap();
        assert!(
            writer
                .event(&ObservationEvent::Entry {
                    group: EntryGroup::Staged,
                    entry: GitEntry {
                        path: record.path.clone(),
                        previous_path: None,
                        status: "M".into()
                    }
                })
                .is_err()
        );
        assert!(writer.finish().is_err());
        let mut writer = OutputWriter::new(
            Vec::new(),
            &summary,
            TargetPathLimit::declared(4096).unwrap(),
        )
        .unwrap();
        let mut wrong = record;
        wrong.membership = None;
        assert!(writer.event(&ObservationEvent::Alias(wrong)).is_err());
        assert!(
            OutputReader::new(
                bytes.as_slice(),
                bytes.len() as u64,
                &summary.worktree.target
            )
            .unwrap()
            .finish()
            .is_err(),
            "partial output granted summary"
        );
    }
    #[test]
    fn owned_output_uses_proof_store_bytes_and_releases_its_input_slot() {
        let dir = tempfile::tempdir().unwrap();
        let local =
            crate::connections::local::LocalConnection::open(dir.path().join("state")).unwrap();
        let lease = WorkspaceLeaseID([92; 16]);
        local.register(WorkspaceID([92; 16]), lease).unwrap();
        let owner = local.observation_owner(lease).unwrap();
        let (mut summary, mut record) = fixture();
        summary.worktree.target = local.identity.clone();
        record.path = TargetPath::PosixBytes(b"/alias".to_vec());
        let spool = local.git.observation_input(&owner).unwrap();
        let mut output = OutputWriter::new(
            std::io::BufWriter::with_capacity(65536, spool),
            &summary,
            TargetPathLimit::declared(libc::PATH_MAX as u32).unwrap(),
        )
        .unwrap();
        output.event(&ObservationEvent::Alias(record)).unwrap();
        let buffered = output.finish().unwrap();
        let input = buffered
            .into_inner()
            .map_err(|e| e.into_error())
            .unwrap()
            .seal()
            .unwrap();
        assert_eq!(
            local.git.observation_storage_stats().unwrap().bytes,
            input.len()
        );
        assert!(local.git.observation_input(&owner).is_err());
        let mut reader =
            OutputReader::new(input.reader().unwrap(), input.len(), &local.identity).unwrap();
        while reader.next_event().unwrap().is_some() {}
        assert_eq!(reader.wire_digest(), Some(input.digest));
        assert_eq!(reader.finish().unwrap(), summary);
        drop(input);
        assert_eq!(local.git.observation_storage_stats().unwrap().bytes, 0);
        local.git.observation_input(&owner).unwrap();
    }
}
