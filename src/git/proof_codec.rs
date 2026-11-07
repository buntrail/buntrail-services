//! Bounded proof bodies. Transport owns authentication, credits, cancellation and deadlines.
use crate::files::io_error;
use buntrail_core::contracts::*;
use serde::ser::SerializeSeq;
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    io::{self, Read, Write},
};
const ORIGINAL: &[u8; 8] = b"BTORIG01";
const SCRATCH: usize = 65536;
// Production native Git scalar envelope, also larger than any legacy header scalar.
const SCALAR: u64 = 65536;
pub mod output;
fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid framed proof body")
}
fn invalid() -> CoreError {
    CoreError::new(ErrorCode::InvalidArgument, "invalid framed proof body")
}
#[derive(Clone, Copy)]
pub struct TargetPathLimit(u32);
impl TargetPathLimit {
    pub fn declared(value: u32) -> Result<Self, CoreError> {
        if matches!(value, 1024 | 4096) {
            Ok(Self(value))
        } else {
            Err(invalid())
        }
    }
}
const ALIASES: &[u8; 8] = b"BTALIS01";
pub fn write_aliases<'a>(
    out: &mut impl Write,
    target: &TargetIdentity,
    aliases: impl IntoIterator<Item = &'a FileRef>,
) -> Result<(), CoreError> {
    out.write_all(ALIASES).map_err(io_error)?;
    for file in aliases {
        if &file.target != target {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "alias target changed",
            ));
        }
        (|| -> io::Result<()> {
            tag(out, 1)?;
            bytes(out, path_bytes(&file.path)?)?;
            match &file.resolved_identity {
                None => tag(out, 0),
                Some(hint) => {
                    tag(out, 1)?;
                    bytes(out, hint)
                }
            }
        })()
        .map_err(codec_error)?;
    }
    Ok(())
}
pub struct AliasReader<'a, R> {
    input: Option<Input<R>>,
    target: &'a TargetIdentity,
    limit: TargetPathLimit,
}
impl<'a, R: Read> AliasReader<'a, R> {
    pub fn new(
        reader: R,
        length: u64,
        target: &'a TargetIdentity,
        limit: TargetPathLimit,
    ) -> Result<Self, CoreError> {
        let mut input = Input::new(reader, length);
        if &input.fixed::<8>().map_err(codec_error)? != ALIASES {
            return Err(invalid());
        }
        Ok(Self {
            input: Some(input),
            target,
            limit,
        })
    }
}
impl<R: Read> Iterator for AliasReader<'_, R> {
    type Item = Result<super::observation::CapturedAlias, CoreError>;
    fn next(&mut self) -> Option<Self::Item> {
        let input = self.input.as_mut()?;
        if input.remaining == 0 {
            return self
                .input
                .take()
                .unwrap()
                .finish()
                .err()
                .map(|e| Err(codec_error(e)));
        }
        let result = (|| -> Result<super::observation::CapturedAlias, CoreError> {
            if input.tag().map_err(codec_error)? != 1 {
                return Err(invalid());
            }
            let path = TargetPath::posix(input.bounded(self.limit.0 as u64).map_err(codec_error)?)?;
            let mut out = HashWriter(Sha256::new());
            (|| -> io::Result<()> {
                out.write_all(br#"{"target":"#)?;
                json(&mut out, self.target)?;
                out.write_all(br#","path":"#)?;
                json(&mut out, &path)?;
                out.write_all(br#","resolved_identity":"#)?;
                match input.tag()? {
                    0 => out.write_all(b"null")?,
                    1 => array(input, &mut out)?,
                    _ => return Err(malformed()),
                };
                out.write_all(b"}")
            })()
            .map_err(codec_error)?;
            Ok(super::observation::CapturedAlias {
                file: FileRef {
                    target: self.target.clone(),
                    path,
                    resolved_identity: None,
                },
                digest: out.0.finalize().into(),
            })
        })();
        if result.is_err() {
            self.input = None;
        }
        Some(result)
    }
}

fn codec_error(e: io::Error) -> CoreError {
    if matches!(
        e.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
    ) {
        invalid()
    } else {
        io_error(e)
    }
}

#[derive(Debug)]
pub struct OriginalIdentity {
    operation: OperationID,
    digest: [u8; 32],
    wire_digest: [u8; 32],
    length: u64,
    target: [u8; 32],
}
impl OriginalIdentity {
    pub fn operation(&self) -> OperationID {
        self.operation
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn wire_digest(&self) -> [u8; 32] {
        self.wire_digest
    }
    pub fn length(&self) -> u64 {
        self.length
    }
}
struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn json(out: &mut impl Write, value: &impl serde::Serialize) -> io::Result<()> {
    serde_json::to_writer(out, value).map_err(io::Error::other)
}
fn target_digest(target: &TargetIdentity) -> Result<[u8; 32], CoreError> {
    super::observation::serialized_digest(target)
}
fn bytes(out: &mut impl Write, b: &[u8]) -> io::Result<()> {
    out.write_all(&(b.len() as u64).to_be_bytes())?;
    out.write_all(b)
}
fn path_bytes(path: &TargetPath) -> io::Result<&[u8]> {
    match path {
        TargetPath::PosixBytes(b) => Ok(b),
        _ => Err(malformed()),
    }
}
fn tag(out: &mut impl Write, tag: u8) -> io::Result<()> {
    out.write_all(&[tag])
}

/// The target is omitted on wire only after comparing the complete actual target.
pub fn write_original(
    out: &mut impl Write,
    r: &GitMutationRequest,
    target: &TargetIdentity,
) -> Result<(), CoreError> {
    if &r.worktree.target != target {
        return Err(CoreError::new(
            ErrorCode::TargetChanged,
            "original request target changed",
        ));
    }
    (|| -> io::Result<()> {
        out.write_all(ORIGINAL)?;
        out.write_all(&r.operation.0)?;
        bytes(out, path_bytes(&r.worktree.canonical_path)?)?;
        bytes(out, &r.worktree.common_git_directory_identity)?;
        match &r.expected.head {
            GitHead::Branch { name, oid } => {
                tag(out, 0)?;
                bytes(out, name)?;
                bytes(out, oid.as_bytes())?;
            }
            GitHead::Detached(oid) => {
                tag(out, 1)?;
                bytes(out, oid.as_bytes())?;
            }
            GitHead::Unborn(name) => {
                tag(out, 2)?;
                bytes(out, name)?;
            }
        }
        out.write_all(&r.expected.index_fingerprint)?;
        out.write_all(&r.expected.worktree_fingerprint)?;
        match &r.command {
            GitMutation::Stage(paths) | GitMutation::Unstage(paths) => {
                tag(
                    out,
                    if matches!(r.command, GitMutation::Stage(_)) {
                        0
                    } else {
                        1
                    },
                )?;
                out.write_all(&(paths.len() as u64).to_be_bytes())?;
                for p in paths {
                    bytes(out, path_bytes(p)?)?;
                }
            }
            GitMutation::Commit { message } => {
                tag(out, 2)?;
                bytes(out, message.as_bytes())?;
            }
            GitMutation::Checkout { reference } => {
                tag(out, 3)?;
                bytes(out, reference)?;
            }
            GitMutation::Fetch { remote } => {
                tag(out, 4)?;
                bytes(out, remote)?;
            }
            GitMutation::Push { remote, reference }
            | GitMutation::PullFastForward { remote, reference } => {
                tag(
                    out,
                    if matches!(r.command, GitMutation::Push { .. }) {
                        5
                    } else {
                        6
                    },
                )?;
                bytes(out, remote)?;
                bytes(out, reference)?;
            }
        }
        Ok(())
    })()
    .map_err(codec_error)
}
struct Input<R> {
    reader: R,
    remaining: u64,
    hash: Sha256,
}
impl<R: Read> Read for Input<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let length = self.remaining.min(out.len() as u64) as usize;
        let n = self.reader.read(&mut out[..length])?;
        self.hash.update(&out[..n]);
        self.remaining -= n as u64;
        Ok(n)
    }
}
impl<R: Read> Input<R> {
    fn new(reader: R, length: u64) -> Self {
        Self {
            reader,
            remaining: length,
            hash: Sha256::new(),
        }
    }
    fn exact(&mut self, b: &mut [u8]) -> io::Result<()> {
        if b.len() as u64 > self.remaining {
            return Err(malformed());
        }
        self.reader.read_exact(b)?;
        self.hash.update(&*b);
        self.remaining -= b.len() as u64;
        Ok(())
    }
    fn fixed<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut b = [0; N];
        self.exact(&mut b)?;
        Ok(b)
    }
    fn tag(&mut self) -> io::Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }
    fn number(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }
    fn length(&mut self) -> io::Result<u64> {
        let n = self.number()?;
        if n > self.remaining {
            return Err(malformed());
        }
        Ok(n)
    }
    fn bounded(&mut self, maximum: u64) -> io::Result<Vec<u8>> {
        let n = self.length()?;
        if n > maximum {
            return Err(malformed());
        }
        let mut b = vec![0; n as usize];
        self.exact(&mut b)?;
        Ok(b)
    }
    fn string(&mut self) -> io::Result<String> {
        String::from_utf8(self.bounded(SCALAR)?).map_err(|_| malformed())
    }
    fn finish(mut self) -> io::Result<[u8; 32]> {
        if self.remaining != 0 || self.reader.read(&mut [0; 1])? != 0 {
            return Err(malformed());
        }
        Ok(self.hash.finalize().into())
    }
}
struct ByteSequence<'a, R> {
    input: RefCell<&'a mut Input<R>>,
    length: u64,
}
impl<R: Read> serde::Serialize for ByteSequence<'_, R> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error;
        let mut seq = s.serialize_seq(None)?;
        let mut input = self.input.borrow_mut();
        let mut left = self.length;
        let mut scratch = [0; SCRATCH];
        while left > 0 {
            let n = left.min(SCRATCH as u64) as usize;
            input.exact(&mut scratch[..n]).map_err(S::Error::custom)?;
            for b in &scratch[..n] {
                seq.serialize_element(b)?;
            }
            left -= n as u64;
        }
        seq.end()
    }
}
fn array<R: Read>(input: &mut Input<R>, out: &mut impl Write) -> io::Result<()> {
    let length = input.length()?;
    json(
        out,
        &ByteSequence {
            input: RefCell::new(input),
            length,
        },
    )
}
fn posix<R: Read>(input: &mut Input<R>, out: &mut impl Write) -> io::Result<()> {
    out.write_all(br#"{"PosixBytes":"#)?;
    array(input, out)?;
    out.write_all(b"}")
}
fn string<R: Read>(input: &mut Input<R>, out: &mut impl Write) -> io::Result<()> {
    let mut left = input.length()?;
    let mut scratch = [0; SCRATCH];
    let mut pending = [0; 4];
    let mut used = 0;
    let mut needed = 0;
    out.write_all(b"\"")?;
    while left > 0 {
        let n = left.min(SCRATCH as u64) as usize;
        input.exact(&mut scratch[..n])?;
        left -= n as u64;
        for &b in &scratch[..n] {
            if used > 0 {
                pending[used] = b;
                used += 1;
                if used == needed {
                    std::str::from_utf8(&pending[..used]).map_err(|_| malformed())?;
                    out.write_all(&pending[..used])?;
                    used = 0;
                }
                continue;
            }
            match b {
                b'"' => out.write_all(b"\\\"")?,
                b'\\' => out.write_all(b"\\\\")?,
                8 => out.write_all(b"\\b")?,
                9 => out.write_all(b"\\t")?,
                10 => out.write_all(b"\\n")?,
                12 => out.write_all(b"\\f")?,
                13 => out.write_all(b"\\r")?,
                0..=31 => {
                    const HEX: &[u8] = b"0123456789abcdef";
                    out.write_all(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(b >> 4) as usize],
                        HEX[(b & 15) as usize],
                    ])?;
                }
                32..=127 => out.write_all(&[b])?,
                0xc2..=0xdf => {
                    pending[0] = b;
                    used = 1;
                    needed = 2;
                }
                0xe0..=0xef => {
                    pending[0] = b;
                    used = 1;
                    needed = 3;
                }
                0xf0..=0xf4 => {
                    pending[0] = b;
                    used = 1;
                    needed = 4;
                }
                _ => return Err(malformed()),
            }
        }
    }
    if used != 0 {
        return Err(malformed());
    }
    out.write_all(b"\"")
}
/// Reads the complete bounded body; no filesystem/proof state is consulted.
/// Caller must supply a deadline/cancellation-aware reader and verify its transport seal.
pub fn hash_original(
    reader: impl Read,
    length: u64,
    operation: OperationID,
    target: &TargetIdentity,
) -> Result<OriginalIdentity, CoreError> {
    let mut input = Input::new(reader, length);
    let mut out = HashWriter(Sha256::new());
    (|| -> io::Result<()> {
        if &input.fixed::<8>()? != ORIGINAL || input.fixed::<16>()? != operation.0 {
            return Err(malformed());
        }
        out.write_all(br#"{"operation":"#)?;
        json(&mut out, &operation)?;
        out.write_all(br#","worktree":{"target":"#)?;
        json(&mut out, target)?;
        out.write_all(br#","canonical_path":"#)?;
        posix(&mut input, &mut out)?;
        out.write_all(br#","common_git_directory_identity":"#)?;
        array(&mut input, &mut out)?;
        out.write_all(br#"},"expected":{"head":"#)?;
        match input.tag()? {
            0 => {
                out.write_all(br#"{"Branch":{"name":"#)?;
                array(&mut input, &mut out)?;
                out.write_all(br#","oid":"#)?;
                string(&mut input, &mut out)?;
                out.write_all(b"}}")?;
            }
            1 => {
                out.write_all(br#"{"Detached":"#)?;
                string(&mut input, &mut out)?;
                out.write_all(b"}")?;
            }
            2 => {
                out.write_all(br#"{"Unborn":"#)?;
                array(&mut input, &mut out)?;
                out.write_all(b"}")?;
            }
            _ => return Err(malformed()),
        }
        out.write_all(br#","index_fingerprint":"#)?;
        json(&mut out, &input.fixed::<32>()?)?;
        out.write_all(br#","worktree_fingerprint":"#)?;
        json(&mut out, &input.fixed::<32>()?)?;
        out.write_all(br#"},"command":"#)?;
        match input.tag()? {
            kind @ (0 | 1) => {
                out.write_all(if kind == 0 {
                    br#"{"Stage":["#
                } else {
                    br#"{"Unstage":["#
                })?;
                let count = input.number()?;
                if count > input.remaining / 8 {
                    return Err(malformed());
                }
                for i in 0..count {
                    if i > 0 {
                        out.write_all(b",")?;
                    }
                    posix(&mut input, &mut out)?;
                }
                out.write_all(b"]}")?;
            }
            2 => {
                out.write_all(br#"{"Commit":{"message":"#)?;
                string(&mut input, &mut out)?;
                out.write_all(b"}}")?;
            }
            3 => {
                out.write_all(br#"{"Checkout":{"reference":"#)?;
                array(&mut input, &mut out)?;
                out.write_all(b"}}")?;
            }
            4 => {
                out.write_all(br#"{"Fetch":{"remote":"#)?;
                array(&mut input, &mut out)?;
                out.write_all(b"}}")?;
            }
            kind @ (5 | 6) => {
                out.write_all(if kind == 5 {
                    br#"{"Push":{"remote":"#
                } else {
                    br#"{"PullFastForward":{"remote":"#
                })?;
                array(&mut input, &mut out)?;
                out.write_all(br#","reference":"#)?;
                array(&mut input, &mut out)?;
                out.write_all(b"}}")?;
            }
            _ => return Err(malformed()),
        }
        out.write_all(b"}")?;
        Ok(())
    })()
    .map_err(codec_error)?;
    let wire_digest = input.finish().map_err(codec_error)?;
    Ok(OriginalIdentity {
        operation,
        digest: out.0.finalize().into(),
        wire_digest,
        length,
        target: target_digest(target)?,
    })
}
/// Known-None/new-work pass only; input remains charged by the caller until close.
pub fn read_original(
    reader: impl Read,
    identity: &OriginalIdentity,
    target: &TargetIdentity,
) -> Result<GitMutationRequest, CoreError> {
    if identity.target != target_digest(target)? {
        return Err(invalid());
    }
    let mut input = Input::new(reader, identity.length);
    let request = (|| -> io::Result<GitMutationRequest> {
        if &input.fixed::<8>()? != ORIGINAL || input.fixed::<16>()? != identity.operation.0 {
            return Err(malformed());
        }
        let worktree = WorktreeIdentity {
            target: target.clone(),
            canonical_path: TargetPath::posix(input.bounded(SCALAR)?).map_err(|_| malformed())?,
            common_git_directory_identity: input.bounded(SCALAR)?,
        };
        let head = match input.tag()? {
            0 => GitHead::Branch {
                name: input.bounded(SCALAR)?,
                oid: input.string()?,
            },
            1 => GitHead::Detached(input.string()?),
            2 => GitHead::Unborn(input.bounded(SCALAR)?),
            _ => return Err(malformed()),
        };
        let expected = GitExpectedState {
            head,
            index_fingerprint: input.fixed()?,
            worktree_fingerprint: input.fixed()?,
        };
        let command = match input.tag()? {
            3 => GitMutation::Checkout {
                reference: input.bounded(SCALAR)?,
            },
            6 => GitMutation::PullFastForward {
                remote: input.bounded(SCALAR)?,
                reference: input.bounded(SCALAR)?,
            },
            _ => return Err(malformed()),
        };
        Ok(GitMutationRequest {
            operation: identity.operation,
            worktree,
            expected,
            command,
        })
    })()
    .map_err(codec_error)?;
    if input.finish().map_err(codec_error)? != identity.wire_digest
        || super::observation::serialized_digest(&request)? != identity.digest
    {
        return Err(invalid());
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    fn target() -> TargetIdentity {
        TargetIdentity {
            security_binding: vec![0, 255],
            effective_user: b"user".to_vec(),
            filesystem_namespace: vec![1],
            container: None,
        }
    }
    pub(super) fn original() -> GitMutationRequest {
        GitMutationRequest {
            operation: OperationID([1; 16]),
            worktree: WorktreeIdentity {
                target: target(),
                canonical_path: TargetPath::PosixBytes(b"/repo\xff".to_vec()),
                common_git_directory_identity: vec![0, 128, 255],
            },
            expected: GitExpectedState {
                head: GitHead::Unborn(b"main".to_vec()),
                index_fingerprint: [2; 32],
                worktree_fingerprint: [3; 32],
            },
            command: GitMutation::Checkout {
                reference: vec![b'x'; 65536],
            },
        }
    }
    pub(super) struct Chunks<'a>(pub(super) &'a [u8], pub(super) usize);
    impl Read for Chunks<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = out.len().min(self.0.len()).min(self.1);
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }
    #[test]
    fn original_codec_is_exact_core_serde_for_every_head_and_command() {
        let text: String = (0..=127)
            .map(char::from)
            .chain("é水🦀\u{2028}".chars())
            .collect();
        let commands = vec![
            GitMutation::Stage(vec![
                TargetPath::PosixBytes(b"/a\xff".to_vec()),
                TargetPath::PosixBytes(b"/b".to_vec()),
            ]),
            GitMutation::Unstage(vec![]),
            GitMutation::Commit {
                message: text.clone(),
            },
            original().command,
            GitMutation::Fetch {
                remote: vec![0, 255],
            },
            GitMutation::Push {
                remote: vec![],
                reference: b"r".to_vec(),
            },
            GitMutation::PullFastForward {
                remote: b"origin".to_vec(),
                reference: vec![b'r'; 65536],
            },
        ];
        for head in [
            GitHead::Branch {
                name: vec![0, 255],
                oid: text.clone(),
            },
            GitHead::Detached(text.clone()),
            GitHead::Unborn(vec![]),
        ] {
            for command in &commands {
                let mut r = original();
                r.expected.head = head.clone();
                r.command = command.clone();
                let mut bytes = Vec::new();
                write_original(&mut bytes, &r, &target()).expect("original request must stream");
                let expected: [u8; 32] = Sha256::digest(serde_json::to_vec(&r).unwrap()).into();
                for chunk in [1, 7, 65536] {
                    let identity = hash_original(
                        Chunks(&bytes, chunk),
                        bytes.len() as u64,
                        r.operation,
                        &target(),
                    )
                    .unwrap();
                    assert_eq!(identity.digest, expected, "{head:?}/{command:?}");
                    assert_eq!(
                        identity.wire_digest,
                        <[u8; 32]>::from(Sha256::digest(&bytes))
                    );
                    if matches!(
                        command,
                        GitMutation::Checkout { .. } | GitMutation::PullFastForward { .. }
                    ) {
                        assert_eq!(
                            read_original(Chunks(&bytes, chunk), &identity, &target()).unwrap(),
                            r
                        );
                    } else {
                        assert!(read_original(bytes.as_slice(), &identity, &target()).is_err());
                    }
                }
            }
        }
    }
    #[test]
    fn original_codec_rejects_truncation_extra_bytes_wrong_op_and_changed_replay() {
        let mut r = original();
        r.command = GitMutation::Checkout {
            reference: b"branch".to_vec(),
        };
        let mut bytes = Vec::new();
        write_original(&mut bytes, &r, &target()).unwrap();
        for n in 0..bytes.len() {
            assert!(
                hash_original(&bytes[..n], n as u64, r.operation, &target()).is_err(),
                "truncation {n}"
            );
        }
        let identity =
            hash_original(bytes.as_slice(), bytes.len() as u64, r.operation, &target()).unwrap();
        assert!(
            hash_original(
                bytes.as_slice(),
                bytes.len() as u64,
                OperationID([2; 16]),
                &target()
            )
            .is_err()
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(
            hash_original(extra.as_slice(), extra.len() as u64, r.operation, &target()).is_err()
        );
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(read_original(bytes.as_slice(), &identity, &target()).is_err());
        let mut foreign = target();
        foreign.effective_user.push(1);
        assert!(write_original(&mut Vec::new(), &r, &foreign).is_err());
        assert!(read_original(extra.as_slice(), &identity, &foreign).is_err());
    }
    #[test]
    fn original_codec_rejects_overflow_tags_and_invalid_utf8_across_scratch_boundary() {
        let mut r = original();
        r.expected.head = GitHead::Detached(format!("{}é", "a".repeat(65535)));
        let mut bytes = Vec::new();
        write_original(&mut bytes, &r, &target()).unwrap();
        assert_eq!(
            hash_original(
                Chunks(&bytes, 3),
                bytes.len() as u64,
                r.operation,
                &target()
            )
            .unwrap()
            .digest,
            <[u8; 32]>::from(Sha256::digest(serde_json::to_vec(&r).unwrap()))
        );
        let at = bytes.windows(2).position(|b| b == "é".as_bytes()).unwrap();
        for bad in [[0xc0, 0xaf], [0xc3, 0], [0xed, 0xa0], [0x80, 0x80]] {
            let mut changed = bytes.clone();
            changed[at..at + 2].copy_from_slice(&bad);
            assert!(
                hash_original(
                    Chunks(&changed, 1),
                    changed.len() as u64,
                    r.operation,
                    &target()
                )
                .is_err()
            );
        }
        let head_tag = 8 + 16 + 8 + 6 + 8 + 3;
        let mut changed = bytes.clone();
        changed[head_tag] = 255;
        assert!(
            hash_original(
                changed.as_slice(),
                changed.len() as u64,
                r.operation,
                &target()
            )
            .is_err()
        );
        let command_tag = bytes.len() - 65536 - 8 - 1;
        let mut changed = bytes.clone();
        changed[command_tag] = 255;
        assert!(
            hash_original(
                changed.as_slice(),
                changed.len() as u64,
                r.operation,
                &target()
            )
            .is_err()
        );
        bytes[24..32].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(
            hash_original(bytes.as_slice(), bytes.len() as u64, r.operation, &target()).is_err()
        );
    }
    #[test]
    fn alias_codec_preserves_none_empty_large_hints_and_non_utf8_paths() {
        let target = target();
        let aliases: Vec<_> = [None, Some(vec![]), Some(vec![255; 3 * 65536 + 7])]
            .into_iter()
            .map(|resolved_identity| FileRef {
                target: target.clone(),
                path: TargetPath::PosixBytes(b"/alias\xff".to_vec()),
                resolved_identity,
            })
            .collect();
        let mut bytes = Vec::new();
        write_aliases(&mut bytes, &target, aliases.iter()).expect("aliases must stream");
        let decoded: Vec<_> = AliasReader::new(
            Chunks(&bytes, 7),
            bytes.len() as u64,
            &target,
            TargetPathLimit::declared(4096).unwrap(),
        )
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
        assert_eq!(decoded.len(), 3);
        for (a, b) in aliases.iter().zip(decoded) {
            assert_eq!(b.path(), &a.path);
            assert_eq!(
                b.reference_digest(),
                <[u8; 32]>::from(Sha256::digest(serde_json::to_vec(a).unwrap()))
            );
        }
        for n in [0, 7, 9, 16, bytes.len() - 1] {
            assert!(
                AliasReader::new(
                    &bytes[..n],
                    n as u64,
                    &target,
                    TargetPathLimit::declared(4096).unwrap()
                )
                .and_then(|r| r.collect::<Result<Vec<_>, _>>())
                .is_err()
            );
        }
        let mut foreign = target.clone();
        foreign.effective_user.push(1);
        assert!(write_aliases(&mut Vec::new(), &foreign, aliases.iter()).is_err());
        for at in [8, 17 + 7] {
            let mut changed = bytes.clone();
            changed[at] = 255;
            assert!(
                AliasReader::new(
                    changed.as_slice(),
                    changed.len() as u64,
                    &target,
                    TargetPathLimit::declared(4096).unwrap()
                )
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .is_err()
            );
        }
        let mut changed = bytes.clone();
        changed[9..17].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(
            AliasReader::new(
                changed.as_slice(),
                changed.len() as u64,
                &target,
                TargetPathLimit::declared(4096).unwrap()
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .is_err()
        );
        assert!(
            AliasReader::new(
                ALIASES.as_slice(),
                8,
                &target,
                TargetPathLimit::declared(4096).unwrap()
            )
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .is_empty()
        );
    }
}
