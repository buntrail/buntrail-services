use buntrail_core::contracts::TerminalEvent;
use std::collections::VecDeque;
pub const BYTE_LIMIT: usize = 8 * 1024 * 1024;
pub const LINE_LIMIT: usize = 10_000;
pub const CHUNK_BYTES: usize = 8192;
/// A single replay store. Subscribers retain only a cursor, never another pending-byte queue.
#[derive(Default)]
pub(super) struct OutputBuffer {
    chunks: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    lines: usize,
    pub sequence: u64,
}
impl OutputBuffer {
    pub fn push(&mut self, bytes: &[u8]) {
        self.sequence += 1;
        self.bytes += bytes.len();
        self.lines += bytes.iter().filter(|b| **b == b'\n').count();
        self.chunks.push_back((self.sequence, bytes.to_vec()));
        while self.bytes > BYTE_LIMIT || self.lines > LINE_LIMIT || self.chunks.len() > 4096 {
            let (_, bytes) = self.chunks.pop_front().unwrap();
            self.bytes -= bytes.len();
            self.lines -= bytes.iter().filter(|b| **b == b'\n').count();
        }
    }
    pub fn after(&self, cursor: &mut u64) -> Option<TerminalEvent> {
        let first = self.chunks.front().map_or(self.sequence + 1, |(s, _)| *s);
        if *cursor + 1 < first {
            let event = TerminalEvent::Gap {
                first: *cursor + 1,
                last: first - 1,
            };
            *cursor = first - 1;
            return Some(event);
        }
        let (sequence, bytes) = self.chunks.iter().find(|(s, _)| *s > *cursor)?;
        *cursor = *sequence;
        Some(TerminalEvent::Output {
            sequence: *sequence,
            bytes: bytes.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_and_line_replay_limits_evict_oldest_with_exact_gap() {
        let mut bytes = OutputBuffer::default();
        for _ in 0..1152 {
            bytes.push(&[b'x'; CHUNK_BYTES]);
        }
        assert_eq!(bytes.bytes, BYTE_LIMIT);
        assert_eq!(bytes.lines, 0);
        let mut cursor = 0;
        assert_eq!(
            bytes.after(&mut cursor),
            Some(TerminalEvent::Gap {
                first: 1,
                last: 128
            })
        );
        let mut lines = OutputBuffer::default();
        for _ in 0..11 {
            lines.push(&[b'\n'; 1000]);
        }
        assert_eq!(lines.lines, LINE_LIMIT);
        assert_eq!(lines.bytes, LINE_LIMIT);
        let mut cursor = 0;
        assert_eq!(
            lines.after(&mut cursor),
            Some(TerminalEvent::Gap { first: 1, last: 1 })
        );
    }
}
