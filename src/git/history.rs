use super::{adapter::LocalGitService, process};
use crate::files::io_error;
use buntrail_core::contracts::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    sync::atomic::AtomicBool,
    time::Instant,
};

const PAGE_SIZE: usize = 200;
#[derive(Serialize, Deserialize)]
struct Cursor {
    query: [u8; 32],
    tips: Vec<String>,
    offset: u64,
    lanes: Vec<Option<String>>,
    edges: Vec<(String, String)>,
}
fn oid(value: &[u8]) -> Result<String, CoreError> {
    if !matches!(value.len(), 40 | 64) || !value.iter().all(u8::is_ascii_hexdigit) {
        return Err(io_error("Invalid history object ID"));
    }
    Ok(String::from_utf8_lossy(value).into_owned())
}
fn lane(lanes: &mut Vec<Option<String>>, oid: &str) -> usize {
    if let Some(i) = lanes.iter().position(|v| v.as_deref() == Some(oid)) {
        return i;
    }
    let i = lanes
        .iter()
        .position(Option::is_none)
        .unwrap_or(lanes.len());
    if i == lanes.len() {
        lanes.push(None);
    }
    lanes[i] = Some(oid.to_owned());
    i
}
impl LocalGitService {
    pub fn history_sync(
        &self,
        query: HistoryQuery,
        cancel: &AtomicBool,
    ) -> Result<GraphPage, CoreError> {
        let root = self.validate(&query.worktree, cancel)?;
        if query.ref_filter.len() > 16
            || query
                .ref_filter
                .iter()
                .any(|r| r.is_empty() || r.len() > 4096 || r.contains(&0))
        {
            return Err(CoreError::new(
                ErrorCode::InvalidArgument,
                "Choose at most 16 bounded history refs",
            ));
        }
        let filter = query.filter.as_ref();
        if filter.is_some_and(|f| f.text.len() > 4096) {
            return Err(io_error("History filter exceeds 4096 bytes"));
        }
        let fingerprint: [u8; 32] = Sha256::digest(
            match filter {
                Some(filter) => serde_json::to_vec(&(&query.worktree, &query.ref_filter, filter)),
                None => serde_json::to_vec(&(&query.worktree, &query.ref_filter)),
            }
            .map_err(io_error)?,
        )
        .into();
        let mut cursor = if let Some(bytes) = query.cursor {
            if bytes.len() > 65536 {
                return Err(io_error("History cursor exceeds bound"));
            }
            let c: Cursor =
                serde_json::from_slice(&bytes).map_err(|_| io_error("Invalid history cursor"))?;
            if c.query != fingerprint
                || c.tips.len() > 16
                || c.lanes.len() > 512
                || c.edges.len() > 512
                || c.tips
                    .iter()
                    .chain(c.lanes.iter().flatten())
                    .any(|s| oid(s.as_bytes()).is_err())
                || c.edges
                    .iter()
                    .any(|(a, b)| oid(a.as_bytes()).is_err() || oid(b.as_bytes()).is_err())
            {
                return Err(io_error("History cursor does not match this query"));
            }
            c
        } else {
            let filters = if query.ref_filter.is_empty() {
                vec![b"HEAD".to_vec()]
            } else {
                query.ref_filter.clone()
            };
            let mut tips = vec![];
            for reference in filters {
                let mut args = process::args(&["rev-parse", "--verify", "--end-of-options"]);
                args.push(
                    OsStr::from_bytes(&[reference.as_slice(), b"^{commit}"].concat()).to_owned(),
                );
                let output = process::run(&root, &args, cancel)?;
                if !output.success
                    && query.ref_filter.is_empty()
                    && matches!(self.state(&root, cancel)?.head, GitHead::Unborn(_))
                {
                    continue;
                }
                let bytes = output.checked()?;
                tips.push(oid(bytes
                    .strip_suffix(b"\n")
                    .ok_or_else(|| io_error("Incomplete history tip"))?)?);
            }
            Cursor {
                query: fingerprint,
                tips,
                offset: 0,
                lanes: vec![],
                edges: vec![],
            }
        };
        if cursor.tips.is_empty() {
            return Ok(GraphPage {
                commits: vec![],
                continuation_edges: vec![],
                next_cursor: None,
            });
        }
        let raw_refs = self.command(
            &root,
            &process::args(&[
                "for-each-ref",
                "--format=%(objectname)%00%(*objectname)%00%(refname)%00",
            ]),
            cancel,
        )?;
        let mut decorations: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        for line in raw_refs.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
            let fields: Vec<_> = line.split(|b| *b == 0).collect();
            if fields.len() != 4 {
                return Err(io_error("Invalid history decorations"));
            }
            let id = oid(if fields[1].is_empty() {
                fields[0]
            } else {
                fields[1]
            })?;
            decorations.entry(id).or_default().push(fields[2].to_vec());
        }
        let started = Instant::now();
        let needle = filter.map(|f| f.text.to_lowercase()).unwrap_or_default();
        let mut selected: Vec<Vec<Vec<u8>>> = vec![];
        let mut scanned = cursor.offset;
        let more = 'scan: loop {
            if started.elapsed() >= process::DEADLINE {
                return Err(io_error("History filtering exceeded deadline; narrow refs"));
            }
            let mut args = process::args(&[
                "log",
                "--topo-order",
                "-z",
                "--no-show-signature",
                "--format=%H%x00%P%x00%s%x00%an%x00%aI%x00%B%x00%at",
            ]);
            args.push(format!("--max-count={}", PAGE_SIZE + 1).into());
            args.push(format!("--skip={scanned}").into());
            args.extend(cursor.tips.iter().map(OsString::from));
            args.push("--".into());
            let raw = self.command(&root, &args, cancel)?;
            let fields: Vec<_> = raw.split(|b| *b == 0).collect();
            if fields.last() != Some(&&b""[..]) || (fields.len() - 1) % 7 != 0 {
                return Err(io_error("Incomplete history page"));
            }
            let rows = fields[..fields.len() - 1].as_chunks::<7>().0;
            for row in rows {
                let authored = std::str::from_utf8(row[6])
                    .map_err(io_error)?
                    .parse::<i64>()
                    .map_err(io_error)?;
                let matches_date = filter
                    .and_then(|f| f.authored_since)
                    .is_none_or(|since| authored >= since);
                let matches_text = needle.is_empty()
                    || [row[0], row[3], row[5]]
                        .iter()
                        .any(|v| String::from_utf8_lossy(v).to_lowercase().contains(&needle));
                if matches_date && matches_text {
                    if selected.len() == PAGE_SIZE {
                        break 'scan true;
                    }
                    selected.push(row[..6].iter().map(|v| v.to_vec()).collect());
                }
                scanned = scanned
                    .checked_add(1)
                    .ok_or_else(|| io_error("History offset exhausted"))?;
            }
            if rows.len() < PAGE_SIZE + 1 {
                break false;
            }
        };
        let mut commits = vec![];
        for owned in &selected {
            let fields = owned.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let id = oid(fields[0])?;
            let parents: Vec<_> = fields[1]
                .split(|b| *b == b' ')
                .filter(|s| !s.is_empty())
                .map(oid)
                .collect::<Result<_, _>>()?;
            // Filtered pages omit intermediate parents; those are not unresolved graph lanes.
            let (current, parent_lanes) = if filter.is_none() {
                let current = lane(&mut cursor.lanes, &id);
                cursor.lanes[current] = None;
                let mut parent_lanes = vec![];
                for parent in &parents {
                    let p = if parent_lanes.is_empty()
                        && !cursor.lanes.iter().any(|v| v.as_ref() == Some(parent))
                    {
                        cursor.lanes[current] = Some(parent.clone());
                        current
                    } else {
                        lane(&mut cursor.lanes, parent)
                    };
                    parent_lanes.push(p as u32);
                    cursor.edges.push((id.clone(), parent.clone()));
                }
                (current, parent_lanes)
            } else {
                cursor.lanes.clear();
                cursor.edges.clear();
                (0, vec![])
            };
            commits.push(GraphCommit {
                oid: id.clone(),
                parents,
                decorations: decorations.remove(&id).unwrap_or_default(),
                subject: String::from_utf8_lossy(fields[2]).into_owned(),
                lane: current as u32,
                parent_lanes,
                author: String::from_utf8_lossy(fields[3]).into_owned(),
                authored_at: String::from_utf8_lossy(fields[4]).into_owned(),
                message: String::from_utf8_lossy(fields[5]).into_owned(),
            });
        }
        let known: HashSet<_> = commits.iter().map(|c| c.oid.as_str()).collect();
        cursor.edges.retain(|(_, to)| !known.contains(to.as_str()));
        let continuation_edges = cursor.edges.clone();
        cursor.offset = scanned;
        let next_cursor = if more {
            let bytes = serde_json::to_vec(&cursor).map_err(io_error)?;
            if bytes.len() > 65536 || cursor.lanes.len() > 512 || cursor.edges.len() > 512 {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "History topology exceeds bound; narrow refs",
                ));
            }
            Some(bytes)
        } else {
            None
        };
        Ok(GraphPage {
            commits,
            continuation_edges,
            next_cursor,
        })
    }
}
