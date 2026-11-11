# buntrail-services

Filesystem, Git, terminal, search and connection services.

## Features

Version-checked writes, owned PTYs, Git inspection/mutation and verified remote connections.

## Usage

Add to your Cargo.toml after the initial registry release:

```toml
[dependencies]
buntrail-services = "0.3.0"
serde_json = "=1.0.154"
```

```rust
let services = buntrail_services::Services::new();
let error = services.call(&serde_json::json!({"command":"unknown"}));
assert!(error.is_err());
```

Rust 1.99.1 (edition 2024). Unix integration checks need Git, Python 3, zsh, and ripgrep 15.1.0. Install rg beside your executable for bundled discovery, or use the explicit search constructor. SSH, Docker and Podman are required only for their respective routes. SSH askpass and remote bootstrap require matching helper resources supplied by the embedding application.

```sh
cargo fetch
scripts/check.sh
```

## Technologies and support

Rust, Cargo. Typed filesystem/remote/terminal implementations are primarily Unix-only. Windows currently uses command services and ConPTY; Unix supervisors are unavailable there. Native Windows acceptance and full interactive remote authentication/bootstrap acceptance remain unverified. This is a development release, not a promise of desktop parity.

## Service interfaces

The typed contracts are `EnvironmentService`, `FileService`, `SearchService`,
`GitService`, `TerminalService`, `OperationService` and `WorkspaceLeaseService`.
Unix implementations provide verified connection/bootstrap/authentication,
encoding-aware documents, durable operation inspection and owned terminals.
Use the engine's document and Git admission coordinators for app mutations.
Uncertain outcomes require inspection of the same operation; never replay them.

### Blocking command interface

`Services::new().call(&request)` accepts JSON objects with a `command` field and
returns `Result<Value, String>`. Keep the service instance for session state and
run calls away from the GUI thread. The engine and helper supply error envelopes.
This dispatcher still exists; its retirement and the typed Windows migration are
not complete.

| Command | Input and result |
| --- | --- |
| `fs.read` | `path` → `{text,version}`; retain the opaque version for saving. |
| `fs.list` | `path` → `{entries:[{name,path,directory}]}`, sorted by name. |
| `fs.write` | `path,text,version` → save result with the new version. |
| `fs.create` | `path,text` → save result; refuses existing destinations, including symlinks. |
| `fs.mkdir` | `path`; creates one directory. |
| `fs.rename` | `path,to`; atomic no-clobber rename. |
| `fs.remove` | `path`; only files, symlinks or empty directories, without recursive deletion. |
| `git` | `root,args` → `{stdout,stderr,status,truncated}`; Unix accepts fixed typed read queries. |
| `search` | `root,query` → `{matches:[{path,line,text}],truncated}`; literal ripgrep search. |

Unix file commands delegate to the typed file service. Reads preserve encoding,
BOM and newlines and admit up to 64 MiB logical text (128 MiB + 4 encoded bytes).
Versions bind the file, target and codec, not just its contents. Mutation results
can include an operation receipt; filesystem operations do not universally return
null. Windows currently uses the UTF-8 command backend with a 64 MiB input limit
and content-digest versions. NUL-bearing binary content and paths the JSON
consumer cannot represent fail explicitly. Save As can supply `source_version`
to retain the source codec on Unix.

`terminal.start {root,shell?}` returns `{id}`. Subsequent `terminal.read`,
`terminal.write`, `terminal.resize {id,columns,rows}` and `terminal.close` require
that ID. Reads return lossless `bytes`, lossy `output`, `alive`, `drained` and
`truncated`; process exit alone is not output EOF. Writes accept exactly one
`text` string or `bytes` array (integers 0–255), at most 1 MiB. Reads drain at most
256 KiB and retain up to 4 MiB between reads. Unix uses PTYs; Windows uses ConPTY
and a kill-on-close Job Object. Closing ends the owned process groups/job, not
arbitrary detached Unix jobs.

### Direct remote sessions

`remote.start {transport:"ssh"|"docker"|"podman",target,helper?}` returns
`{id,instance}`. `remote.call {id,request}` sends a nested service request;
`remote.close {id}` closes the transport. Compare the helper `instance` before
reusing terminal IDs after reconnect. Protocol/transport failures remove the
connection; service errors keep it available. Nested remote transports are refused.

This direct route requires a preinstalled helper. SSH uses batch mode, a ten-second
connection timeout, and constrained literal target/helper identifiers;
Docker/Podman use literal `exec -i` arguments. Reply waits are 30 seconds, but
request writes still use blocking pipes. These limits describe the direct route,
not the typed connection/bootstrap APIs.

### Safety and limits

- Content comparison and advisory locks do not provide an atomic compare-and-swap
  against arbitrary noncooperating writers. Do not promise that they do. Metadata
  preservation depends on the backend; the direct file writer copies permissions,
  not every filesystem attribute.
- Direct search and non-Unix command Git capture are bounded to 4 MiB and
  30 seconds; direct search also caps results at 10,000 matches. Typed Unix Git
  uses a 512 KiB output limit and a 120-second deadline. Missing search executables and execution errors fail
  explicitly. Ripgrep's normal ignore/hidden-file behavior applies.
- Commands use literal arguments rather than shell interpolation. Git prompting is
  disabled in direct capture. Capture deadlines include pipes inherited by
  descendants, and readers are canceled and joined. This does not supervise
  detached Unix descendants or Windows non-terminal subprocess trees.
- A saved/recovered document is not proof of current remote identity. Keep target,
  runtime, version and operation ownership checks when reconnecting or recovering.


API documentation is built with `cargo doc --no-deps`. Public dependency types
remain in their originating Buntrail crates; depend on those crates directly
when constructing those types. No API stability beyond the declared 0.x version
is promised. See [release instructions](docs/releasing.md).

## Collaborators and contributing

Maintained by Bunga Mungil for the [Buntrail organization](https://github.com/buntrail).
Contributions are welcome through issues and small pull requests in
https://github.com/buntrail/buntrail-services. Read [CONTRIBUTING.md](CONTRIBUTING.md)
and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Contact: bungamungil@icloud.com.
Report vulnerabilities privately using [SECURITY.md](SECURITY.md).

## License

First-party code is [MIT licensed](LICENSE), Copyright (c) 2026 Bunga Mungil.
Third-party dependencies retain their own licenses. See
[third-party notices](THIRD_PARTY_NOTICES.md).

Terminal workspace layouts and launch descriptors are session-only. Workspace catalogs retain documents and verified ownership, but do not restore terminals after an application restart. Remote disconnect retention is independent of catalog persistence.
