#[cfg(unix)]
#[test]
fn rust_owns_pty_resize_bytes_and_reaping() {
    use buntrail_services::Pty;
    use std::io::{Read, Write};
    for shell in ["/bin/bash", "/bin/zsh"] {
        let mut pty = Pty::spawn(shell, &["-c", "printf 'héllo'; stty size"], 31, 91).unwrap();
        let mut reader = pty.reader().unwrap();
        let mut result = Vec::new();
        let mut chunk = [0; 3];
        while let Ok(n) = reader.read(&mut chunk) {
            if n == 0 {
                break;
            }
            result.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("héllo"), "{text}");
        assert!(text.contains("31 91"), "{text}");
        assert!(pty.wait().unwrap().success());
    }
    let mut pty = Pty::spawn("/bin/bash", &["--noprofile", "--norc"], 24, 80).unwrap();
    pty.resize(40, 100).unwrap();
    pty.write_all(b"exit\n").unwrap();
    pty.stop().unwrap();
    assert!(pty.wait().is_ok());
}

#[cfg(unix)]
#[test]
fn pty_sustained_output_is_not_truncated() {
    use std::io::Read;
    let mut pty =
        buntrail_services::Pty::spawn("/bin/sh", &["-c", "head -c 1048576 /dev/zero"], 24, 80)
            .unwrap();
    let mut reader = pty.reader().unwrap();
    let mut total = 0;
    let mut bytes = [0; 37];
    while let Ok(n) = reader.read(&mut bytes) {
        if n == 0 {
            break;
        }
        assert!(bytes[..n].iter().all(|b| *b == 0));
        total += n;
    }
    assert_eq!(total, 1_048_576);
    assert!(pty.wait().unwrap().success());
}

#[cfg(unix)]
#[test]
#[ignore = "explicit local Codex CLI fixture; not available on generic CI"]
fn codex_cli_runs_inside_rust_pty() {
    use std::io::Read;
    let mut pty = buntrail_services::Pty::spawn("codex", &["--version"], 24, 80).unwrap();
    let mut bytes = Vec::new();
    let _ = pty.reader().unwrap().read_to_end(&mut bytes);
    let output = String::from_utf8(bytes).unwrap();
    assert!(output.contains("codex"), "{output}");
    assert!(pty.wait().unwrap().success());
    println!("PTY Codex: {}", output.trim());
}
