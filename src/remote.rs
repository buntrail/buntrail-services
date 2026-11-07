//! Persistent protocol-1 helper connections over literal transport arguments.
use super::*;
use std::{
    io::BufReader,
    process::{Child, ChildStdin},
    sync::mpsc::{self, Receiver},
};
const MAX_FRAME: usize = 8 * 1024 * 1024;

pub struct Session {
    child: Child,
    input: ChildStdin,
    replies: Receiver<Result<Value, String>>,
    healthy: bool,
    instance: String,
}
fn transport(request: &Value) -> Result<Command, String> {
    let target = string(request, "target")?;
    // SSH runs its remote command through a shell; keep that command to a single literal executable.
    if target.is_empty()
        || target.starts_with('-')
        || !target
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._@-:".contains(&c))
    {
        return Err("target must be a literal host or container identifier".into());
    }
    let helper = request
        .get("helper")
        .map(|v| v.as_str().ok_or("helper must be a string"))
        .transpose()?
        .unwrap_or("buntrail-helper");
    if helper.is_empty()
        || helper.starts_with('-')
        || !helper
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c))
    {
        return Err("helper must be a literal executable path without shell syntax".into());
    }
    let mut command = match string(request, "transport")? {
        "ssh" => {
            let mut c = Command::new("ssh");
            c.args([
                "-T",
                "-oBatchMode=yes",
                "-oConnectTimeout=10",
                "--",
                target,
                helper,
            ]);
            c
        }
        kind @ ("docker" | "podman") => {
            let mut c = Command::new(kind);
            c.args(["exec", "-i", "--", target, helper]);
            c
        }
        _ => return Err("transport must be ssh, docker, or podman".into()),
    };
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    Ok(command)
}
impl Session {
    pub fn start(request: &Value) -> Result<Self, String> {
        let mut child = transport(request)?
            .spawn()
            .map_err(|e| format!("remote transport unavailable: {e}"))?;
        let input = child.stdin.take().ok_or("remote input unavailable")?;
        let stdout = child.stdout.take().ok_or("remote output unavailable")?;
        let (send, replies) = mpsc::sync_channel(2);
        std::thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let result = read_frame(&mut stdout);
                let failed = result.is_err();
                if send.send(result).is_err() || failed {
                    break;
                }
            }
        });
        let mut session = Self {
            child,
            input,
            replies,
            healthy: true,
            instance: String::new(),
        };
        let handshake = session.exchange(&json!({"protocol":1}))?;
        if handshake["protocol"] != 1 {
            return Err("remote protocol mismatch".into());
        }
        session.instance = handshake["instance"]
            .as_str()
            .ok_or("remote helper instance is missing")?
            .to_owned();
        Ok(session)
    }
    pub fn call(&mut self, request: &Value) -> Result<Value, String> {
        self.exchange(request)
    }
    pub fn healthy(&self) -> bool {
        self.healthy
    }
    pub fn instance(&self) -> &str {
        &self.instance
    }
    fn exchange(&mut self, request: &Value) -> Result<Value, String> {
        let bytes = serde_json::to_vec(request).map_err(error)?;
        if bytes.is_empty() || bytes.len() > MAX_FRAME {
            return Err("remote request exceeds frame limit".into());
        }
        self.healthy = false;
        self.input
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .map_err(error)?;
        self.input.write_all(&bytes).map_err(error)?;
        self.input.flush().map_err(error)?;
        let reply = self
            .replies
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| "remote helper timed out or disconnected")??;
        if !reply["ok"].is_boolean() {
            return Err("remote response is missing boolean ok".into());
        }
        self.healthy = true;
        if reply["ok"] == true {
            reply
                .get("value")
                .cloned()
                .ok_or_else(|| "remote response is missing value".into())
        } else {
            Err(reply["error"]["message"]
                .as_str()
                .unwrap_or("remote helper rejected request")
                .to_owned())
        }
    }
}
fn read_frame(input: &mut impl Read) -> Result<Value, String> {
    let mut length = [0; 4];
    input.read_exact(&mut length).map_err(error)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err("invalid remote frame length".into());
    }
    let mut bytes = vec![0; length];
    input.read_exact(&mut bytes).map_err(error)?;
    serde_json::from_slice(&bytes).map_err(error)
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transports_reject_interpolation_and_option_injection() {
        for target in [
            "-oProxyCommand=bad",
            "host; touch bad",
            "$(bad)",
            "host\nother",
        ] {
            assert!(transport(&json!({"transport":"ssh","target":target})).is_err());
        }
        assert!(
            transport(
                &json!({"transport":"ssh","target":"example.invalid","helper":"helper; bad"})
            )
            .is_err()
        );
        let command = transport(&json!({"transport":"ssh","target":"user@example.invalid","helper":"/tmp/buntrail-helper"})).unwrap();
        let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "-T",
                "-oBatchMode=yes",
                "-oConnectTimeout=10",
                "--",
                "user@example.invalid",
                "/tmp/buntrail-helper"
            ]
        );
        let docker = transport(&json!({"transport":"docker","target":"test-container"})).unwrap();
        assert_eq!(docker.get_program(), "docker");
        assert_eq!(
            docker.get_args().collect::<Vec<_>>(),
            ["exec", "-i", "--", "test-container", "buntrail-helper"]
        );
    }
    #[test]
    fn remote_frames_reject_untrusted_lengths_and_invalid_json() {
        assert!(read_frame(&mut [0, 0, 0, 0].as_slice()).is_err());
        assert!(read_frame(&mut (MAX_FRAME as u32 + 1).to_be_bytes().as_slice()).is_err());
        assert!(read_frame(&mut [0, 0, 0, 1, b'{'].as_slice()).is_err());
        assert_eq!(
            read_frame(&mut [0, 0, 0, 4, b'n', b'u', b'l', b'l'].as_slice()).unwrap(),
            Value::Null
        );
    }
}
