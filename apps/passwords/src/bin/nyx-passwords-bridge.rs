//! The Native Messaging host (docs/NATIVE_MESSAGING.md). A browser starts it for its
//! extension and talks on stdin/stdout: a 32-bit native-endian length, then JSON. Each
//! frame goes to the daemon unchanged (`Relay`) and the answer comes back. It reads
//! nothing in the frames and keeps nothing: after pairing they're sealed between the
//! extension and the daemon.

use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use nyx_passwords_proto as proto;

/// Frames from the browser larger than this end the connection.
const MAX_IN: usize = 64 * 1024;
/// Chromium refuses messages to the extension over 1 MiB.
const MAX_OUT: usize = 1024 * 1024;
/// The frame in hand when the bridge starts again on a new build.
const PENDING: &str = "NYX_PASSWORDS_BRIDGE_PENDING";

fn main() {
    // Firefox passes the manifest path and the extension id; Chromium the extension's
    // origin (chrome-extension://ID/).
    let args: Vec<String> = std::env::args().skip(1).collect();
    let caller = args.iter().find(|a| a.starts_with("chrome-extension://")).or_else(|| args.last()).cloned().unwrap_or_default();
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(_) => std::process::exit(1),
    };
    // Unbuffered: nothing the browser sent may be left in a buffer when the bridge
    // starts again on a new build.
    // SAFETY: fd 0 is stdin, open for the life of the process and used only here.
    let mut stdin = unsafe { std::fs::File::from_raw_fd(0) };
    let mut stdout = std::io::stdout().lock();
    let mut conn: Option<zbus::Connection> = None;
    let mut pending = std::env::var(PENDING).ok().and_then(|f| base64::engine::general_purpose::STANDARD.decode(f).ok());
    while let Some(frame) = pending.take().or_else(|| read_frame(&mut stdin)) {
        let reply = rt.block_on(relay(&mut conn, &caller, frame));
        if reply.len() > MAX_OUT || write_frame(&mut stdout, &reply).is_err() {
            break;
        }
    }
}

fn read_frame(input: &mut impl Read) -> Option<Vec<u8>> {
    let mut len = [0u8; 4];
    input.read_exact(&mut len).ok()?;
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_IN {
        return None;
    }
    let mut frame = vec![0u8; len];
    input.read_exact(&mut frame).ok()?;
    Some(frame)
}

fn write_frame(output: &mut impl Write, frame: &[u8]) -> std::io::Result<()> {
    output.write_all(&(frame.len() as u32).to_ne_bytes())?;
    output.write_all(frame)?;
    output.flush()
}

async fn relay(conn: &mut Option<zbus::Connection>, caller: &str, frame: Vec<u8>) -> Vec<u8> {
    for attempt in 0..2 {
        if conn.is_none() {
            // An update restarts the daemon, which refuses a bridge whose binary was
            // replaced; this one carries on as the new build instead.
            if let Some(exe) = replaced() {
                start_again(&exe, &frame);
            }
            *conn = connect().await;
        }
        let Some(c) = conn.as_ref() else { break };
        let reply = c.call_method(None::<&str>, proto::OBJECT_PATH, Some(proto::INTERFACE), "Relay", &(caller, &frame)).await;
        match reply {
            Ok(msg) => {
                if let Ok(bytes) = msg.body().deserialize::<Vec<u8>>() {
                    return bytes;
                }
                break;
            }
            // The daemon restarted: connect again once.
            Err(zbus::Error::InputOutput(_)) if attempt == 0 => *conn = None,
            Err(zbus::Error::MethodError(name, _, _)) => {
                let code = proto::Error::from_name(name.as_str()).map_or("Failed", |e| e.short());
                return format!(r#"{{"t":"error","error":"{code}"}}"#).into_bytes();
            }
            Err(_) => {
                *conn = None;
                break;
            }
        }
    }
    br#"{"t":"unavailable"}"#.to_vec()
}

/// This program's path, if the binary there was replaced since it started.
fn replaced() -> Option<PathBuf> {
    let exe = std::fs::read_link("/proc/self/exe").ok()?;
    let path = PathBuf::from(exe.to_str()?.strip_suffix(" (deleted)")?);
    path.is_file().then_some(path)
}

/// Runs the new build in this process, with the same browser pipes and arguments and
/// the frame in hand. Returns only if that failed.
fn start_again(exe: &Path, frame: &[u8]) {
    use std::os::unix::process::CommandExt;
    let _ = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(PENDING, base64::engine::general_purpose::STANDARD.encode(frame))
        .exec();
}

/// Connects to the daemon, starting it if needed (its unit, or the one next to this
/// binary in a checkout).
async fn connect() -> Option<zbus::Connection> {
    let socket = proto::socket_path()?;
    for attempt in 0..30 {
        if let Ok(stream) = tokio::net::UnixStream::connect(&socket).await {
            let build = zbus::connection::Builder::unix_stream(stream).p2p().build();
            return tokio::time::timeout(Duration::from_secs(5), build).await.ok()?.ok();
        }
        if attempt == 0 {
            start_daemon();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

fn start_daemon() {
    let quiet = |c: &mut std::process::Command| {
        c.env_remove(PENDING);
        c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    };
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".config")));
    if config.is_some_and(|c| c.join("systemd/user").join(proto::SERVICE).exists()) {
        let mut c = std::process::Command::new("systemctl");
        c.args(["--user", "start", proto::SERVICE]);
        quiet(&mut c);
        let _ = c.spawn();
    } else if let Some(sibling) = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("nyx-passwordsd"))) {
        let mut c = std::process::Command::new(sibling);
        quiet(&mut c);
        let _ = c.spawn();
    }
}
