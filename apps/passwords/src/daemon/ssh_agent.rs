//! The SSH agent: `$XDG_RUNTIME_DIR/nyx-passwords/ssh-agent.sock`, for `SSH_AUTH_SOCK`.
//! It offers only the SSH key items turned on for it, only while the vault is open and
//! "SSH agent" is on in the settings. Each signature needs the user's approval in the
//! Passwords window, once or until the vault locks, per key and program. Private keys
//! never leave the daemon; adding keys, removing them and the rest of the protocol are
//! refused.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use nyx_passwords_core::model::Kind;
use nyx_passwords_core::ssh;
use nyx_passwords_core::ssh_agent::{self as protocol, Request};
use nyx_passwords_core::vault::{reveal_for_use, sub_field};
use nyx_passwords_proto::Error as Code;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

use super::approvals::{Answer, Question};
use super::peer::Scope;
use super::vault::{Failure, Result, State, Vault, locked, need, parse_id};

/// Where the keys turned on for the agent are kept, encrypted with the user key.
const KEYS_KEPT: &str = "ssh_agent_keys";

/// Listens on the agent socket for as long as the daemon runs.
pub async fn serve(vault: Arc<Vault>, socket: PathBuf) {
    let _ = std::fs::remove_file(&socket);
    let Ok(listener) = UnixListener::bind(&socket) else {
        eprintln!("nyx-passwordsd: couldn't listen on {}", socket.display());
        return;
    };
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(client(stream, vault.clone()));
    }
}

/// Who connected: the program's path and its command line, for the approval card.
fn caller(stream: &UnixStream) -> Option<(PathBuf, String)> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the sizes given.
    let rc = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &raw mut len)
    };
    // SAFETY: getuid has no preconditions.
    if rc != 0 || cred.uid != unsafe { libc::getuid() } {
        return None;
    }
    let exe = std::fs::read_link(format!("/proc/{}/exe", cred.pid)).unwrap_or_else(|_| PathBuf::from("an unknown program"));
    let raw = std::fs::read(format!("/proc/{}/cmdline", cred.pid)).unwrap_or_default();
    let mut command: String = String::from_utf8_lossy(&raw).split('\0').filter(|a| !a.is_empty()).collect::<Vec<_>>().join(" ");
    if command.chars().count() > 160 {
        command = command.chars().take(160).collect::<String>() + "…";
    }
    Some((exe, command))
}

async fn client(mut stream: UnixStream, vault: Arc<Vault>) {
    // Another user's programs never get an answer.
    let Some((exe, command)) = caller(&stream) else { return };
    loop {
        let mut prefix = [0u8; 4];
        if stream.read_exact(&mut prefix).await.is_err() {
            return;
        }
        let Some(len) = protocol::frame_len(prefix) else { return };
        let mut frame = vec![0u8; len];
        if stream.read_exact(&mut frame).await.is_err() {
            return;
        }
        let reply = match protocol::parse(&frame) {
            Some(Request::Identities) => protocol::identities(&vault.agent_keys().await),
            Some(Request::Sign { key, data, flags }) => match vault.agent_sign(&key, &data, flags, &exe, &command).await {
                Some(signature) => protocol::signed(&signature),
                None => protocol::failure(),
            },
            Some(Request::Other(_)) | None => protocol::failure(),
        };
        if stream.write_all(&reply).await.is_err() {
            return;
        }
    }
}

/// The ids of the keys turned on for the agent.
fn turned_on(st: &State) -> Vec<Uuid> {
    let Some(session) = st.session.as_ref() else { return Vec::new() };
    let Some(stored) = st.store.setting(KEYS_KEPT).ok().flatten() else { return Vec::new() };
    let plain = session.keys.item(None, None).and_then(|mut k| k.decrypt(&stored));
    plain.ok().and_then(|p| serde_json::from_str(p.expose()).ok()).unwrap_or_default()
}

/// A key the agent may offer: an SSH key item, live, readable, whose organization
/// doesn't hide its secrets and that doesn't ask for the master password.
struct Offered {
    id: Uuid,
    name: String,
    blob: Vec<u8>,
    fingerprint: String,
}

fn offered(st: &State) -> Vec<Offered> {
    let Some(session) = st.session.as_ref() else { return Vec::new() };
    if !st.settings.current.ssh_agent {
        return Vec::new();
    }
    let field = |id, name| sub_field(name).and_then(|f| reveal_for_use(&session.keys, &session.snapshot, id, f).ok());
    turned_on(st)
        .into_iter()
        .filter_map(|id| session.view.get(id))
        .filter(|e| e.kind == Kind::SshKey && !e.deleted && e.readable && e.view_password && !e.reprompt)
        .filter_map(|e| {
            let public = field(e.id, "ssh.publicKey")?;
            let blob = ssh::blob_from_public(public.expose()).ok()?;
            let fingerprint = field(e.id, "ssh.keyFingerprint").map(|f| f.expose().to_string()).unwrap_or_default();
            Some(Offered { id: e.id, name: e.name.expose().to_string(), blob, fingerprint })
        })
        .collect()
}

impl Vault {
    /// The keys offered to SSH clients: public blob and comment (the item's name).
    async fn agent_keys(&self) -> Vec<(Vec<u8>, String)> {
        let mut st = self.state.lock().await;
        st.settings.refresh();
        offered(&st).into_iter().map(|k| (k.blob, k.name)).collect()
    }

    /// Signs for a client, if the key is offered and the user allows it (or allowed it
    /// for this program until the vault locks).
    async fn agent_sign(&self, blob: &[u8], data: &[u8], flags: u32, exe: &Path, command: &str) -> Option<Vec<u8>> {
        let key = {
            let mut st = self.state.lock().await;
            st.settings.refresh();
            offered(&st).into_iter().find(|k| k.blob == blob)?
        };
        let allowed = self.state.lock().await.ssh_allowed.contains(&(key.id, exe.to_path_buf()));
        if !allowed {
            let who = if command.is_empty() { exe.display().to_string() } else { command.to_string() };
            let question = Question {
                title: format!("Use the SSH key “{}”?", key.name),
                detail: format!("{who} asks to sign in with it ({}).", key.fingerprint),
                program: exe.display().to_string(),
                once_label: "Allow once".into(),
                session_label: Some("Allow until locked".into()),
            };
            match self.ask(question).await {
                Answer::Deny => {
                    let st = self.state.lock().await;
                    super::grants::record(&st, &exe.display().to_string(), "sign with SSH key", Some(key.id), "denied");
                    return None;
                }
                Answer::Once => {}
                Answer::Session => {
                    self.state.lock().await.ssh_allowed.insert((key.id, exe.to_path_buf()));
                }
            }
        }
        let signature = {
            let mut st = self.state.lock().await;
            let session = st.session.as_ref()?;
            let private = reveal_for_use(&session.keys, &session.snapshot, key.id, sub_field("ssh.privateKey")?).ok()?;
            let signature = ssh::sign(private.expose(), data, flags).ok()?;
            st.last_used = Instant::now();
            super::grants::record(&st, &exe.display().to_string(), "sign with SSH key", Some(key.id), "done");
            signature
        };
        if allowed {
            // Allowed without asking: a notification keeps the use visible.
            self.notifier.send(&format!("SSH key “{}” used", key.name), &exe.display().to_string()).await;
        }
        Some(signature)
    }

    /// The SSH key items turned on for the agent, as a JSON list of ids.
    pub async fn ssh_agent_keys(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let st = self.state.lock().await;
        st.session.as_ref().ok_or_else(locked)?;
        Ok(json!(turned_on(&st)).to_string())
    }

    /// Turns a key on or off for the agent. Turning one off also ends what was allowed
    /// for it until the vault locks.
    pub async fn set_ssh_agent_key(&self, scope: Scope, id: &str, on: bool) -> Result<()> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let mut st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let e = session.view.get(id).ok_or_else(|| Failure::new(Code::NotFound, "no such item"))?;
        if e.kind != Kind::SshKey {
            return Err(Failure::new(Code::Failed, "only SSH keys can be used by the agent"));
        }
        let mut ids = turned_on(&st);
        ids.retain(|i| *i != id);
        if on {
            ids.push(id);
        }
        let session = st.session.as_ref().ok_or_else(locked)?;
        let text = serde_json::to_string(&ids).unwrap_or_default();
        let encrypted = session
            .keys
            .item(None, None)
            .and_then(|mut k| k.encrypt(&text))
            .map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        st.store.set_setting(KEYS_KEPT, &encrypted).map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        if !on {
            st.ssh_allowed.retain(|(key, _)| *key != id);
        }
        Ok(())
    }
}
