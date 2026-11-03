//! Confirming it's the person at the screen, through Nyx Biometrics, before Glimpse copies
//! from an item that asks for the master password again.
//!
//! The daemon asks Nyx Biometrics' sign-in broker (`nyx-authd`) under the `vault` policy:
//! the broker knows the daemon from its bus connection, applies the policy, shows the
//! system's prompt (face, fingerprint, security key or password, as the computer is set
//! up; nothing here sees which) and keeps an audit line. An older Nyx Biometrics without
//! the broker gets the same prompt from polkit directly (`app-action`). Without Nyx
//! Biometrics the item stays as before: Passwords only.

use std::process::{Command, Stdio};

const ACTION: &str = "io.github.design_nexus.nyx.auth.app-action";
const ACTIONS: &str = "/usr/share/polkit-1/actions/io.github.design_nexus.nyx.auth.unlock.policy";
const PKCHECK: &str = "/usr/bin/pkcheck";

pub fn available() -> bool {
    test_answer().is_some() || std::fs::read_to_string(ACTIONS).is_ok_and(|t| t.contains(ACTION))
}

/// Debug builds only: the daemon tests answer for the person with a file ("yes" or "no")
/// named by `NYX_PW_TEST_SIGN_IN`.
fn test_answer() -> Option<bool> {
    if !cfg!(debug_assertions) {
        return None;
    }
    let text = std::fs::read_to_string(std::env::var_os("NYX_PW_TEST_SIGN_IN")?).ok()?;
    Some(text.trim() == "yes")
}

/// "pid,start-time,uid" for this process, so polkit can't be pointed at a reused pid.
fn subject() -> Option<String> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let start: u64 = stat[stat.rfind(')')? + 1..].split_whitespace().nth(19)?.parse().ok()?;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    Some(format!("{},{start},{uid}", std::process::id()))
}

/// Whether the person confirmed, waiting until the prompt is answered.
pub async fn confirm() -> bool {
    if let Some(answer) = test_answer() {
        return answer;
    }
    match broker().await {
        Ok(reply) => reply.outcome == nyx_auth_proto::Outcome::Granted,
        // No broker on this computer (or no session bus): ask polkit directly.
        Err(_) => tokio::task::spawn_blocking(polkit).await.unwrap_or(false),
    }
}

async fn broker() -> zbus::Result<nyx_auth_proto::Reply> {
    use nyx_auth_proto::{AuthProxy, Request, Surface};
    let conn = zbus::Connection::session().await?;
    AuthProxy::new(&conn)
        .await?
        .authenticate(Request {
            action: "io.github.design_nexus.nyx.passwords.copy-protected".into(),
            purpose: "Copy from a protected item in Glimpse".into(),
            surface: Surface::Vault,
            grant_secs: 0,
        })
        .await
}

/// Polkit lets only root pass a message of its own, so the dialog shows the action's
/// ("Confirm it's you to allow this").
fn polkit() -> bool {
    let Some(subject) = subject() else { return false };
    Command::new(PKCHECK)
        .args(["--action-id", ACTION, "--process", &subject, "--allow-user-interaction"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    #[test]
    fn subject_names_this_process() {
        let s = super::subject().unwrap();
        assert!(s.starts_with(&format!("{},", std::process::id())));
        assert_eq!(s.split(',').count(), 3);
    }
}
