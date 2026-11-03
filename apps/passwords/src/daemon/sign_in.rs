//! Confirming it's the person at the screen, through Nyx Biometrics, before Glimpse copies
//! from an item that asks for the master password again.
//!
//! The daemon asks polkit about itself with Nyx Biometrics' `app-action` ("authenticate as
//! yourself"). The system's authentication dialog takes the face,
//! fingerprint, security key or password the computer is set up for; nothing here sees
//! which. Without Nyx Biometrics the item stays as before: Passwords only.

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

/// Whether the person confirmed. Blocks until the dialog is answered. Polkit lets only
/// root pass a message of its own, so the dialog shows the action's ("Confirm it's you to
/// allow this").
pub fn confirm() -> bool {
    if let Some(answer) = test_answer() {
        return answer;
    }
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
