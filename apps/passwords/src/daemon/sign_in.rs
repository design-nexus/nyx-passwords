//! Confirming it's the person at the screen, through Nyx Biometrics, before Glimpse copies
//! from an item that asks for the master password again.
//!
//! The daemon asks polkit about itself with Nyx Biometrics' `app-action` ("authenticate as
//! yourself"). The system's authentication dialog shows the message and takes the face,
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

/// One short, plain line for the dialog.
fn message(what: &str, item: &str) -> String {
    let item: String = item.chars().filter(|c| !c.is_control()).take(60).collect();
    format!("Glimpse wants to copy the {what} for “{}”", item.trim())
}

/// Whether the person confirmed. Blocks until the dialog is answered.
pub fn confirm(what: &str, item: &str) -> bool {
    if let Some(answer) = test_answer() {
        return answer;
    }
    let Some(subject) = subject() else { return false };
    Command::new(PKCHECK)
        .args(["--action-id", ACTION, "--process", &subject, "--allow-user-interaction"])
        .args(["--detail", "polkit.message", &message(what, item)])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    #[test]
    fn messages_are_one_short_line() {
        assert_eq!(super::message("password", "Bank"), "Glimpse wants to copy the password for “Bank”");
        let long = super::message("password", &format!("{}\nINJECTED", "x".repeat(200)));
        assert!(!long.contains('\n'));
        assert!(long.chars().count() < 110);
    }

    #[test]
    fn subject_names_this_process() {
        let s = super::subject().unwrap();
        assert!(s.starts_with(&format!("{},", std::process::id())));
        assert_eq!(s.split(',').count(), 3);
    }
}
