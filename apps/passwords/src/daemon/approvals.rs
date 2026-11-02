//! Asking the user before something uses the vault for another program: an SSH key
//! signing for `ssh`, a Nyx app asking for access. The daemon opens the Passwords
//! window's approval card (`nyx-passwords --approve`), which lists what's waiting
//! (`Approvals`) and answers (`Answer`); only the app's scope may do either. An
//! unanswered request is refused after a minute, and locking refuses them all.

use std::time::Duration;

use nyx_passwords_proto::Error as Code;
use serde::Serialize;
use serde_json::json;
use tokio::sync::oneshot;

use super::peer::Scope;
use super::vault::{Failure, Result, Vault, need};

/// How long a request waits for an answer.
const WAIT: Duration = Duration::from_secs(60);
/// Requests waiting at once; more are refused without asking.
const MAX_WAITING: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Deny,
    Once,
    /// Allowed until the vault locks (or the grant's own time runs out).
    Session,
}

/// What the card shows. All text is plain; the window escapes it.
#[derive(Debug, Clone, Serialize)]
pub struct Question {
    pub title: String,
    pub detail: String,
    /// Who asks, as the kernel says: the program's path.
    pub program: String,
    /// The button for allowing this once.
    pub once_label: String,
    /// The button for allowing until the vault locks (or the grant's time), where offered.
    pub session_label: Option<String>,
}

#[derive(Default)]
pub struct Approvals {
    next: u64,
    waiting: Vec<(u64, Question, oneshot::Sender<Answer>)>,
}

impl Approvals {
    /// Refuses everything waiting (on lock).
    pub fn deny_all(&mut self) {
        for (_, _, reply) in self.waiting.drain(..) {
            let _ = reply.send(Answer::Deny);
        }
    }
}

impl Vault {
    /// Asks the user and waits for the answer; Deny when nobody answers in time, the
    /// window can't open, or too much is already waiting.
    pub(super) async fn ask(&self, question: Question) -> Answer {
        let (send, receive) = oneshot::channel();
        let id = {
            let mut st = self.state.lock().await;
            if st.session.is_none() || st.approvals.waiting.len() >= MAX_WAITING {
                return Answer::Deny;
            }
            st.approvals.next += 1;
            let id = st.approvals.next;
            st.approvals.waiting.push((id, question, send));
            id
        };
        if let Some(app) = super::peer::allowed_dir().map(|d| d.join("nyx-passwords")) {
            let _ = std::process::Command::new(app)
                .arg("--approve")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
        let answer = tokio::time::timeout(WAIT, receive).await.ok().and_then(std::result::Result::ok).unwrap_or(Answer::Deny);
        self.state.lock().await.approvals.waiting.retain(|(i, _, _)| *i != id);
        answer
    }

    /// What's waiting for an answer, oldest first: JSON `[{id, title, detail, program,
    /// session_label}]`.
    pub async fn approvals(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let st = self.state.lock().await;
        let list: Vec<_> = st
            .approvals
            .waiting
            .iter()
            .map(|(id, q, _)| {
                json!({"id": id, "title": q.title, "detail": q.detail, "program": q.program,
                       "once_label": q.once_label, "session_label": q.session_label})
            })
            .collect();
        Ok(serde_json::Value::Array(list).to_string())
    }

    /// The user's answer: `deny`, `once` or `session`.
    pub async fn answer_approval(&self, scope: Scope, id: u64, answer: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let at = st.approvals.waiting.iter().position(|(i, _, _)| *i == id);
        let Some(at) = at else { return Err(Failure::new(Code::NotFound, "that request has gone")) };
        let session_offered = st.approvals.waiting[at].1.session_label.is_some();
        let answer = match answer {
            "once" => Answer::Once,
            "session" if session_offered => Answer::Session,
            "deny" => Answer::Deny,
            _ => return Err(Failure::new(Code::Failed, "not an answer")),
        };
        let (_, _, reply) = st.approvals.waiting.remove(at);
        let _ = reply.send(answer);
        Ok(())
    }
}
