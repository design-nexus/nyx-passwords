//! Access for other Nyx apps, granted by the user. An app (`Scope::Requester`: a `nyx-*`
//! program next to the daemon, identified as every peer is) can do nothing until it
//! asks (`RequestAccess`) for some of:
//!
//! - `search`: find logins by name and site (names, usernames, sites; no secrets);
//! - `copy`: put a login's username, password or code on the clipboard (never back).
//!
//! The user answers in the approval card: allow for the time asked (at most a week), or
//! allow but ask before each copy. Grants are kept encrypted with the user key, so no
//! file edit can make one, and can be revoked in Settings. No method returns a secret to
//! an app. Every use by another program (apps, Glimpse, the Assistant, SSH) goes into an
//! activity log, also encrypted, with item ids and outcomes only.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nyx_passwords_core::vault::{Field, reveal};
use nyx_passwords_proto::{Error as Code, Item, field};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use uuid::Uuid;

use super::approvals::{Answer, Question, plain};
use super::peer::Scope;
use super::vault::{Failure, Result, State, Vault, denied, item, locked, need, parse_id, within};

const GRANTS: &str = "grants";
const ACTIVITY: &str = "activity";
/// Events kept in the activity log, newest last.
const ACTIVITY_KEPT: usize = 500;
/// After a refusal, how long before the same app may ask again.
const ASK_AGAIN_AFTER: std::time::Duration = std::time::Duration::from_secs(60);
/// The longest an app may ask for.
const MAX_MINUTES: u32 = 7 * 24 * 60;
const APP_COPIES_PER_MINUTE: usize = 10;
const REASON_MAX: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Grant {
    pub app: String,
    pub search: bool,
    pub copy: bool,
    /// Each copy asks first.
    pub ask_each_copy: bool,
    /// Seconds since the epoch.
    pub granted: u64,
    pub expires: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Event {
    at: u64,
    who: String,
    what: String,
    item: Option<Uuid>,
    outcome: String,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A value kept beside the vault, encrypted with the user key.
fn load<T: DeserializeOwned + Default>(st: &State, name: &str) -> T {
    let Some(session) = st.session.as_ref() else { return T::default() };
    let Some(stored) = st.store.setting(name).ok().flatten() else { return T::default() };
    let plain = session.keys.item(None, None).and_then(|mut k| k.decrypt(&stored));
    plain.ok().and_then(|p| serde_json::from_str(p.expose()).ok()).unwrap_or_default()
}

fn save<T: Serialize>(st: &State, name: &str, value: &T) -> Result<()> {
    let session = st.session.as_ref().ok_or_else(locked)?;
    let text = serde_json::to_string(value).map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
    let encrypted = session
        .keys
        .item(None, None)
        .and_then(|mut k| k.encrypt(&text))
        .map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
    st.store.set_setting(name, &encrypted).map_err(|e| Failure::new(Code::Failed, e.to_string()))
}

/// Grants still in force.
fn grants(st: &State) -> Vec<Grant> {
    let mut list: Vec<Grant> = load(st, GRANTS);
    let t = now();
    list.retain(|g| g.expires > t);
    list
}

fn grant_for(st: &State, app: &str) -> Option<Grant> {
    grants(st).into_iter().find(|g| g.app == app)
}

/// Adds an event to the activity log. Never a value or an item's name; best effort.
pub(super) fn record(st: &State, who: &str, what: &str, item: Option<Uuid>, outcome: &str) {
    if st.session.is_none() {
        return;
    }
    let mut log: VecDeque<Event> = load(st, ACTIVITY);
    log.push_back(Event { at: now(), who: who.into(), what: what.into(), item, outcome: outcome.into() });
    while log.len() > ACTIVITY_KEPT {
        log.pop_front();
    }
    let _ = save(st, ACTIVITY, &log);
}

fn duration(minutes: u32) -> String {
    match minutes {
        m if m % (24 * 60) == 0 => match m / (24 * 60) {
            1 => "a day".into(),
            d => format!("{d} days"),
        },
        m if m % 60 == 0 => match m / 60 {
            1 => "an hour".into(),
            h => format!("{h} hours"),
        },
        m => format!("{m} minutes"),
    }
}

impl Vault {
    /// An app asks for access: `scopes` is a JSON list of `search` and `copy`, `reason`
    /// what it's for (shown as the app's words), `minutes` how long (at most a week).
    /// JSON `{granted, ask_each_copy, expires}`.
    pub async fn request_access(&self, scope: Scope, app: &str, scopes: &str, reason: &str, minutes: u32) -> Result<String> {
        need(scope, Scope::Requester)?;
        let wanted: Vec<String> =
            serde_json::from_str(scopes).map_err(|_| Failure::new(Code::Failed, "scopes must be a JSON list"))?;
        if wanted.is_empty() || wanted.iter().any(|s| s != "search" && s != "copy") {
            return Err(Failure::new(Code::Failed, "scopes are \"search\" and \"copy\""));
        }
        let minutes = minutes.clamp(1, MAX_MINUTES);
        let (search, copy) = (wanted.iter().any(|s| s == "search"), wanted.iter().any(|s| s == "copy"));
        {
            let st = self.state.lock().await;
            st.session.as_ref().ok_or_else(locked)?;
            if st.access_refused.get(app).is_some_and(|at| at.elapsed() < ASK_AGAIN_AFTER) {
                return Err(Failure::new(Code::RateLimited, "refused a moment ago; ask again later"));
            }
        }
        let reason = plain(reason, REASON_MAX);
        let mut abilities = Vec::new();
        if search {
            abilities.push("find logins by name and site (names, usernames and sites, never passwords)");
        }
        if copy {
            abilities.push("copy usernames, passwords and one-time codes to the clipboard (never to the app itself)");
        }
        let question = Question {
            title: format!("Let “{app}” use Passwords?"),
            detail: format!(
                "It asks to {} for {}.{}",
                abilities.join(" and to "),
                duration(minutes),
                if reason.is_empty() { String::new() } else { format!(" It says: “{reason}”") }
            ),
            program: app.to_string(),
            once_label: if copy { "Allow, asking before each copy".into() } else { "Allow".into() },
            session_label: copy.then(|| format!("Allow for {}", duration(minutes))),
        };
        let answer = self.ask(question).await;
        let mut st = self.state.lock().await;
        let outcome = if answer == Answer::Deny { "denied" } else { "granted" };
        record(&st, app, "asked for access", None, outcome);
        if answer == Answer::Deny {
            st.access_refused.insert(app.to_string(), Instant::now());
            return Ok(json!({"granted": false}).to_string());
        }
        let t = now();
        let grant = Grant {
            app: app.to_string(),
            search,
            copy,
            ask_each_copy: copy && answer == Answer::Once,
            granted: t,
            expires: t + u64::from(minutes) * 60,
        };
        let mut list = grants(&st);
        list.retain(|g| g.app != app);
        list.push(grant.clone());
        save(&st, GRANTS, &list)?;
        Ok(json!({"granted": true, "ask_each_copy": grant.ask_each_copy, "expires": grant.expires}).to_string())
    }

    /// The calling app's grant: JSON `{search, copy, ask_each_copy, expires}`, or `null`.
    pub async fn access_status(&self, scope: Scope, app: &str) -> Result<String> {
        need(scope, Scope::Requester)?;
        let st = self.state.lock().await;
        st.session.as_ref().ok_or_else(locked)?;
        Ok(match grant_for(&st, app) {
            Some(g) => json!({"search": g.search, "copy": g.copy, "ask_each_copy": g.ask_each_copy, "expires": g.expires}),
            None => serde_json::Value::Null,
        }
        .to_string())
    }

    /// Search for an app with a `search` grant: metadata only, as Glimpse gets.
    pub async fn app_search(&self, scope: Scope, app: &str, query: &str, limit: u32) -> Result<Vec<Item>> {
        need(scope, Scope::Requester)?;
        let st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        if !grant_for(&st, app).is_some_and(|g| g.search) {
            return Err(denied());
        }
        let query: String = query.chars().take(256).collect();
        Ok(session.view.search(&query, limit.min(50) as usize).into_iter().map(item).collect())
    }

    /// A copy for an app with a `copy` grant: username, password or code onto the
    /// clipboard. Asks first when the grant says so; refuses items that ask for the
    /// master password.
    pub async fn app_copy(self: &Arc<Self>, scope: Scope, app: &str, id: &str, field_name: &str) -> Result<u32> {
        need(scope, Scope::Requester)?;
        let wanted = match field_name {
            field::USERNAME => Field::Username,
            field::PASSWORD => Field::Password,
            field::TOTP => Field::Totp,
            _ => return Err(Failure::new(Code::NoField, "unknown field")),
        };
        let id = parse_id(id)?;
        let (grant, name) = {
            let mut st = self.state.lock().await;
            let session = st.session.as_ref().ok_or_else(locked)?;
            let entry =
                session.view.get(id).filter(|e| !e.deleted).ok_or_else(|| Failure::new(Code::NotFound, "no such item"))?;
            if entry.reprompt && wanted != Field::Username {
                return Err(Failure::new(Code::Reprompt, "this item asks for the master password: copy it in Passwords"));
            }
            let name = entry.name.expose().to_string();
            let grant = grant_for(&st, app).filter(|g| g.copy).ok_or_else(denied)?;
            let copies = st.app_copies.entry(app.to_string()).or_default();
            if !within(copies, APP_COPIES_PER_MINUTE) {
                return Err(Failure::new(Code::RateLimited, "too many copies; wait a minute"));
            }
            (grant, name)
        };
        let label = match wanted {
            Field::Username => "username",
            Field::Password => "password",
            _ => "one-time code",
        };
        if grant.ask_each_copy {
            let question = Question {
                title: format!("Let “{app}” copy a {label}?"),
                detail: format!("The {label} of “{name}” goes to the clipboard, not to the app."),
                program: app.to_string(),
                once_label: "Allow".into(),
                session_label: None,
            };
            if self.ask(question).await == Answer::Deny {
                record(&*self.state.lock().await, app, &format!("copy {label}"), Some(id), "denied");
                return Err(denied());
            }
        }
        let (value, settings) = {
            let mut st = self.state.lock().await;
            // Revoked, or the item changed, while the card was up.
            grant_for(&st, app).filter(|g| g.copy).ok_or_else(denied)?;
            let session = st.session.as_ref().ok_or_else(locked)?;
            let entry =
                session.view.get(id).filter(|e| !e.deleted).ok_or_else(|| Failure::new(Code::NotFound, "no such item"))?;
            if entry.reprompt && wanted != Field::Username {
                return Err(Failure::new(Code::Reprompt, "this item asks for the master password: copy it in Passwords"));
            }
            let value = reveal(&session.keys, &session.snapshot, id, wanted)?;
            st.last_used = Instant::now();
            super::vault::used(&mut st, id);
            record(&st, app, &format!("copy {label}"), Some(id), "done");
            (value, st.settings.refresh().clone())
        };
        let title = format!("{} copied for {app}", label[..1].to_uppercase() + &label[1..]);
        self.put_on_clipboard(value, &settings, &title).await
    }

    /// The grants in force: JSON `[{app, search, copy, ask_each_copy, granted, expires}]`.
    pub async fn list_grants(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let st = self.state.lock().await;
        st.session.as_ref().ok_or_else(locked)?;
        Ok(json!(grants(&st)).to_string())
    }

    pub async fn revoke_grant(&self, scope: Scope, app: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let st = self.state.lock().await;
        let mut list = grants(&st);
        list.retain(|g| g.app != app);
        save(&st, GRANTS, &list)?;
        record(&st, app, "access revoked", None, "done");
        Ok(())
    }

    /// The activity log, newest first: JSON `[{at, who, what, item, outcome}]`.
    pub async fn activity(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let st = self.state.lock().await;
        st.session.as_ref().ok_or_else(locked)?;
        let log: VecDeque<Event> = load(&st, ACTIVITY);
        Ok(json!(log.iter().rev().collect::<Vec<_>>()).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration(60), "an hour");
        assert_eq!(duration(120), "2 hours");
        assert_eq!(duration(24 * 60), "a day");
        assert_eq!(duration(MAX_MINUTES), "7 days");
        assert_eq!(duration(45), "45 minutes");
    }
}
