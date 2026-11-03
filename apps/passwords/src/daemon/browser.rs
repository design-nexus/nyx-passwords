//! Browser extensions (docs/NATIVE_MESSAGING.md): pairing, sealed messages, and the
//! few things a paired extension may ask for, each about the page it's on.
//!
//! The bridge relays frames and is trusted with nothing: every request after pairing
//! is sealed with the pairing key (AES-256-GCM, the pairing id and a counter as
//! associated data), and each counter is accepted once, within five minutes of now, so
//! a recorded request can't be replayed. Pairing keys are stored under the user key and
//! loaded on unlock; while locked an extension only learns that.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use nyx_passwords_core::crypto::{self, PairKey};
use nyx_passwords_core::edit::{LoginDraft, Place};
use nyx_passwords_core::matching;
use nyx_passwords_core::model::Kind;
use nyx_passwords_core::secret::Secret;
use nyx_passwords_core::store::Pairing;
use nyx_passwords_core::vault::{Field, reveal_for_use};
use nyx_passwords_proto::{Error as Code, state};
use serde_json::{Value, json};
use url::Url;

use super::peer::Scope;

use super::vault::{Failure, Result, State, Vault, generated, need, online, parse_id, within};

const MAX_FRAME: usize = 64 * 1024;
const PENDING_FOR: Duration = Duration::from_secs(120);
const MAX_PENDING: usize = 4;
const CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
/// Counters remembered per pairing: each is accepted once, and one may come a little
/// after a later one (the extension seals several requests at once).
const SEEN: usize = 64;
/// How long an extension's icon request waits for a fetch.
const ICON_WAIT: std::time::Duration = std::time::Duration::from_millis(250);
/// How often a paired extension may have the unlock window shown while locked.
const UNLOCK_EVERY: std::time::Duration = std::time::Duration::from_secs(5);
const FILLS_PER_MINUTE: usize = 30;
/// Usernames a pairing may ask for in a minute: each may make a real alias at a service.
const USERNAMES_PER_MINUTE: usize = 5;
const MATCHES: usize = 20;

#[derive(Default)]
pub struct Browser {
    pending: Vec<Pending>,
    active: HashMap<String, Active>,
    pub context: Option<Context>,
    /// When a paired extension last had the unlock window shown.
    unlock_shown: Option<Instant>,
}

struct Pending {
    id: String,
    extension: String,
    browser: String,
    key: PairKey,
    code: String,
    at: Instant,
}

struct Active {
    pairing: Pairing,
    key: PairKey,
    /// The latest `SEEN` counters.
    seen: BTreeSet<u64>,
    fills: VecDeque<Instant>,
    usernames: VecDeque<Instant>,
}

/// The tab a paired extension last said was active, in which browser process. It holds
/// until the extension reports another or the vault locks: the extension reports every
/// tab switch, navigation and window focus, so the last report is that browser's tab.
pub struct Context {
    pub url: Url,
    pub pid: i32,
}

impl Browser {
    /// Whether a pairing may fill, copy or change one more thing this minute.
    pub fn fills_left(&mut self, pairing: &str) -> bool {
        self.active.get_mut(pairing).is_some_and(|a| within(&mut a.fills, FILLS_PER_MINUTE))
    }

    /// On lock: keys and the active tab go; confirmed pairings stay stored.
    pub fn lock(&mut self) {
        self.pending.clear();
        self.active.clear();
        self.context = None;
    }
}

/// Opens the stored pairings' keys with the user key (after unlock).
pub fn load(st: &mut State) {
    let Some(session) = st.session.as_ref() else { return };
    let Ok(pairings) = st.store.pairings() else { return };
    for p in pairings {
        let key = session.keys.item(None, None).and_then(|mut k| k.decrypt(&p.key)).and_then(|plain| PairKey::import(&plain));
        if let Ok(key) = key {
            st.browser.active.insert(
                p.id.clone(),
                Active { pairing: p, key, seen: BTreeSet::new(), fills: VecDeque::new(), usernames: VecDeque::new() },
            );
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

fn random_id() -> String {
    let mut bytes = [0u8; 16];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn error(code: Code) -> Value {
    json!({"error": code.short()})
}

impl Vault {
    /// One frame from the bridge: `extension` is the id the browser started it for,
    /// `browser` the browser process (pid, name). Returns the reply frame.
    pub async fn relay(&self, scope: Scope, extension: &str, browser: &(i32, String), frame: &[u8]) -> Result<Vec<u8>> {
        need(scope, Scope::Browser)?;
        if frame.len() > MAX_FRAME {
            return Err(Failure::new(Code::Failed, "frame too large"));
        }
        let msg: Value = serde_json::from_slice(frame).map_err(|_| Failure::new(Code::Failed, "not JSON"))?;
        let reply = match msg["t"].as_str() {
            Some("hello") => self.hello(extension, &browser.1, &msg).await,
            Some("msg") => self.sealed(extension, browser, &msg).await,
            Some("unlock") => self.show_unlock(extension, &msg).await,
            _ => json!({"t": "error", "error": "unknown"}),
        };
        Ok(reply.to_string().into_bytes())
    }

    async fn hello(&self, extension: &str, browser: &str, msg: &Value) -> Value {
        let Some(public) = msg["pub"].as_str().and_then(unb64) else {
            return json!({"t": "error", "error": "bad key"});
        };
        let Ok(paired) = crypto::pair(&public) else {
            return json!({"t": "error", "error": "bad key"});
        };
        let id = random_id();
        {
            let mut st = self.state.lock().await;
            if st.session.is_none() {
                return json!({"t": "locked"});
            }
            st.browser.pending.retain(|p| p.at.elapsed() < PENDING_FOR);
            if st.browser.pending.len() >= MAX_PENDING {
                return json!({"t": "error", "error": "busy"});
            }
            st.browser.pending.push(Pending {
                id: id.clone(),
                extension: extension.to_string(),
                browser: browser.to_string(),
                key: paired.key,
                code: paired.code,
                at: Instant::now(),
            });
        }
        self.notifier.send(&format!("Pair {browser} with Passwords?"), "Open Passwords to compare the code and confirm.").await;
        json!({"t": "pairing", "p": id, "pub": b64(&paired.public)})
    }

    /// A paired extension asks for Passwords' unlock window. While the vault is locked its
    /// pairing key is locked too, so this one frame isn't sealed: it names a stored pairing
    /// of this extension, and can only show the window, where the user unlocks as usual
    /// (nothing comes back but whether it was shown), once every few seconds.
    async fn show_unlock(&self, extension: &str, msg: &Value) -> Value {
        let p = msg["p"].as_str().unwrap_or_default();
        let mut st = self.state.lock().await;
        if st.session.is_some() {
            return json!({"t": "unlocked"});
        }
        let paired = st.store.pairings().ok().is_some_and(|all| all.iter().any(|x| x.id == p && x.extension == extension));
        if !paired {
            return json!({"t": "unknown"});
        }
        if st.browser.unlock_shown.is_some_and(|at| at.elapsed() < UNLOCK_EVERY) {
            return json!({"t": "error", "error": "busy"});
        }
        st.browser.unlock_shown = Some(Instant::now());
        drop(st);
        launch_app(&["--unlock"]);
        json!({"t": "shown"})
    }

    async fn sealed(&self, extension: &str, browser: &(i32, String), msg: &Value) -> Value {
        let (Some(p), Some(n), Some(c)) = (msg["p"].as_str(), msg["n"].as_u64(), msg["c"].as_str().and_then(unb64)) else {
            return json!({"t": "error", "error": "malformed"});
        };
        let request = {
            let mut st = self.state.lock().await;
            let st = &mut *st;
            if st.browser.pending.iter().any(|x| x.id == p && x.at.elapsed() < PENDING_FOR) {
                return json!({"t": "pending"});
            }
            let Some(active) = st.browser.active.get_mut(p) else {
                let stored = st.store.pairings().ok().is_some_and(|all| all.iter().any(|x| x.id == p));
                return json!({"t": if stored && st.session.is_none() { "locked" } else { "unknown" }});
            };
            // A pairing belongs to one extension, and each counter is used once, near the
            // clock; anything older than the counters remembered is refused.
            let now = now_ms();
            let fresh =
                !active.seen.contains(&n) && (active.seen.len() < SEEN || active.seen.first().is_some_and(|&low| n > low));
            if active.pairing.extension != extension || !fresh || n.abs_diff(now) > CLOCK_SKEW_MS {
                return json!({"t": "error", "error": "rejected"});
            }
            let Ok(plain) = active.key.open(format!("{p}|{n}").as_bytes(), &c) else {
                return json!({"t": "error", "error": "rejected"});
            };
            active.seen.insert(n);
            if active.seen.len() > SEEN {
                active.seen.pop_first();
            }
            serde_json::from_slice::<Value>(plain.expose()).unwrap_or(Value::Null)
        };
        let answer = self.answer(p, browser, &request).await;
        let st = self.state.lock().await;
        let Some(active) = st.browser.active.get(p) else { return json!({"t": "unknown"}) };
        match active.key.seal(format!("{p}|{n}|r").as_bytes(), answer.to_string().as_bytes()) {
            Ok(sealed) => json!({"t": "msg", "p": p, "n": n, "c": b64(&sealed)}),
            Err(_) => json!({"t": "error", "error": "seal"}),
        }
    }

    /// Answers one opened request. Copies and usernames run without the vault lock held
    /// (the clipboard and alias services take their time).
    async fn answer(&self, pairing: &str, browser: &(i32, String), request: &Value) -> Value {
        let r = request["r"].as_str().unwrap_or_default();
        // A site that requires user verification gets a real one where Nyx Biometrics is
        // installed: the person confirms through its prompt (the face, as set up) before
        // anything is signed, without the vault held. Otherwise an unlocked vault counts,
        // as in the official clients.
        if matches!(r, "passkey.get" | "passkey.create")
            && request["uv"] == "required"
            && super::sign_in::available()
            && !super::sign_in::confirm(super::sign_in::Why::Passkey).await
        {
            return error(Code::Denied);
        }
        match r {
            "save" => save(&mut *self.state.lock().await, pairing, request).await,
            "add_uri" | "signin.save" | "passkey.create" => {
                super::extension::edit(&mut *self.state.lock().await, pairing, request).await
            }
            "copy" => self.browser_copy(pairing, request).await,
            "otp.match" | "otp.take" => self.browser_notified_code(pairing, request).await,
            "icon" => self.browser_icon(request).await,
            "lock" => {
                self.lock().await;
                json!({})
            }
            "username" => {
                {
                    let mut st = self.state.lock().await;
                    let Some(active) = st.browser.active.get_mut(pairing) else { return error(Code::Denied) };
                    if !within(&mut active.usernames, USERNAMES_PER_MINUTE) {
                        return error(Code::RateLimited);
                    }
                }
                let site = request["url"].as_str().unwrap_or_default();
                match self.generate_username(Scope::Browser, site).await {
                    Ok(made) => json!({"username": made.expose()}),
                    Err(f) => json!({"error": f.kind.short(), "message": f.message}),
                }
            }
            _ => handle(&mut *self.state.lock().await, pairing, browser, request),
        }
    }

    /// A site's icon for the popup, as a data URL: only for sites the vault has an item
    /// for, so the extension can't use the server's icon service for anything else.
    async fn browser_icon(&self, request: &Value) -> Value {
        let host = request["host"].as_str().unwrap_or_default().trim_start_matches("www.").to_ascii_lowercase();
        {
            let st = self.state.lock().await;
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            if host.is_empty() || !session.view.entries.iter().any(|e| e.host.as_deref() == Some(host.as_str())) {
                return error(Code::NotFound);
            }
        }
        // The extension's requests go one at a time: a slow fetch mustn't hold up the
        // ones behind it. It goes on, and the icon is there next time.
        match self.icon(Scope::App, &host, Some(ICON_WAIT)).await {
            Ok(bytes) => {
                let kind = if bytes.starts_with(b"\x89PNG") {
                    "image/png"
                } else if bytes.starts_with(b"\xff\xd8") {
                    "image/jpeg"
                } else if bytes.starts_with(b"GIF8") {
                    "image/gif"
                } else if bytes.starts_with(b"RIFF") {
                    "image/webp"
                } else {
                    "image/x-icon"
                };
                let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
                json!({"url": format!("data:{kind};base64,{data}")})
            }
            Err(f) => error(f.kind),
        }
    }

    /// Verification codes from notifications, held by Nyx Clipboard (`…Clipboard.Otp1`),
    /// for a one-time-code field: `otp.match` lists the ones that may be for the page
    /// (no codes), `otp.take` gets one. Clipboard decides which site a code is for and
    /// gives an unsure one only with `confirmed` (the user picked it in the menu). The
    /// same rules as `totp`: unlocked, the page's own site, the fill limit.
    async fn browser_notified_code(&self, pairing: &str, request: &Value) -> Value {
        let r = request["r"].as_str().unwrap_or_default();
        let Some(url) = request["url"].as_str().and_then(|u| Url::parse(u).ok()).filter(|u| matches!(u.scheme(), "http" | "https"))
        else {
            return error(Code::NoUrl);
        };
        if !frame_on_site(request, &url) {
            return error(Code::Denied);
        }
        {
            let mut st = self.state.lock().await;
            if st.session.is_none() {
                return error(Code::Locked);
            }
            if r == "otp.take" && !st.browser.fills_left(pairing) {
                return error(Code::RateLimited);
            }
        }
        let Ok(conn) = clipboard_bus().await else { return json!({"items": []}) };
        const BUS: &str = "io.github.design_nexus.nyx.Clipboard1";
        const PATH: &str = "/io/github/design_nexus/nyx/Clipboard1";
        const IFACE: &str = "io.github.design_nexus.nyx.Clipboard.Otp1";
        if r == "otp.match" {
            let reply = conn.call_method(Some(BUS), PATH, Some(IFACE), "Match", &(url.as_str(),)).await;
            let items = reply
                .ok()
                .and_then(|m| m.body().deserialize::<String>().ok())
                .and_then(|t| serde_json::from_str::<Vec<Value>>(&t).ok())
                .unwrap_or_default();
            let items: Vec<Value> = items
                .into_iter()
                .take(5)
                .map(|c| json!({"id": c["id"], "app": c["app"], "confidence": c["confidence"], "expires": c["expires"]}))
                .collect();
            return json!({"items": items});
        }
        let id = request["id"].as_str().unwrap_or_default();
        let confirmed = request["confirmed"] == true;
        let reply = conn.call_method(Some(BUS), PATH, Some(IFACE), "Take", &(id, url.as_str(), confirmed)).await;
        match reply.ok().and_then(|m| m.body().deserialize::<String>().ok()).and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
            Some(v) if v["code"].is_string() => json!({"code": v["code"], "confidence": v["confidence"]}),
            _ => error(Code::NotFound),
        }
    }

    /// Copies a login's username, password or one-time code through the daemon's
    /// clipboard, which clears it later: the value never reaches the browser.
    async fn browser_copy(&self, pairing: &str, request: &Value) -> Value {
        let field = match request["field"].as_str() {
            Some("username") => Field::Username,
            Some("password") => Field::Password,
            Some("totp") => Field::Totp,
            _ => return error(Code::NoField),
        };
        let Some(id) = request["id"].as_str().and_then(|i| parse_id(i).ok()) else { return error(Code::NotFound) };
        let (value, settings, label) = {
            let mut st = self.state.lock().await;
            if !st.browser.fills_left(pairing) {
                return error(Code::RateLimited);
            }
            let settings = st.settings.refresh().clone();
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            if field != Field::Username && session.view.get(id).is_some_and(|e| e.reprompt) {
                return error(Code::Reprompt);
            }
            let value = match nyx_passwords_core::vault::reveal(&session.keys, &session.snapshot, id, field) {
                Ok(v) => v,
                Err(e) => return error(Failure::from(e).kind),
            };
            let label = match field {
                Field::Username => "Username",
                Field::Password => "Password",
                _ => "One-time code",
            };
            (value, settings, label)
        };
        match self.put_on_clipboard(value, &settings, label).await {
            Ok(seconds) => json!({"seconds": seconds}),
            Err(f) => error(f.kind),
        }
    }

    /// For the app: pairings waiting for confirmation (with their codes) and paired ones.
    pub async fn pairings(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        st.browser.pending.retain(|p| p.at.elapsed() < PENDING_FOR);
        let pending: Vec<Value> = st
            .browser
            .pending
            .iter()
            .map(|p| json!({"id": p.id, "browser": p.browser, "extension": p.extension, "code": p.code}))
            .collect();
        let paired: Vec<Value> = st
            .store
            .pairings()
            .unwrap_or_default()
            .iter()
            .map(|p| json!({"id": p.id, "browser": p.browser, "extension": p.extension, "created": p.created}))
            .collect();
        Ok(json!({"pending": pending, "paired": paired}).to_string())
    }

    /// The user compared the codes and said yes.
    pub async fn confirm_pairing(&self, scope: Scope, id: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let at = st.browser.pending.iter().position(|p| p.id == id && p.at.elapsed() < PENDING_FOR);
        let Some(at) = at else { return Err(Failure::new(Code::NotFound, "that pairing request has expired")) };
        let pending = st.browser.pending.remove(at);
        let session = st.session.as_ref().ok_or_else(super::vault::locked)?;
        let stored_key = session
            .keys
            .item(None, None)
            .and_then(|mut k| k.encrypt(pending.key.export().expose()))
            .map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        let pairing = Pairing {
            id: pending.id.clone(),
            extension: pending.extension,
            browser: pending.browser,
            key: stored_key,
            created: now_ms() / 1000,
        };
        st.store.put_pairing(&pairing).map_err(|e| Failure::new(Code::Failed, e.to_string()))?;
        st.browser.active.insert(
            pending.id,
            Active { pairing, key: pending.key, seen: BTreeSet::new(), fills: VecDeque::new(), usernames: VecDeque::new() },
        );
        Ok(())
    }

    /// Forgets a pairing (or turns down a request).
    pub async fn remove_pairing(&self, scope: Scope, id: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let mut st = self.state.lock().await;
        st.browser.pending.retain(|p| p.id != id);
        st.browser.active.remove(id);
        st.store.remove_pairing(id).map_err(|e| Failure::new(Code::Failed, e.to_string()))
    }
}

/// The session bus, for Nyx Clipboard's codes (opened once).
async fn clipboard_bus() -> zbus::Result<zbus::Connection> {
    static BUS: tokio::sync::OnceCell<zbus::Connection> = tokio::sync::OnceCell::const_new();
    BUS.get_or_try_init(zbus::Connection::session).await.cloned()
}

/// A request from a frame on another site than the page gets nothing.
fn frame_on_site(request: &Value, url: &Url) -> bool {
    match request["frame"].as_str().filter(|f| !f.is_empty()) {
        None => true,
        Some(frame) => Url::parse(frame).ok().is_some_and(|f| {
            matches!(f.scheme(), "http" | "https")
                && f.host_str().zip(url.host_str()).is_some_and(|(a, b)| matching::base_domain(a) == matching::base_domain(b))
        }),
    }
}

/// One opened request from a paired extension.
fn handle(st: &mut State, pairing: &str, browser: &(i32, String), request: &Value) -> Value {
    let url = || request["url"].as_str().and_then(|u| Url::parse(u).ok()).filter(|u| matches!(u.scheme(), "http" | "https"));
    match request["r"].as_str() {
        Some("status") => {
            let st_name = if st.session.is_some() { state::UNLOCKED } else { state::LOCKED };
            json!({"state": st_name})
        }
        Some("context") => {
            if let Some(url) = url() {
                st.browser.context = Some(Context { url, pid: browser.0 });
            }
            json!({})
        }
        Some("match") => {
            let Some(url) = url() else { return error(Code::NoUrl) };
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let items: Vec<Value> = session
                .view
                .matching(&url)
                .into_iter()
                .take(MATCHES)
                .map(|e| {
                    json!({
                        "id": e.id, "name": e.name.expose(),
                        "username": e.username.as_ref().map(|u| u.expose()).unwrap_or(""),
                        "has_totp": e.has_totp, "reprompt": e.reprompt, "has_password": e.has_password,
                        "sign_in_with": super::extension::custom(session, e.id, super::extension::SIGN_IN_WITH),
                        "has_passkey": !session.passkeys(e.id).unwrap_or_default().is_empty(),
                        "host": e.host, "favorite": e.favorite,
                    })
                })
                .collect();
            json!({"items": items})
        }
        Some(r @ ("fill" | "totp")) => {
            let Some(url) = url() else { return error(Code::NoUrl) };
            let Some(session) = st.session.as_ref() else { return error(Code::Locked) };
            let on_load = request["trigger"] == "load";
            // As the page loads: only if that's on, and only the one login made for this
            // very host (or the last used of several), never one that asks for the
            // master password.
            let id = if on_load {
                if r != "fill" || !st.settings.refresh().fill_on_load {
                    return error(Code::Denied);
                }
                let fit: Vec<&nyx_passwords_core::vault::Entry> = session
                    .view
                    .matching(&url)
                    .into_iter()
                    .filter(|e| super::extension::fill_on_load_ok(session, e, &url))
                    .collect();
                let chosen = match fit.as_slice() {
                    [one] => Some(one.id),
                    _ => st.recent.iter().find(|r| fit.iter().any(|e| e.id == **r)).copied(),
                };
                match chosen {
                    Some(id) => id,
                    None => return error(Code::NotFound),
                }
            } else {
                let Some(id) = request["id"].as_str().and_then(|i| parse_id(i).ok()) else { return error(Code::NotFound) };
                id
            };
            let matched = session.view.matching(&url).into_iter().find(|e| e.id == id);
            // Another site's login, only when the user picked it in the popup and confirmed.
            let confirmed = !on_load && request["confirmed"] == true;
            let entry = match matched {
                Some(e) => e,
                None if confirmed => match session.view.get(id).filter(|e| e.kind == Kind::Login && !e.deleted) {
                    Some(e) => e,
                    None => return error(Code::NotFound),
                },
                // Only an item that belongs to this page, never one named by id alone.
                None => return error(Code::Denied),
            };
            // A login form in a frame from another site gets nothing.
            if let Some(frame) = request["frame"].as_str().filter(|f| !f.is_empty()) {
                let same_site = Url::parse(frame).ok().is_some_and(|f| {
                    matches!(f.scheme(), "http" | "https")
                        && f.host_str()
                            .zip(url.host_str())
                            .is_some_and(|(a, b)| matching::base_domain(a) == matching::base_domain(b))
                });
                if !same_site {
                    return error(Code::Denied);
                }
            }
            if entry.reprompt {
                return error(Code::Reprompt);
            }
            let Some(active) = st.browser.active.get_mut(pairing) else { return error(Code::Denied) };
            if !within(&mut active.fills, FILLS_PER_MINUTE) {
                return error(Code::RateLimited);
            }
            // Filling uses the password even where the organization hides it from view,
            // as the official extension does.
            let get =
                |field| reveal_for_use(&session.keys, &session.snapshot, id, field).ok().map(|s: Secret| s.expose().to_string());
            let has_totp = entry.has_totp;
            let answer = if r == "fill" {
                json!({"id": id, "has_totp": has_totp,
                       "username": get(Field::Username).unwrap_or_default(), "password": get(Field::Password).unwrap_or_default()})
            } else {
                match nyx_passwords_core::vault::current_code(&session.keys, &session.snapshot, id) {
                    Ok(c) => json!({"code": c.code.expose(), "period": c.period, "period_left": c.remaining}),
                    Err(_) => return error(Code::NoField),
                }
            };
            super::vault::used(st, id);
            st.last_used = Instant::now();
            answer
        }
        Some("generate") => {
            match generated(&st.settings.refresh().clone(), request.get("rules").map(|r| r.to_string()).as_deref()) {
                Ok(p) => json!({"password": p.expose()}),
                Err(_) => error(Code::Failed),
            }
        }
        Some("unlock") => {
            launch_app(&["--unlock"]);
            json!({})
        }
        // The extension unpairs itself. Its key is gone with it, so the reply can't be
        // sealed: the extension hears "unknown", which it takes as unpaired.
        Some("unpair") => {
            st.browser.active.remove(pairing);
            let _ = st.store.remove_pairing(pairing);
            json!({})
        }
        // Shows an item in the Passwords window: for what stays in the app (an SSH key's
        // private half, notes).
        Some("open") => {
            let Some(id) = request["id"].as_str().and_then(|i| parse_id(i).ok()) else { return error(Code::NotFound) };
            if !st.session.as_ref().is_some_and(|s| s.view.get(id).is_some_and(|e| !e.deleted)) {
                return error(Code::NotFound);
            }
            launch_app(&["--item", &id.to_string()]);
            json!({})
        }
        _ => super::extension::read(st, pairing, request),
    }
}

/// Starts the Passwords window with these arguments, detached.
fn launch_app(args: &[&str]) {
    if let Some(app) = super::peer::allowed_dir().map(|d| d.join("nyx-passwords")) {
        let _ = std::process::Command::new(app)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

/// Saves the login the user just typed on a page (they asked, from the extension's
/// popup): a new login for the site, or a new password for the site's login with the
/// same username. Everything else on an existing login is kept, and the old password goes
/// into its history.
async fn save(st: &mut State, pairing: &str, request: &Value) -> Value {
    let Some(url) = request["url"].as_str().and_then(|u| Url::parse(u).ok()).filter(|u| matches!(u.scheme(), "http" | "https"))
    else {
        return error(Code::NoUrl);
    };
    let username = request["username"].as_str().unwrap_or("").trim().to_string();
    let password = request["password"].as_str().unwrap_or("").to_string();
    if password.is_empty() || password.len() > 1024 || username.len() > 512 {
        return error(Code::NoField);
    }
    if !st.browser.active.get_mut(pairing).is_some_and(|a| within(&mut a.fills, FILLS_PER_MINUTE)) {
        return error(Code::RateLimited);
    }
    let Ok((server, refresh)) = online(st) else { return error(Code::Failed) };
    let Some(session) = st.session.as_mut() else { return error(Code::Locked) };
    let candidates = super::extension::save_candidates(session, &url, request);
    // The login `check` named, else the page's login with this username.
    let named = request["id"].as_str().and_then(|i| parse_id(i).ok());
    let existing = match named {
        Some(id) => match candidates.iter().find(|e| e.id == id) {
            Some(e) => Some(e.id),
            None => return error(Code::Denied),
        },
        None => candidates
            .iter()
            .find(|e| super::extension::same_username(e.username.as_ref().map_or("", |u| u.expose()), &username))
            .map(|e| e.id),
    };
    st.edits += 1;
    let result = match existing {
        Some(id) if session.view.get(id).is_some_and(|e| e.reprompt) => {
            return error(Code::Reprompt);
        }
        // A read-only login, or one whose password is hidden, can't take a new password.
        Some(id) if session.view.get(id).is_some_and(|e| !e.editable || !e.view_password) => {
            return error(Code::Denied);
        }
        Some(id) => {
            let entry = session.view.get(id).expect("found above");
            let get = |field| reveal_for_use(&session.keys, &session.snapshot, id, field).ok();
            let draft = LoginDraft {
                name: Secret::new(entry.name.expose()),
                username: entry.username.as_ref().map(|u| Secret::new(u.expose())),
                password: Some(Secret::new(password)),
                totp: get(Field::TotpSeed),
                uris: entry.uris.iter().map(|u| Secret::new(u.expose()).into()).collect(),
                notes: get(Field::Notes),
                folder: entry.folder,
                favorite: entry.favorite,
                reprompt: entry.reprompt,
                place: Place { organization: entry.organization, collections: entry.collections.clone() },
                custom: None,
            };
            session.update_login(&mut st.store, &server, &refresh, id, &draft).await.map(|()| ("updated", id))
        }
        None => {
            let host = url.host_str().unwrap_or_default().trim_start_matches("www.").to_string();
            let draft = LoginDraft {
                name: Secret::new(host),
                username: (!username.is_empty()).then(|| Secret::new(username.as_str())),
                password: Some(Secret::new(password)),
                totp: None,
                uris: vec![Secret::new(url.origin().ascii_serialization()).into()],
                notes: None,
                folder: None,
                favorite: false,
                reprompt: false,
                place: Place::default(),
                custom: None,
            };
            session.create_login(&mut st.store, &server, &refresh, &draft).await.map(|id| ("created", id))
        }
    };
    match result {
        Ok((what, id)) => json!({"saved": what, "id": id, "username": username}),
        Err(e) => json!({"error": Failure::from(e).kind.short()}),
    }
}

/// The trusted active site for Glimpse: the tab a paired extension last reported, if
/// that browser was the window in front (`front`). Window titles are never used.
pub fn active_site(st: &State, front: Option<i32>) -> Option<Url> {
    let ctx = st.browser.context.as_ref()?;
    (front == Some(ctx.pid)).then(|| ctx.url.clone())
}
