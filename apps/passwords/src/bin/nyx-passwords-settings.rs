//! The Settings extension helper: a Passwords page in Settings (pages, describe, set;
//! see extensions/README.md). It edits `~/.config/nyx-passwords/settings.toml`, the
//! same file the window writes and the daemon reads, and asks the daemon for its state.
//! The daemon lets it see the status, lock and sync, nothing more.

use std::path::PathBuf;
use std::time::Duration;

use nyx_core::{app, paths};
use nyx_passwords::daemon::settings::Settings;
use nyx_passwords_proto as proto;
use serde_json::{Value, json};

fn main() {
    app::init(nyx_passwords::daemon::APP);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["pages"] => Ok(pages()),
        ["describe", _] => Ok(if preview_supported() { describe_preview() } else { describe() }),
        ["set", _, key, value] => set(key, value),
        ["theme-changed"] => Ok(Value::Null),
        _ => Err("usage: nyx-passwords-settings pages | describe PAGE | set PAGE KEY VALUE".to_string()),
    };
    match result {
        Ok(Value::Null) => {}
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn pages() -> Value {
    json!([{
        "id": "passwords", "title": "Passwords", "icon": "dialog-password-symbolic",
        "description": "Vault locking, clipboard, Glimpse, browsers and email aliases",
        "keywords": "passwords vault vaultwarden bitwarden lock clipboard glimpse assistant browser alias fastmail simplelogin template",
    }])
}

fn file() -> PathBuf {
    paths::prefs_file()
}

fn current() -> Settings {
    std::fs::read_to_string(file()).ok().and_then(|t| toml::from_str(&t).ok()).unwrap_or_default()
}

fn opts(pairs: &[(u64, &str)]) -> Value {
    Value::Array(pairs.iter().map(|(v, l)| json!([v.to_string(), l])).collect())
}

const LOCK_AFTER: &[(u64, &str)] =
    &[(1, "1 minute"), (5, "5 minutes"), (15, "15 minutes"), (30, "30 minutes"), (60, "1 hour"), (240, "4 hours"), (0, "Never")];
const CLEAR_AFTER: &[(u64, &str)] = &[
    (10, "After 10 seconds"),
    (20, "After 20 seconds"),
    (30, "After 30 seconds"),
    (60, "After 1 minute"),
    (120, "After 2 minutes"),
    (0, "Never"),
];
const SYNC_EVERY: &[(u64, &str)] =
    &[(5, "Every 5 minutes"), (15, "Every 15 minutes"), (30, "Every 30 minutes"), (60, "Every hour"), (0, "Only when unlocking")];

fn label(pairs: &[(u64, &'static str)], value: u64) -> Option<&'static str> {
    pairs.iter().find(|(v, _)| *v == value).map(|(_, l)| *l)
}

fn preview_supported() -> bool {
    std::env::var("SETTINGS_KINDS").is_ok_and(|k| k.split(' ').any(|x| x == "preview"))
}

/// The two-column page: the controls on the left, the vault's state and where logins
/// show up on the right. Counts come from the local copy's unencrypted parts.
fn describe_preview() -> Value {
    let s = current();
    let (state, host) = daemon_status();
    let open = state.as_deref() == Some(proto::state::UNLOCKED);
    let locks = match s.lock_minutes {
        0 => "doesn't lock on a timer".to_string(),
        n => format!("locks after {} unused", label(LOCK_AFTER, n).map_or_else(|| format!("{n} minutes"), str::to_string)),
    };
    let (title, line) = match state.as_deref() {
        Some(proto::state::UNLOCKED) => ("Vault open", format!("{host} · {locks}")),
        Some(proto::state::LOCKED) => ("Vault locked", host.clone()),
        Some(_) => ("Not signed in", "Sign in in Passwords".to_string()),
        None => ("Passwords isn't running", "It starts when Passwords or Glimpse needs it".to_string()),
    };
    let summary = nyx_passwords_core::store::summary(&paths::data_dir().join("vault.sqlite"));
    let browsers = summary.as_ref().map(|s| s.browsers.clone()).unwrap_or_default();

    let mut blocks = Vec::new();
    if open {
        blocks.push(json!({"kind": "rows", "rows": [
            {"kind": "button", "key": "lock", "title": "Lock now", "icon": "system-lock-screen-symbolic", "label": "Lock", "refresh": true},
            {"kind": "button", "key": "sync", "title": "Sync now", "desc": "Fetch changes from the server", "icon": "view-refresh-symbolic", "label": "Sync", "refresh": true},
        ]}));
    }
    if let Some(sum) = &summary {
        let passkeys_sub = match (s.browser_passkeys, browsers.len()) {
            (false, _) => "Not in browsers".to_string(),
            (true, 0) => String::new(),
            (true, 1) => "In 1 browser".to_string(),
            (true, n) => format!("In {n} browsers"),
        };
        blocks.push(json!({"kind": "stats", "items": [
            {"label": "Logins", "value": sum.logins.to_string()},
            {"label": "Last synced", "value": sum.last_sync.map_or_else(|| "Not yet".to_string(), ago), "sub": label(SYNC_EVERY, s.sync_minutes).unwrap_or_default()},
            {"label": "Passkeys", "value": sum.passkeys.to_string(), "sub": passkeys_sub},
        ]}));
    }
    let item = |icon: &str, label: &str, sub: &str, on: bool| {
        let mut item = json!({"icon": icon, "label": label, "sub": sub, "value": if on { "On" } else { "Off" }});
        if on {
            item["tone"] = json!("good");
        }
        item
    };
    let browsers_sub = match browsers.as_slice() {
        [] => "No browser paired".to_string(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    };
    let browsers_sub =
        if s.fill_on_load && !browsers.is_empty() { format!("{browsers_sub} · fill as pages load") } else { browsers_sub };
    let items = [
        item("system-search-symbolic", "Glimpse", "“pw” and a name · names only", s.glimpse),
        item("web-browser-symbolic", "Browsers", &browsers_sub, !browsers.is_empty()),
        item("starred-symbolic", "Nyx Assistant", "Asks for a key press each time", s.assistant),
        item("utilities-terminal-symbolic", "SSH and git", "Keys turned on for the agent; each use asks", s.ssh_agent),
    ];
    blocks.push(json!({"kind": "list", "title": "Where your logins show up", "items": items}));
    blocks.push(json!({"kind": "rows", "rows": [
        {"kind": "button", "key": "open", "title": "Open Passwords", "icon": "dialog-password-symbolic", "label": "Open"},
    ]}));

    let paired = if browsers.is_empty() { "Pair one in Passwords' settings".to_string() } else { browsers.join(", ") };
    json!({
        "poll": 10,
        "preview": {
            "title": title, "line": line, "blocks": blocks,
            "foot": "Glimpse and Nyx Assistant never see a password; Passwords copies it for them.",
            "foot_icon": "security-high-symbolic",
        },
        "groups": [
            {"title": "Locking", "rows": [
                {"kind": "choice", "key": "lock_minutes", "title": "Lock after", "desc": "When the vault hasn't been used this long", "icon": "preferences-system-time-symbolic", "value": s.lock_minutes.to_string(), "options": opts(LOCK_AFTER)},
                {"kind": "switch", "key": "lock_on_screen_lock", "title": "Lock when the screen locks", "desc": "Along with the desktop", "icon": "system-lock-screen-symbolic", "value": s.lock_on_screen_lock},
                {"kind": "switch", "key": "lock_on_sleep", "title": "Lock on sleep", "desc": "Before the computer suspends", "icon": "weather-clear-night-symbolic", "value": s.lock_on_sleep},
            ]},
            {"title": "Copying", "rows": [
                {"kind": "choice", "key": "clipboard_seconds", "title": "Clear copied values", "desc": "If the clipboard still holds the copy", "icon": "edit-copy-symbolic", "value": s.clipboard_seconds.to_string(), "options": opts(CLEAR_AFTER)},
                {"kind": "switch", "key": "paste_once", "title": "Paste once", "desc": "Clear the clipboard after the first paste", "icon": "edit-paste-symbolic", "value": s.paste_once},
                {"kind": "switch", "key": "notify_copies", "title": "Notify on copy", "desc": "Names what was copied, never the value", "icon": "preferences-system-notifications-symbolic", "value": s.notify_copies},
            ]},
            {"title": "Finding logins", "note": "Glimpse never shows a password and Nyx Assistant never sees one. The Assistant can also generate passwords, count weak ones and show a login.", "rows": [
                {"kind": "switch", "key": "glimpse", "title": "In Glimpse", "desc": "Type “pw” and a name", "icon": "system-search-symbolic", "value": s.glimpse},
                {"kind": "switch", "key": "assistant", "title": "With Nyx Assistant", "desc": "Asks for a key press each time", "icon": "starred-symbolic", "value": s.assistant},
                {"kind": "choice", "key": "sync_minutes", "title": "Sync", "desc": "While the vault is open", "icon": "view-refresh-symbolic", "value": s.sync_minutes.to_string(), "options": opts(SYNC_EVERY)},
            ]},
            {"title": "Browsers", "collapsible": true, "note": "Logins fill only on https, only the one made for that exact site, only into empty fields. Each passkey use is confirmed in the extension.", "rows": [
                {"kind": "switch", "key": "fill_on_load", "title": "Fill logins as pages load", "desc": "On https, for that exact site only", "icon": "web-browser-symbolic", "value": s.fill_on_load},
                {"kind": "switch", "key": "browser_passkeys", "title": "Passkeys in browsers", "desc": "Paired browsers offer and save them", "icon": "auth-fingerprint-symbolic", "value": s.browser_passkeys},
                {"kind": "button", "key": "open_browsers", "title": "Paired browsers", "desc": paired, "icon": "preferences-system-symbolic", "label": "Open"},
            ]},
            {"title": "SSH agent", "collapsible": true, "rows": [
                {"kind": "switch", "key": "ssh_agent", "title": "SSH agent", "desc": "For ssh and git; each use asks first", "icon": "utilities-terminal-symbolic", "value": s.ssh_agent},
                {"kind": "info", "key": "ssh_socket", "title": "SSH_AUTH_SOCK", "icon": "insert-link-symbolic", "value": proto::ssh_agent_socket_path().map(|p| p.display().to_string()).unwrap_or_default()},
            ]},
            {"title": "Email aliases", "collapsible": true, "rows": dress(aliases(&s), &[
                ("username.kind", "avatar-default-symbolic", None),
                ("username.service", "mail-send-symbolic", None),
                ("username.service_domain", "network-workgroup-symbolic", None),
                ("username.service_url", "network-server-symbolic", Some("Self-hosted; empty for the hosted one")),
                ("username.zone_id", "emblem-system-symbolic", None),
                ("username.forward_to", "mail-forward-symbolic", None),
                ("username.email", "mail-unread-symbolic", None),
                ("username.domain", "network-workgroup-symbolic", None),
                ("open_aliases", "mail-message-new-symbolic", Some("See aliases and save tokens")),
            ])},
            {"title": "Templates", "collapsible": true, "rows": dress(templates(), &[
                ("templates", "text-x-generic-symbolic", None),
                ("open_templates", "document-edit-symbolic", None),
            ])},
        ]
    })
}

/// Gives rows their icon, and a shorter description where one is given.
fn dress(mut rows: Vec<Value>, looks: &[(&str, &str, Option<&str>)]) -> Vec<Value> {
    for row in &mut rows {
        let key = row["key"].as_str().unwrap_or_default().to_string();
        if let Some((_, icon, desc)) = looks.iter().find(|(k, ..)| *k == key) {
            row["icon"] = json!(icon);
            if let Some(desc) = desc {
                row["desc"] = json!(desc);
            }
        }
    }
    rows
}

/// "just now", "5 min ago", "3 h ago", "2 days ago".
fn ago(epoch: u64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let s = now.saturating_sub(epoch);
    match s {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", s / 60),
        3600..86_400 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86_400),
    }
}

fn describe() -> Value {
    let s = current();
    let (state, host) = daemon_status();
    let status = match state.as_deref() {
        Some(proto::state::UNLOCKED) => format!("Open · {host}"),
        Some(proto::state::LOCKED) => format!("Locked · {host}"),
        Some(_) => "Not signed in".to_string(),
        None => "Not running; it starts when Passwords or Glimpse needs it".to_string(),
    };
    let mut vault = vec![json!({"kind": "info", "key": "status", "title": "Vault", "value": status})];
    if state.as_deref() == Some(proto::state::UNLOCKED) {
        vault.push(json!({"kind": "button", "key": "lock", "title": "Lock now", "label": "Lock", "refresh": true}));
        vault.push(json!({"kind": "button", "key": "sync", "title": "Sync now", "desc": "Fetch changes from the server.", "label": "Sync", "refresh": true}));
    }
    vault.push(json!({"kind": "button", "key": "open", "title": "Open Passwords", "label": "Open"}));
    let (minutes, seconds, syncs) = (LOCK_AFTER, CLEAR_AFTER, SYNC_EVERY);
    json!({
        "poll": 10,
        "groups": [
            {"title": "Vault", "rows": vault},
            {"title": "Locking", "rows": [
                {"kind": "choice", "key": "lock_minutes", "title": "Lock after", "desc": "Lock the vault when it hasn't been used for this long.", "value": s.lock_minutes.to_string(), "options": opts(minutes)},
                {"kind": "switch", "key": "lock_on_screen_lock", "title": "Lock when the screen locks", "value": s.lock_on_screen_lock},
                {"kind": "switch", "key": "lock_on_sleep", "title": "Lock on sleep", "value": s.lock_on_sleep},
            ]},
            {"title": "Clipboard", "rows": [
                {"kind": "choice", "key": "clipboard_seconds", "title": "Clear copied values", "desc": "Empty the clipboard this long after copying, if it still holds the copy.", "value": s.clipboard_seconds.to_string(), "options": opts(seconds)},
                {"kind": "switch", "key": "paste_once", "title": "Paste once", "desc": "Clear the clipboard after the first paste.", "value": s.paste_once},
                {"kind": "switch", "key": "notify_copies", "title": "Notify on copy", "desc": "Name what was copied, never the value.", "value": s.notify_copies},
            ]},
            {"title": "Sync", "rows": [
                {"kind": "choice", "key": "sync_minutes", "title": "Sync", "desc": "Fetch changes from the server while the vault is open.", "value": s.sync_minutes.to_string(), "options": opts(syncs)},
            ]},
            {"title": "Glimpse", "rows": [
                {"kind": "switch", "key": "glimpse", "title": "Find logins in Glimpse", "desc": "Type “pw” and a name. Passwords are never shown there.", "value": s.glimpse},
            ]},
            {"title": "Nyx Assistant", "rows": [
                {"kind": "switch", "key": "assistant", "title": "Find and copy logins", "desc": "Also generate passwords, count weak ones and show a login. The Assistant asks for a key press each time and never sees a password.", "value": s.assistant},
            ]},
            {"title": "SSH agent", "collapsible": true, "rows": [
                {"kind": "switch", "key": "ssh_agent", "title": "SSH agent", "desc": "Let ssh and git use the keys turned on for it; each use asks first.", "value": s.ssh_agent},
                {"kind": "info", "key": "ssh_socket", "title": "SSH_AUTH_SOCK", "value": proto::ssh_agent_socket_path().map(|p| p.display().to_string()).unwrap_or_default()},
            ]},
            {"title": "Browsers", "collapsible": true, "rows": [
                {"kind": "switch", "key": "fill_on_load", "title": "Fill logins as pages load", "desc": "Only on https, only the login made for that exact site, only into empty fields.", "value": s.fill_on_load},
                {"kind": "switch", "key": "browser_passkeys", "title": "Passkeys in browsers", "desc": "Paired browsers may offer and save passkeys; each use is confirmed in the extension.", "value": s.browser_passkeys},
                {"kind": "button", "key": "open_browsers", "title": "Paired browsers", "desc": "Pair and remove browsers in Passwords' settings.", "label": "Open"},
            ]},
            {"title": "Email aliases", "collapsible": true, "rows": aliases(&s)},
            {"title": "Templates", "collapsible": true, "rows": templates()},
        ]
    })
}

/// The username generator's alias service and its settings. Tokens are set in the
/// Passwords window: a value given here would pass through a command line.
fn aliases(s: &Settings) -> Vec<Value> {
    let r = &s.username_rules;
    let services: Vec<Value> = nyx_passwords_core::alias::SERVICES.iter().map(|(id, name)| json!([id, name])).collect();
    let kinds = json!([
        ["word", "A random word"],
        ["plus", "Your email with a tag"],
        ["catch_all", "An address at your catch-all domain"],
        ["forwarded", "An alias from an email service"]
    ]);
    let kind = serde_json::to_value(r.kind).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
    let mut rows = vec![
        json!({"kind": "choice", "key": "username.kind", "title": "Generate usernames", "value": kind, "options": kinds, "refresh": true}),
    ];
    if kind == "forwarded" {
        rows.extend([
            json!({"kind": "choice", "key": "username.service", "title": "Email alias service", "value": r.service, "options": services}),
            json!({"kind": "entry", "key": "username.service_domain", "title": "Alias domain", "desc": "addy.io, Forward Email and Cloudflare.", "value": r.service_domain, "placeholder": "example.com"}),
            json!({"kind": "entry", "key": "username.service_url", "title": "Your own server", "desc": "A self-hosted SimpleLogin or addy.io; empty for the hosted one.", "value": r.service_url, "placeholder": "https://"}),
            json!({"kind": "entry", "key": "username.zone_id", "title": "Cloudflare zone id", "value": r.zone_id}),
            json!({"kind": "entry", "key": "username.forward_to", "title": "Cloudflare forwards to", "desc": "A verified destination address.", "value": r.forward_to}),
        ]);
    } else if kind == "plus" {
        rows.push(json!({"kind": "entry", "key": "username.email", "title": "Your email address", "value": r.email}));
    } else if kind == "catch_all" {
        rows.push(json!({"kind": "entry", "key": "username.domain", "title": "Catch-all domain", "value": r.domain}));
    }
    rows.push(json!({"kind": "button", "key": "open_aliases", "title": "Aliases and API tokens", "desc": "See and turn off aliases, and save each service's token, in Passwords.", "label": "Open"}));
    rows
}

/// The user's own templates, by name; they're made and changed in Passwords.
fn templates() -> Vec<Value> {
    let path = paths::app_dir().join("templates.toml");
    let own: Vec<String> = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| toml::from_str::<nyx_passwords_core::templates::TemplateFile>(&t).ok())
        .map(|f| f.usable().into_iter().map(|t| t.name).collect())
        .unwrap_or_default();
    let built_in = nyx_passwords_core::templates::builtin().len();
    let value =
        if own.is_empty() { format!("{built_in} built in") } else { format!("{built_in} built in · yours: {}", own.join(", ")) };
    vec![
        json!({"kind": "info", "key": "templates", "title": "Templates", "value": value}),
        json!({"kind": "button", "key": "open_templates", "title": "Make or change templates", "desc": "In Passwords' settings.", "label": "Open"}),
    ]
}

fn set(key: &str, value: &str) -> Result<Value, String> {
    match key {
        "lock" | "sync" => {
            let method = if key == "lock" { "Lock" } else { "Sync" };
            return match daemon_call(method) {
                Ok(()) => Ok(json!({"toast": if key == "lock" { "Vault locked." } else { "Synced." }, "refresh": true})),
                Err(e) => Err(e),
            };
        }
        "open" | "open_aliases" | "open_templates" | "open_browsers" => {
            let section = match key {
                "open_aliases" => Some("aliases"),
                "open_templates" | "open_browsers" => Some("settings"),
                _ => None,
            };
            let mut window = std::process::Command::new("nyx-passwords");
            if let Some(section) = section {
                window.args(["--section", section]);
            }
            window.spawn().map_err(|_| "Couldn't open Passwords".to_string())?;
            return Ok(Value::Null);
        }
        _ => {}
    }
    // The username generator's settings live in their own table.
    let (table_key, key) = match key.split_once('.') {
        Some(("username", field)) => (Some("username_rules"), field),
        Some(_) => return Err(format!("unknown setting {key}")),
        None => (None, key),
    };
    let new = match (table_key, key) {
        (None, "lock_minutes" | "clipboard_seconds" | "sync_minutes") => {
            toml::Value::Integer(value.parse::<i64>().map_err(|_| "not a number".to_string())?)
        }
        (
            None,
            "lock_on_screen_lock"
            | "lock_on_sleep"
            | "paste_once"
            | "notify_copies"
            | "glimpse"
            | "assistant"
            | "fill_on_load"
            | "browser_passkeys"
            | "ssh_agent",
        ) => toml::Value::Boolean(value == "true"),
        (Some(_), "kind") if ["word", "plus", "catch_all", "forwarded"].contains(&value) => toml::Value::String(value.into()),
        (Some(_), "service") if nyx_passwords_core::alias::SERVICES.iter().any(|(id, _)| *id == value) => {
            toml::Value::String(value.into())
        }
        (Some(_), "service_domain" | "service_url" | "zone_id" | "forward_to" | "email" | "domain") if value.len() <= 320 => {
            toml::Value::String(value.trim().into())
        }
        _ => return Err(format!("unknown setting {key}")),
    };
    // Edit only this key, keeping the window's own settings as they are.
    let path = file();
    let mut root: toml::Table = std::fs::read_to_string(&path)
        .ok()
        .map(|t| toml::from_str(&t).map_err(|_| "settings.toml couldn't be read; fix or remove it".to_string()))
        .transpose()?
        .unwrap_or_default();
    let target = match table_key {
        Some(name) => match root.entry(name).or_insert_with(|| toml::Value::Table(Default::default())) {
            toml::Value::Table(t) => t,
            _ => return Err("settings.toml couldn't be read; fix or remove it".into()),
        },
        None => &mut root,
    };
    target.insert(key.to_string(), new);
    let text = toml::to_string(&root).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    nyx_core::cmd::atomic_write(&path, text).map_err(|e| e.to_string())?;
    Ok(Value::Null)
}

/// `(state, server host)`, or `(None, _)` when the daemon isn't running. Never starts it.
fn daemon_status() -> (Option<String>, String) {
    let reply = with_daemon(|conn| async move {
        let msg = conn
            .call_method(None::<&str>, proto::OBJECT_PATH, Some(proto::INTERFACE), "Status", &())
            .await
            .map_err(|e| e.to_string())?;
        msg.body().deserialize::<(String, String, u32)>().map_err(|e| e.to_string())
    });
    match reply {
        Ok((state, host, _)) => (Some(state), host),
        Err(_) => (None, String::new()),
    }
}

fn daemon_call(method: &'static str) -> Result<(), String> {
    with_daemon(move |conn| async move {
        match conn.call_method(None::<&str>, proto::OBJECT_PATH, Some(proto::INTERFACE), method, &()).await {
            Ok(_) => Ok(()),
            Err(zbus::Error::MethodError(_, Some(text), _)) => Err(text),
            Err(e) => Err(e.to_string()),
        }
    })
}

fn with_daemon<T, F, Fut>(run: F) -> Result<T, String>
where
    F: FnOnce(zbus::Connection) -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let socket = proto::socket_path().ok_or("XDG_RUNTIME_DIR isn't set")?;
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async move {
        let stream = tokio::net::UnixStream::connect(&socket).await.map_err(|_| "Passwords isn't running".to_string())?;
        let build = zbus::connection::Builder::unix_stream(stream).p2p().build();
        let conn = tokio::time::timeout(Duration::from_secs(5), build)
            .await
            .map_err(|_| "Passwords didn't answer".to_string())?
            .map_err(|e| e.to_string())?;
        tokio::time::timeout(Duration::from_secs(25), run(conn)).await.map_err(|_| "Passwords didn't answer".to_string())?
    })
}
