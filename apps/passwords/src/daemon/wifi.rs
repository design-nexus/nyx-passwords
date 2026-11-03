//! The Wi-Fi networks NetworkManager has saved, read over the system bus for "Import
//! Wi-Fi networks". Listing reads names and settings only; a network's password is
//! asked for (`GetSecrets`) only while importing it, comes into a `Secret` here, and is
//! encrypted into the vault item by the caller. Nothing of it reaches the window.
//!
//! NetworkManager answers `GetSecrets` for system connections under polkit's
//! `settings.modify.system`, which its own rule allows without a prompt for the
//! `wheel` group on a local session; elsewhere polkit may ask.

use std::collections::HashMap;
use std::time::Instant;

use nyx_passwords_core::edit::{CustomDraft, LoginDraft, Place};
use nyx_passwords_core::model::Kind;
use nyx_passwords_core::secret::Secret;
use nyx_passwords_proto::Error as Code;
use serde::Serialize;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use super::peer::Scope;
use super::vault::{Failure, Result, State, Vault, locked, need, online};

const SERVICE: &str = "org.freedesktop.NetworkManager";
const SETTINGS_PATH: &str = "/org/freedesktop/NetworkManager/Settings";
const SETTINGS_IFACE: &str = "org.freedesktop.NetworkManager.Settings";
const CONNECTION_IFACE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const SECURITY: &str = "802-11-wireless-security";

/// Saved connections looked at, and the longest text taken from one.
const CONNECTIONS_MAX: usize = 500;
const TEXT_MAX: usize = 256;
/// A WPA passphrase is at most 63 characters (or a 64-digit key); WEP keys are shorter.
const SECRET_MAX: usize = 128;

type Section = HashMap<String, OwnedValue>;
type Settings = HashMap<String, Section>;

/// One saved Wi-Fi network, as the import dialog lists it. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Network {
    pub uuid: String,
    /// NetworkManager's name for the connection.
    pub name: String,
    pub ssid: String,
    /// `WPA2`, `WPA3`, `WEP`, `Open`, `Enterprise`, …
    pub security: String,
    pub hidden: bool,
    /// Why it can't be imported, if it can't.
    pub why_not: Option<String>,
    #[serde(skip)]
    pub path: String,
    #[serde(skip)]
    secret_key: Option<&'static str>,
}

/// What a connection's settings say, before deciding what to do with it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Raw {
    kind: String,
    name: String,
    uuid: String,
    ssid: Vec<u8>,
    hidden: bool,
    /// `None`: no security section at all (an open network).
    key_mgmt: Option<String>,
    psk_flags: u32,
    wep_flags: u32,
}

fn text(v: &Value) -> Option<String> {
    match v {
        Value::Value(inner) => text(inner),
        Value::Str(s) => Some(s.as_str().chars().take(TEXT_MAX).collect()),
        _ => None,
    }
}

fn number(v: &Value) -> Option<u32> {
    match v {
        Value::Value(inner) => number(inner),
        Value::U32(n) => Some(*n),
        _ => None,
    }
}

fn flag(v: &Value) -> Option<bool> {
    match v {
        Value::Value(inner) => flag(inner),
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

fn bytes(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Value(inner) => bytes(inner),
        Value::Array(a) if a.len() <= 32 => a.iter().map(|b| if let Value::U8(b) = b { Some(*b) } else { None }).collect(),
        _ => None,
    }
}

fn raw(s: &Settings) -> Raw {
    let get = |section: &str, key: &str| s.get(section).and_then(|sec| sec.get(key));
    let security = s.get(SECURITY);
    Raw {
        kind: get("connection", "type").and_then(|v| text(v)).unwrap_or_default(),
        name: get("connection", "id").and_then(|v| text(v)).unwrap_or_default(),
        uuid: get("connection", "uuid").and_then(|v| text(v)).unwrap_or_default(),
        ssid: get("802-11-wireless", "ssid").and_then(|v| bytes(v)).unwrap_or_default(),
        hidden: get("802-11-wireless", "hidden").and_then(|v| flag(v)).unwrap_or(false),
        key_mgmt: security.map(|sec| sec.get("key-mgmt").and_then(|v| text(v)).unwrap_or_default()),
        psk_flags: get(SECURITY, "psk-flags").and_then(|v| number(v)).unwrap_or(0),
        wep_flags: get(SECURITY, "wep-key-flags").and_then(|v| number(v)).unwrap_or(0),
    }
}

/// A network's SSID as text: UTF-8, or hex when it isn't.
fn ssid_text(ssid: &[u8]) -> String {
    match std::str::from_utf8(ssid) {
        Ok(s) => s.to_string(),
        Err(_) => ssid.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// What can be imported from a connection: `None` for anything that isn't Wi-Fi.
fn describe(raw: &Raw, path: &str) -> Option<Network> {
    if raw.kind != "802-11-wireless" || raw.uuid.is_empty() {
        return None;
    }
    let ssid = ssid_text(&raw.ssid);
    let (security, secret_key, flags, why_not): (&str, _, u32, Option<&str>) = match raw.key_mgmt.as_deref() {
        None | Some("owe") => ("Open", None, 0, Some("it has no password")),
        Some("wpa-psk") => ("WPA2", Some("psk"), raw.psk_flags, None),
        Some("sae") => ("WPA3", Some("psk"), raw.psk_flags, None),
        Some("none") => ("WEP", Some("wep-key0"), raw.wep_flags, None),
        Some(m) if m.starts_with("wpa-eap") || m == "ieee8021x" => {
            ("Enterprise", None, 0, Some("enterprise networks need an identity and certificates"))
        }
        Some(_) => ("Other", None, 0, Some("Passwords doesn't know this kind of security")),
    };
    // Flags other than 0 mean NetworkManager doesn't hold the secret itself (an agent
    // does, or it's never saved).
    let why_not = why_not.or((flags != 0).then_some("another program keeps its password"));
    Some(Network {
        uuid: raw.uuid.clone(),
        name: if raw.name.is_empty() { ssid.clone() } else { raw.name.clone() },
        ssid,
        security: security.to_string(),
        hidden: raw.hidden,
        why_not: why_not.map(str::to_string),
        path: path.to_string(),
        secret_key,
    })
}

/// The system bus (or `DBUS_SYSTEM_BUS_ADDRESS`, as everywhere).
pub async fn connect() -> std::result::Result<zbus::Connection, String> {
    zbus::Connection::system().await.map_err(|_| "NetworkManager isn't running".to_string())
}

/// The saved Wi-Fi networks, by name.
pub async fn list(bus: &zbus::Connection) -> std::result::Result<Vec<Network>, String> {
    let unreachable = |_| "NetworkManager isn't running".to_string();
    let reply =
        bus.call_method(Some(SERVICE), SETTINGS_PATH, Some(SETTINGS_IFACE), "ListConnections", &()).await.map_err(unreachable)?;
    let paths: Vec<OwnedObjectPath> =
        reply.body().deserialize().map_err(|_| "NetworkManager's answer wasn't understood".to_string())?;
    let mut out = Vec::new();
    for path in paths.into_iter().take(CONNECTIONS_MAX) {
        let Ok(reply) = bus.call_method(Some(SERVICE), path.as_str(), Some(CONNECTION_IFACE), "GetSettings", &()).await else {
            continue;
        };
        let Ok(settings) = reply.body().deserialize::<Settings>() else { continue };
        if let Some(network) = describe(&raw(&settings), path.as_str()) {
            out.push(network);
        }
    }
    out.sort_by_key(|n| n.name.to_lowercase());
    Ok(out)
}

/// A network's password, asked of NetworkManager now.
pub async fn secret(bus: &zbus::Connection, network: &Network) -> std::result::Result<Secret, String> {
    let key = network.secret_key.ok_or_else(|| "this network has no password to import".to_string())?;
    let reply = bus
        .call_method(Some(SERVICE), network.path.as_str(), Some(CONNECTION_IFACE), "GetSecrets", &(SECURITY,))
        .await
        .map_err(|e| match e {
        zbus::Error::MethodError(name, _, _) if name.as_str().ends_with("PermissionDenied") => {
            "NetworkManager didn't allow reading the password".to_string()
        }
        _ => "NetworkManager couldn't give the password".to_string(),
    })?;
    let secrets: Settings = reply.body().deserialize().map_err(|_| "NetworkManager's answer wasn't understood".to_string())?;
    let value =
        secrets.get(SECURITY).and_then(|s| s.get(key)).ok_or_else(|| "NetworkManager has no password for it".to_string())?;
    let found = match &**value {
        Value::Str(s) => Some(s.as_str()),
        Value::Value(inner) => match &**inner {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        },
        _ => None,
    };
    let found = found
        .filter(|s| !s.is_empty() && s.len() <= SECRET_MAX)
        .ok_or_else(|| "NetworkManager has no password for it".to_string())?;
    Ok(Secret::new(found))
}

/// Wi-Fi items already in the vault, by SSID (a login's username).
fn saved_ssids(st: &State) -> Vec<String> {
    let Some(session) = st.session.as_ref() else { return Vec::new() };
    session
        .view
        .entries
        .iter()
        .filter(|e| e.kind == Kind::Login && !e.deleted && e.template.as_deref() == Some("wifi"))
        .filter_map(|e| e.username.as_ref().map(|u| u.expose().to_string()))
        .collect()
}

/// The item for an imported network: the `wifi` template's layout.
fn draft(network: &Network, password: Secret) -> LoginDraft {
    let field = |name: &str, value: &str, kind| CustomDraft {
        name: Secret::new(name),
        value: Some(Secret::new(value)),
        kind,
        from: None,
    };
    LoginDraft {
        name: Secret::new(network.name.as_str()),
        username: Some(Secret::new(network.ssid.as_str())),
        password: Some(password),
        totp: None,
        uris: Vec::new(),
        notes: None,
        folder: None,
        favorite: false,
        reprompt: false,
        place: Place::default(),
        custom: Some(vec![
            field("Security", &network.security, 0),
            field("Hidden network", if network.hidden { "true" } else { "false" }, 2),
            field(nyx_passwords_proto::custom::TEMPLATE, "wifi", 0),
        ]),
    }
}

impl Vault {
    /// NetworkManager's saved Wi-Fi networks: JSON `[{uuid, name, ssid, security,
    /// hidden, why_not, already_saved}]`. No passwords.
    pub async fn wifi_networks(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let saved = {
            let st = self.state.lock().await;
            st.session.as_ref().ok_or_else(locked)?;
            saved_ssids(&st)
        };
        let bus = connect().await.map_err(|e| Failure::new(Code::Failed, e))?;
        let list = list(&bus).await.map_err(|e| Failure::new(Code::Failed, e))?;
        let out: Vec<_> = list
            .iter()
            .map(|n| {
                let mut v = serde_json::to_value(n).unwrap_or_default();
                v["already_saved"] = saved.contains(&n.ssid).into();
                v
            })
            .collect();
        Ok(serde_json::Value::Array(out).to_string())
    }

    /// Saves the chosen networks (by NetworkManager uuid) as Wi-Fi items; ones that can't
    /// be imported or are already saved are left out. One that fails doesn't stop the
    /// rest: JSON `{added, failed: [{name, why}]}`.
    pub async fn import_wifi(&self, scope: Scope, uuids: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let wanted: Vec<String> =
            serde_json::from_str(uuids).map_err(|_| Failure::new(Code::Failed, "the networks couldn't be read"))?;
        if wanted.is_empty() || wanted.len() > CONNECTIONS_MAX {
            return Err(Failure::new(Code::Failed, "choose some networks"));
        }
        let saved = {
            let st = self.state.lock().await;
            online(&st)?;
            saved_ssids(&st)
        };
        let bus = connect().await.map_err(|e| Failure::new(Code::Failed, e))?;
        let chosen: Vec<Network> = list(&bus)
            .await
            .map_err(|e| Failure::new(Code::Failed, e))?
            .into_iter()
            .filter(|n| wanted.contains(&n.uuid) && n.why_not.is_none() && !saved.contains(&n.ssid))
            .collect();
        let mut added = 0u32;
        let mut failed = Vec::new();
        for network in &chosen {
            match self.import_one(&bus, network).await {
                Ok(()) => added += 1,
                Err(why) => failed.push(serde_json::json!({"name": network.name, "why": why})),
            }
        }
        if added > 0 {
            self.state.lock().await.revision += 1;
        }
        Ok(serde_json::json!({"added": added, "failed": failed}).to_string())
    }

    async fn import_one(&self, bus: &zbus::Connection, network: &Network) -> std::result::Result<(), String> {
        // Asked for while the vault lock isn't held; dropped once encrypted.
        let password = secret(bus, network).await?;
        let mut st = self.state.lock().await;
        let st = &mut *st;
        let (server, refresh) = online(st).map_err(|f| f.message)?;
        st.edits += 1;
        let session = st.session.as_mut().ok_or("the vault is locked")?;
        let id = session
            .create_login(&mut st.store, &server, &refresh, &draft(network, password))
            .await
            .map_err(|e| Failure::from(e).message)?;
        super::grants::record(st, "Passwords", "imported Wi-Fi network", Some(id), "done");
        st.last_used = Instant::now();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wifi(key_mgmt: Option<&str>) -> Raw {
        Raw {
            kind: "802-11-wireless".into(),
            name: "Home".into(),
            uuid: "u1".into(),
            ssid: b"HomeNet".to_vec(),
            key_mgmt: key_mgmt.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn what_can_be_imported() {
        let n = describe(&wifi(Some("wpa-psk")), "/p/1").unwrap();
        assert_eq!(
            (n.ssid.as_str(), n.security.as_str(), n.why_not.as_deref(), n.secret_key),
            ("HomeNet", "WPA2", None, Some("psk"))
        );
        assert_eq!(describe(&wifi(Some("sae")), "/p").unwrap().security, "WPA3");
        assert_eq!(describe(&wifi(Some("none")), "/p").unwrap().secret_key, Some("wep-key0"));
        assert!(describe(&wifi(None), "/p").unwrap().why_not.unwrap().contains("no password"));
        assert!(describe(&wifi(Some("owe")), "/p").unwrap().why_not.is_some());
        assert!(describe(&wifi(Some("wpa-eap")), "/p").unwrap().why_not.unwrap().contains("enterprise"));
        let agent = Raw { psk_flags: 1, ..wifi(Some("wpa-psk")) };
        assert!(describe(&agent, "/p").unwrap().why_not.unwrap().contains("another program"));
        assert_eq!(describe(&Raw { kind: "802-3-ethernet".into(), ..wifi(None) }, "/p"), None);
        let unnamed = Raw { name: String::new(), ..wifi(Some("wpa-psk")) };
        assert_eq!(describe(&unnamed, "/p").unwrap().name, "HomeNet");
    }

    #[test]
    fn reads_settings() {
        let v = |x: Value<'static>| OwnedValue::try_from(x).unwrap();
        let mut s = Settings::new();
        s.insert(
            "connection".into(),
            Section::from([
                ("type".into(), v(Value::from("802-11-wireless"))),
                ("id".into(), v(Value::from("Café"))),
                ("uuid".into(), v(Value::from("u2"))),
            ]),
        );
        s.insert(
            "802-11-wireless".into(),
            Section::from([("ssid".into(), v(Value::from(vec![0xffu8, 0x41]))), ("hidden".into(), v(Value::from(true)))]),
        );
        s.insert(
            SECURITY.into(),
            Section::from([("key-mgmt".into(), v(Value::from("sae"))), ("psk-flags".into(), v(Value::from(2u32)))]),
        );
        let r = raw(&s);
        assert_eq!((r.name.as_str(), r.uuid.as_str(), r.hidden, r.psk_flags), ("Café", "u2", true, 2));
        assert_eq!(ssid_text(&r.ssid), "ff41", "not UTF-8: shown in hex");
        assert_eq!(r.key_mgmt.as_deref(), Some("sae"));
    }
}
