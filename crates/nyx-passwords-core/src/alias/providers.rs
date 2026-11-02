//! The email alias services behind one interface: make an alias, list them, turn one
//! off or on, delete one. What each service can do is in `Capabilities`, so callers
//! never name a service. Each is asked with the user's own API token, kept in the
//! keyring; nothing here stores anything.
//!
//! Checked against each service's API documentation (2026-11):
//! - Fastmail: JMAP `MaskedEmail/get` and `/set`; "disabled" sends mail to Trash,
//!   "deleted" bounces it (restorable in Fastmail's settings).
//! - SimpleLogin: `GET /api/v2/aliases`, `POST /api/aliases/:id/toggle`, `DELETE`.
//! - addy.io: `GET /api/v1/aliases`, `POST|DELETE /api/v1/active-aliases`, `DELETE`.
//! - Firefox Relay: `GET|PATCH|DELETE /api/v1/relayaddresses/`.
//! - Forward Email: `GET|PUT|DELETE /v1/domains/:domain/aliases`.
//! - Cloudflare Email Routing: a literal-address rule per alias,
//!   `GET|POST|PUT|DELETE /zones/:zone/email/routing/rules`.
//! - DuckDuckGo: making an alias only; it has no public API for the rest.

use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use super::{UsernameError, UsernameRules, site_name, tag};
use crate::secret::Secret;

/// The most aliases listed from one service.
const LIST_MAX: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    SimpleLogin,
    Addy,
    Relay,
    DuckDuckGo,
    Fastmail,
    ForwardEmail,
    Cloudflare,
}

/// What a service lets this client do with its aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    pub create: bool,
    pub list: bool,
    /// Turn an alias off and on again.
    pub toggle: bool,
    pub delete: bool,
    /// It can run on the user's own server (`service_url`).
    pub self_hosted: bool,
}

/// One alias, as its service describes it. Addresses aren't secrets; the token is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alias {
    /// The service's id for it (empty where the service has none, DuckDuckGo).
    pub id: String,
    pub email: String,
    pub enabled: bool,
    /// The site it was made for, where the service keeps that.
    pub site: String,
    pub note: String,
}

impl Service {
    pub const ALL: [Service; 7] = [
        Service::Fastmail,
        Service::SimpleLogin,
        Service::Addy,
        Service::Relay,
        Service::ForwardEmail,
        Service::Cloudflare,
        Service::DuckDuckGo,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Service::SimpleLogin => "simplelogin",
            Service::Addy => "addy",
            Service::Relay => "relay",
            Service::DuckDuckGo => "duckduckgo",
            Service::Fastmail => "fastmail",
            Service::ForwardEmail => "forwardemail",
            Service::Cloudflare => "cloudflare",
        }
    }

    pub fn name(self) -> &'static str {
        super::SERVICES.iter().find(|(id, _)| *id == self.id()).map_or("", |(_, name)| name)
    }

    pub fn from_id(id: &str) -> Option<Service> {
        Service::ALL.into_iter().find(|s| s.id() == id)
    }

    pub fn capabilities(self) -> Capabilities {
        let all = Capabilities { create: true, list: true, toggle: true, delete: true, self_hosted: false };
        match self {
            Service::SimpleLogin | Service::Addy => Capabilities { self_hosted: true, ..all },
            Service::DuckDuckGo => Capabilities { list: false, toggle: false, delete: false, ..all },
            _ => all,
        }
    }

    fn public_base(self) -> &'static str {
        match self {
            Service::SimpleLogin => "https://app.simplelogin.io",
            Service::Addy => "https://app.addy.io",
            Service::Relay => "https://relay.firefox.com",
            Service::DuckDuckGo => "https://quack.duckduckgo.com",
            Service::Fastmail => "https://api.fastmail.com",
            Service::ForwardEmail => "https://api.forwardemail.net",
            Service::Cloudflare => "https://api.cloudflare.com/client/v4",
        }
    }
}

/// A service with the user's token and settings, ready to ask.
pub struct Account<'a> {
    pub service: Service,
    token: &'a str,
    base: String,
    domain: String,
    zone: String,
    forward_to: String,
    http: reqwest::Client,
}

const FASTMAIL_MASKED: &str = "https://www.fastmail.com/dev/maskedemail";

impl<'a> Account<'a> {
    /// The service `rules.service` names, with `token`. `base` replaces its address (for
    /// tests); `rules.service_url` does for a self-hosted one.
    pub fn new(rules: &UsernameRules, token: &'a Secret, base: Option<&str>) -> Result<Self, UsernameError> {
        let service = Service::from_id(&rules.service).ok_or(UsernameError::Incomplete("an email alias service"))?;
        if token.is_empty() {
            return Err(UsernameError::NoToken);
        }
        let own = Some(rules.service_url.trim()).filter(|u| !u.is_empty() && service.capabilities().self_hosted);
        let base = base.or(own).unwrap_or(service.public_base()).trim_end_matches('/').to_string();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("nyx-passwords/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| UsernameError::Service(e.to_string()))?;
        Ok(Account {
            service,
            token: token.expose(),
            base,
            domain: rules.service_domain.trim().trim_start_matches('@').to_string(),
            zone: rules.zone_id.trim().to_string(),
            forward_to: rules.forward_to.trim().to_string(),
            http,
        })
    }

    fn domain(&self) -> Result<&str, UsernameError> {
        if self.domain.is_empty() {
            return Err(UsernameError::Incomplete(match self.service {
                Service::Addy => "the addy.io domain",
                Service::ForwardEmail => "the Forward Email domain",
                _ => "the alias domain",
            }));
        }
        Ok(&self.domain)
    }

    fn zone(&self) -> Result<String, UsernameError> {
        if self.zone.is_empty() {
            return Err(UsernameError::Incomplete("the Cloudflare zone id"));
        }
        Ok(format!("{}/zones/{}/email/routing/rules", self.base, segment(&self.zone)?))
    }

    fn authorized(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let t = self.token;
        match self.service {
            Service::SimpleLogin => request.header("Authentication", t),
            Service::Addy => request.bearer_auth(t).header("X-Requested-With", "XMLHttpRequest"),
            Service::Relay => request.header("Authorization", format!("Token {t}")),
            Service::ForwardEmail => request.basic_auth(t, Some("")),
            Service::DuckDuckGo | Service::Fastmail | Service::Cloudflare => request.bearer_auth(t),
        }
    }

    async fn ask(&self, request: reqwest::RequestBuilder) -> Result<Value, UsernameError> {
        send(self.authorized(request)).await
    }

    /// Makes a new alias for `site` (a page address or host; only its name is sent).
    pub async fn create(&self, site: Option<&str>) -> Result<Alias, UsernameError> {
        let site = site.and_then(site_name).unwrap_or_default();
        let note =
            if site.is_empty() { "Made by Nyx Passwords".to_string() } else { format!("Made by Nyx Passwords for {site}") };
        let b = &self.base;
        let made = |id: &Value, email: Option<String>| -> Result<Alias, UsernameError> {
            let email = email.ok_or_else(|| UsernameError::Service("the service's answer wasn't understood".into()))?;
            Ok(Alias { id: id_text(id), email, enabled: true, site: site.clone(), note: note.clone() })
        };
        match self.service {
            Service::SimpleLogin => {
                let mut url = format!("{b}/api/alias/random/new");
                if !site.is_empty() {
                    url = format!("{url}?hostname={}", url::form_urlencoded::byte_serialize(site.as_bytes()).collect::<String>());
                }
                let v = self.ask(self.http.post(url).json(&json!({"note": note}))).await?;
                made(&v["id"], text(&v["alias"]).or_else(|| text(&v["email"])))
            }
            Service::Addy => {
                let body = json!({"domain": self.domain()?, "description": note});
                let v = self.ask(self.http.post(format!("{b}/api/v1/aliases")).json(&body)).await?;
                made(&v["data"]["id"], text(&v["data"]["email"]))
            }
            Service::Relay => {
                let body = json!({"enabled": true, "generated_for": site, "description": note});
                let v = self.ask(self.http.post(format!("{b}/api/v1/relayaddresses/")).json(&body)).await?;
                made(&v["id"], text(&v["full_address"]))
            }
            Service::DuckDuckGo => {
                let v = self.ask(self.http.post(format!("{b}/api/email/addresses"))).await?;
                made(&Value::Null, text(&v["address"]).map(|a| format!("{a}@duck.com")))
            }
            Service::Fastmail => {
                // Fastmail asks that `description` be the user's own words and the site go
                // in `forDomain`; it names the creating client itself.
                let v = self
                    .jmap(
                        "MaskedEmail/set",
                        json!({"create": {"new": {"state": "enabled", "description": "", "forDomain": site}}}),
                    )
                    .await?;
                let new = &v["created"]["new"];
                made(&new["id"], text(&new["email"]))
            }
            Service::ForwardEmail => {
                let domain = self.domain()?;
                let body = json!({"labels": site, "description": note});
                let v = self.ask(self.http.post(format!("{b}/v1/domains/{}/aliases", segment(domain)?)).json(&body)).await?;
                let at = text(&v["domain"]["name"]).or_else(|| text(&v["domain"])).unwrap_or_else(|| domain.to_string());
                made(&v["id"], text(&v["name"]).map(|n| format!("{n}@{at}")))
            }
            Service::Cloudflare => {
                let domain = self.domain()?;
                if self.forward_to.is_empty() {
                    return Err(UsernameError::Incomplete("the address Cloudflare forwards to"));
                }
                let prefix: String = site.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
                let local = if prefix.is_empty() { tag() } else { format!("{}.{}", prefix.to_ascii_lowercase(), tag()) };
                let email = format!("{local}@{domain}");
                let body = json!({
                    "actions": [{"type": "forward", "value": [self.forward_to]}],
                    "matchers": [{"type": "literal", "field": "to", "value": email}],
                    "enabled": true,
                    "name": note,
                });
                let v = self.ask(self.http.post(self.zone()?).json(&body)).await?;
                made(&v["result"]["id"], Some(email))
            }
        }
    }

    /// The service's aliases, at most `LIST_MAX`. Fastmail's deleted ones are left out.
    pub async fn list(&self) -> Result<Vec<Alias>, UsernameError> {
        let b = &self.base;
        let mut out = Vec::new();
        match self.service {
            Service::DuckDuckGo => return Err(UsernameError::Unsupported),
            Service::SimpleLogin => {
                for page in 0.. {
                    let v = self.ask(self.http.get(format!("{b}/api/v2/aliases?page_id={page}"))).await?;
                    let list = v["aliases"].as_array().cloned().unwrap_or_default();
                    for a in &list {
                        out.push(alias(&a["id"], &a["email"], a["enabled"].as_bool(), "", &a["note"]));
                    }
                    if list.is_empty() || out.len() >= LIST_MAX {
                        break;
                    }
                }
            }
            Service::Addy => {
                for page in 1.. {
                    let url = format!("{b}/api/v1/aliases?page%5Bsize%5D=100&page%5Bnumber%5D={page}");
                    let v = self.ask(self.http.get(url)).await?;
                    for a in v["data"].as_array().into_iter().flatten() {
                        out.push(alias(&a["id"], &a["email"], a["active"].as_bool(), "", &a["description"]));
                    }
                    let last = v["meta"]["last_page"].as_u64().unwrap_or(1);
                    if page >= last || out.len() >= LIST_MAX {
                        break;
                    }
                }
            }
            Service::Relay => {
                let v = self.ask(self.http.get(format!("{b}/api/v1/relayaddresses/"))).await?;
                for a in v.as_array().into_iter().flatten() {
                    let site = a["generated_for"].as_str().unwrap_or_default();
                    out.push(alias(&a["id"], &a["full_address"], a["enabled"].as_bool(), site, &a["description"]));
                }
            }
            Service::Fastmail => {
                let v = self.jmap("MaskedEmail/get", json!({"ids": null})).await?;
                for a in v["list"].as_array().into_iter().flatten().filter(|a| a["state"] != "deleted") {
                    let site = a["forDomain"].as_str().unwrap_or_default();
                    out.push(alias(&a["id"], &a["email"], Some(a["state"] != "disabled"), site, &a["description"]));
                }
            }
            Service::ForwardEmail => {
                let domain = segment(self.domain()?)?;
                for page in 1.. {
                    let url = format!("{b}/v1/domains/{domain}/aliases?paginate=true&page={page}&limit=50");
                    let v = self.ask(self.http.get(url)).await?;
                    let list = v.as_array().cloned().unwrap_or_default();
                    for a in &list {
                        let email =
                            text(&a["name"]).map(|n| format!("{n}@{}", self.domain)).map(Value::String).unwrap_or_default();
                        let site = match &a["labels"] {
                            Value::Array(l) => l.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "),
                            other => other.as_str().unwrap_or_default().to_string(),
                        };
                        out.push(alias(&a["id"], &email, a["is_enabled"].as_bool(), &site, &a["description"]));
                    }
                    if list.len() < 50 || out.len() >= LIST_MAX {
                        break;
                    }
                }
            }
            Service::Cloudflare => {
                let rules = self.zone()?;
                for page in 1.. {
                    let v = self.ask(self.http.get(format!("{rules}?page={page}&per_page=50"))).await?;
                    let list = v["result"].as_array().cloned().unwrap_or_default();
                    for r in &list {
                        let m = &r["matchers"][0];
                        if m["type"] == "literal" && m["field"] == "to" {
                            out.push(alias(&r["id"], &m["value"], r["enabled"].as_bool(), "", &r["name"]));
                        }
                    }
                    let pages = v["result_info"]["total_pages"].as_u64().unwrap_or(1);
                    if list.is_empty() || page >= pages || out.len() >= LIST_MAX {
                        break;
                    }
                }
            }
        }
        out.truncate(LIST_MAX);
        Ok(out.into_iter().filter(|a| !a.email.is_empty()).collect())
    }

    /// Turns an alias off (mail to it is dropped or trashed, depending on the service)
    /// or on again.
    pub async fn set_enabled(&self, id: &str, on: bool) -> Result<(), UsernameError> {
        let b = &self.base;
        let id = segment(id)?;
        match self.service {
            Service::DuckDuckGo => return Err(UsernameError::Unsupported),
            Service::SimpleLogin => {
                // The service only flips it: ask first, flip only if needed.
                let now = self.ask(self.http.get(format!("{b}/api/aliases/{id}"))).await?;
                if now["enabled"].as_bool() != Some(on) {
                    self.ask(self.http.post(format!("{b}/api/aliases/{id}/toggle"))).await?;
                }
            }
            Service::Addy if on => {
                self.ask(self.http.post(format!("{b}/api/v1/active-aliases")).json(&json!({"id": id}))).await?;
            }
            Service::Addy => {
                self.ask(self.http.delete(format!("{b}/api/v1/active-aliases/{id}"))).await?;
            }
            Service::Relay => {
                self.ask(self.http.patch(format!("{b}/api/v1/relayaddresses/{id}/")).json(&json!({"enabled": on}))).await?;
            }
            Service::Fastmail => self.fastmail_state(id, if on { "enabled" } else { "disabled" }).await?,
            Service::ForwardEmail => {
                let url = format!("{b}/v1/domains/{}/aliases/{id}", segment(self.domain()?)?);
                self.ask(self.http.put(url).json(&json!({"is_enabled": on}))).await?;
            }
            Service::Cloudflare => {
                let url = format!("{}/{id}", self.zone()?);
                let v = self.ask(self.http.get(&url)).await?;
                let r = &v["result"];
                let body = json!({
                    "actions": r["actions"], "matchers": r["matchers"], "enabled": on,
                    "name": r["name"], "priority": r["priority"],
                });
                self.ask(self.http.put(url).json(&body)).await?;
            }
        }
        Ok(())
    }

    /// Deletes an alias. Fastmail's and addy.io's can be restored in their own settings;
    /// the others are gone.
    pub async fn delete(&self, id: &str) -> Result<(), UsernameError> {
        let b = &self.base;
        let id = segment(id)?;
        let url = match self.service {
            Service::DuckDuckGo => return Err(UsernameError::Unsupported),
            Service::Fastmail => return self.fastmail_state(id, "deleted").await,
            Service::SimpleLogin => format!("{b}/api/aliases/{id}"),
            Service::Addy => format!("{b}/api/v1/aliases/{id}"),
            Service::Relay => format!("{b}/api/v1/relayaddresses/{id}/"),
            Service::ForwardEmail => format!("{b}/v1/domains/{}/aliases/{id}", segment(self.domain()?)?),
            Service::Cloudflare => format!("{}/{id}", self.zone()?),
        };
        self.ask(self.http.delete(url)).await.map(|_| ())
    }

    async fn fastmail_state(&self, id: &str, state: &str) -> Result<(), UsernameError> {
        let v = self.jmap("MaskedEmail/set", json!({"update": {id: {"state": state}}})).await?;
        match v["notUpdated"][id]["description"].as_str().or(v["notUpdated"][id]["type"].as_str()) {
            Some(why) => Err(UsernameError::Service(format!("Fastmail refused: {why}"))),
            None => Ok(()),
        }
    }

    /// One Masked Email method call: finds the account from the session, then calls it.
    async fn jmap(&self, method: &str, mut args: Value) -> Result<Value, UsernameError> {
        let session = self.ask(self.http.get(format!("{}/jmap/session", self.base))).await?;
        let account = session["primaryAccounts"][FASTMAIL_MASKED]
            .as_str()
            .ok_or_else(|| UsernameError::Service("this Fastmail token can't manage masked email addresses".into()))?;
        // The token goes only to the API address on the same server.
        let api = session["apiUrl"].as_str().filter(|u| u.starts_with(&self.base)).map(str::to_string);
        let api = api.unwrap_or_else(|| format!("{}/jmap/api/", self.base));
        args["accountId"] = account.into();
        let call = json!({"using": ["urn:ietf:params:jmap:core", FASTMAIL_MASKED], "methodCalls": [[method, args, "0"]]});
        let v = self.ask(self.http.post(api).json(&call)).await?;
        let reply = &v["methodResponses"][0];
        if reply[0] == "error" {
            let why = reply[1]["description"].as_str().or(reply[1]["type"].as_str()).unwrap_or("an error");
            return Err(UsernameError::Service(format!("Fastmail refused: {why}")));
        }
        Ok(reply[1].clone())
    }
}

/// Sends a request; a refusal comes back with the service's own message if it has one.
async fn send(request: reqwest::RequestBuilder) -> Result<Value, UsernameError> {
    let resp = request.send().await.map_err(|_| UsernameError::Service("the service couldn't be reached".into()))?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let said = ["error", "message", "detail"]
            .iter()
            .find_map(|k| v[*k].as_str())
            .or_else(|| v["errors"][0]["message"].as_str())
            .map(str::to_string);
        return Err(UsernameError::Service(match (status.as_u16(), said) {
            (401 | 403, _) => "the service refused the token".into(),
            (_, Some(said)) => format!("the service refused: {said}"),
            (code, None) => format!("the service refused (HTTP {code})"),
        }));
    }
    Ok(v)
}

fn text(v: &Value) -> Option<String> {
    v.as_str().filter(|s| !s.is_empty()).map(str::to_string)
}

/// An id as text: services use numbers or strings.
fn id_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn alias(id: &Value, email: &Value, enabled: Option<bool>, site: &str, note: &Value) -> Alias {
    Alias {
        id: id_text(id),
        email: email.as_str().unwrap_or_default().to_string(),
        enabled: enabled.unwrap_or(true),
        site: site.to_string(),
        note: note.as_str().unwrap_or_default().to_string(),
    }
}

/// An id, domain or zone as one part of a URL path: anything that could step outside it
/// is refused.
fn segment(s: &str) -> Result<&str, UsernameError> {
    let fine = !s.is_empty()
        && s.len() <= 255
        && s != "."
        && s != ".."
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@'));
    if fine { Ok(s) } else { Err(UsernameError::Service("that isn't one of the service's aliases".into())) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities() {
        assert!(Service::ALL.iter().all(|s| Service::from_id(s.id()) == Some(*s) && !s.name().is_empty()));
        assert_eq!(Service::ALL.len(), super::super::SERVICES.len());
        let ddg = Service::DuckDuckGo.capabilities();
        assert!(ddg.create && !ddg.list && !ddg.toggle && !ddg.delete);
        assert!(Service::SimpleLogin.capabilities().self_hosted && !Service::Fastmail.capabilities().self_hosted);
        assert!(Service::Fastmail.capabilities().toggle && Service::Cloudflare.capabilities().delete);
    }

    #[test]
    fn path_segments() {
        assert_eq!(segment("50c9e585-e7f5-41c4"), Ok("50c9e585-e7f5-41c4"));
        assert_eq!(segment("me@example.com"), Ok("me@example.com"));
        for bad in ["", "..", "a/b", "a?b", "a#b", "a b", "%2e%2e"] {
            assert!(segment(bad).is_err(), "{bad}");
        }
    }
}
