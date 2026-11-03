//! Email aliases for the window: which services there are and what each can do, a
//! service's aliases, turning one off or on, deleting one, making one for a login, and
//! the alias a login uses. Tokens come from the keyring and never leave the daemon; the
//! answers carry addresses and states only. All of it is the app's alone.

use std::time::{Duration, Instant};

use nyx_passwords_core::alias::{self, Account, Alias, Service, UsernameError, UsernameRules};
use nyx_passwords_core::secret::Secret;
use nyx_passwords_proto::Error as Code;
use serde_json::json;

use super::peer::Scope;
use super::vault::{Failure, Result, Vault, locked, need, parse_id, unlock_entry};

/// How long a service's list counts as its aliases' status, for the item view.
const FRESH_FOR: Duration = Duration::from_secs(5 * 60);

fn failed(e: UsernameError) -> Failure {
    Failure::new(Code::Failed, e.to_string())
}

fn service_of(id: &str) -> Result<Service> {
    Service::from_id(id).ok_or_else(|| Failure::new(Code::Failed, "no such email alias service"))
}

impl Vault {
    /// The generator's settings for `service`, and its token.
    async fn alias_account(&self, service: Service) -> Result<(UsernameRules, Secret)> {
        let (mut rules, entry) = {
            let mut st = self.state.lock().await;
            st.session.as_ref().ok_or_else(locked)?;
            (st.settings.refresh().username_rules.clone(), unlock_entry(&st))
        };
        rules.service = service.id().to_string();
        let entry = entry.ok_or_else(|| Failure::new(Code::LoggedOut, "not signed in"))?;
        let token = tokio::task::spawn_blocking(move || entry.load_forwarder_token(service.id()))
            .await
            .map_err(|_| Failure::new(Code::Failed, "the keyring couldn't be read"))?
            .map_err(|e| Failure::new(Code::Failed, e.to_string()))?
            .unwrap_or_else(|| Secret::new(""));
        Ok((rules, token))
    }

    /// The services: `[{id, name, create, list, toggle, delete, self_hosted, token,
    /// chosen, preferred, account}]`. `chosen` is the generator's; `preferred` and
    /// `account` come from Nyx Online Accounts (a Fastmail account there).
    pub async fn alias_services(&self, scope: Scope) -> Result<String> {
        need(scope, Scope::App)?;
        let (chosen, entry) = {
            let mut st = self.state.lock().await;
            (st.settings.refresh().username_rules.service.clone(), unlock_entry(&st))
        };
        let tokens: Vec<bool> = match entry {
            Some(entry) => tokio::task::spawn_blocking(move || {
                Service::ALL.iter().map(|s| entry.load_forwarder_token(s.id()).ok().flatten().is_some()).collect()
            })
            .await
            .unwrap_or_default(),
            None => Vec::new(),
        };
        let online = super::online_accounts::fastmail_account().await;
        let list: Vec<_> = Service::ALL
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let c = s.capabilities();
                let preferred = *s == Service::Fastmail && online.is_some();
                json!({
                    "id": s.id(), "name": s.name(), "create": c.create, "list": c.list, "toggle": c.toggle,
                    "delete": c.delete, "self_hosted": c.self_hosted, "token": tokens.get(i).copied().unwrap_or(false),
                    "chosen": s.id() == chosen, "preferred": preferred,
                    "account": if preferred { online.clone() } else { None },
                })
            })
            .collect();
        Ok(json!(list).to_string())
    }

    /// A service's aliases as JSON `[{id, email, enabled, site, note}]`; kept in memory
    /// for the item view until the vault locks.
    pub async fn list_aliases(&self, scope: Scope, service: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let service = service_of(service)?;
        let (rules, token) = self.alias_account(service).await?;
        let list = Account::new(&rules, &token, None).map_err(failed)?.list().await.map_err(failed)?;
        let mut st = self.state.lock().await;
        st.session.as_ref().ok_or_else(locked)?;
        st.aliases.insert(service.id(), (Instant::now(), list.clone()));
        Ok(json!(list).to_string())
    }

    pub async fn set_alias_enabled(&self, scope: Scope, service: &str, id: &str, on: bool) -> Result<()> {
        need(scope, Scope::App)?;
        let service = service_of(service)?;
        let (rules, token) = self.alias_account(service).await?;
        Account::new(&rules, &token, None).map_err(failed)?.set_enabled(id, on).await.map_err(failed)?;
        let mut st = self.state.lock().await;
        if let Some((_, list)) = st.aliases.get_mut(service.id()) {
            list.iter_mut().filter(|a| a.id == id).for_each(|a| a.enabled = on);
        }
        Ok(())
    }

    pub async fn delete_alias(&self, scope: Scope, service: &str, id: &str) -> Result<()> {
        need(scope, Scope::App)?;
        let service = service_of(service)?;
        let (rules, token) = self.alias_account(service).await?;
        Account::new(&rules, &token, None).map_err(failed)?.delete(id).await.map_err(failed)?;
        let mut st = self.state.lock().await;
        if let Some((_, list)) = st.aliases.get_mut(service.id()) {
            list.retain(|a| a.id != id);
        }
        Ok(())
    }

    /// A new alias from the generator's service for `site`: JSON `{service, id, email}`,
    /// so the editor can link it to the login (`nyx:alias`).
    pub async fn create_alias(&self, scope: Scope, site: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let chosen = self.state.lock().await.settings.refresh().username_rules.service.clone();
        let service = service_of(&chosen)?;
        let (rules, token) = self.alias_account(service).await?;
        let site = (!site.is_empty()).then_some(site);
        let made: Alias = alias::create(&rules, &token, site, None).await.map_err(failed)?;
        self.remember("username", &Secret::new(made.email.as_str())).await;
        let mut st = self.state.lock().await;
        if let Some((_, list)) = st.aliases.get_mut(service.id()) {
            list.insert(0, made.clone());
        }
        Ok(json!({"service": service.id(), "id": made.id, "email": made.email}).to_string())
    }

    /// The alias a login uses: the one its `nyx:alias` field names, or one whose address
    /// is its username in a service's list seen lately. JSON `{service, name, id, email,
    /// enabled}` (`enabled` null until the service's list has been fetched), or `null`.
    pub async fn item_alias(&self, scope: Scope, id: &str) -> Result<String> {
        need(scope, Scope::App)?;
        let id = parse_id(id)?;
        let st = self.state.lock().await;
        let session = st.session.as_ref().ok_or_else(locked)?;
        let entry = session.view.get(id).ok_or_else(|| Failure::new(Code::NotFound, "no such item"))?;
        let username = entry.username.as_ref().map(|u| u.expose().trim().to_lowercase()).unwrap_or_default();
        let marked = super::extension::custom(session, id, nyx_passwords_proto::custom::ALIAS)
            .and_then(|v| v.split_once(':').map(|(s, i)| (s.to_string(), i.to_string())))
            .and_then(|(s, i)| Service::from_id(&s).map(|s| (s, i)));
        let fresh = |s: Service| st.aliases.get(s.id()).filter(|(at, _)| at.elapsed() < FRESH_FOR).map(|(_, l)| l);
        let found = match marked {
            Some((service, alias_id)) => {
                let seen = fresh(service).and_then(|l| l.iter().find(|a| a.id == alias_id));
                Some((service, alias_id, seen.map(|a| a.email.clone()), seen.map(|a| a.enabled)))
            }
            None if !username.is_empty() => Service::ALL.into_iter().find_map(|s| {
                let a = fresh(s)?.iter().find(|a| a.email.to_lowercase() == username)?;
                Some((s, a.id.clone(), Some(a.email.clone()), Some(a.enabled)))
            }),
            None => None,
        };
        Ok(match found {
            Some((service, alias_id, email, enabled)) => json!({
                "service": service.id(), "name": service.name(), "id": alias_id,
                "email": email.unwrap_or(username), "enabled": enabled,
            }),
            None => serde_json::Value::Null,
        }
        .to_string())
    }
}
