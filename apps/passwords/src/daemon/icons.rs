//! Website icons, when the user turns them on: fetched through the server's icon
//! service and kept in memory while the vault is open. Nothing is written to disk: the
//! hosts would show which sites the vault has logins for. Only the host goes to the
//! server.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nyx_passwords_core::api::Server;
use nyx_passwords_proto::Error as Code;
use tokio::sync::{Mutex, Semaphore};

use super::vault::{Failure, Result};

/// Icons fetched at once.
const AT_ONCE: usize = 4;
/// Icons kept; past this the oldest answers go first.
const KEEP: usize = 2000;
/// A host whose fetch failed isn't asked for again for this long.
const RETRY_AFTER: Duration = Duration::from_secs(10 * 60);

#[derive(Clone, Default)]
pub struct Icons(Arc<Inner>);

struct Inner {
    permits: Semaphore,
    /// Each host's icon, or `None` when it has none.
    known: Mutex<HashMap<String, Option<Vec<u8>>>>,
    /// When fetching each of these last failed.
    failed: Mutex<HashMap<String, Instant>>,
    /// Hosts being fetched now.
    fetching: Mutex<HashSet<String>>,
    /// The server's answer for a site without an icon, to tell real icons from it.
    generic: Mutex<Option<Vec<u8>>>,
}

impl Default for Inner {
    fn default() -> Self {
        Inner {
            permits: Semaphore::new(AT_ONCE),
            known: Mutex::new(HashMap::new()),
            failed: Mutex::new(HashMap::new()),
            fetching: Mutex::new(HashSet::new()),
            generic: Mutex::new(None),
        }
    }
}

/// A host name to ask for: letters, digits, dots and hyphens, with a dot, and not an
/// address.
fn valid(host: &str) -> bool {
    host.len() <= 253
        && host.contains('.')
        && host.parse::<std::net::IpAddr>().is_err()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

impl Icons {
    /// `host`'s icon (PNG or whatever the site has), fetching it the first time.
    /// `NoField` when the site has none. With `wait`, a fetch that takes longer goes on
    /// without the caller, for next time.
    pub async fn get(&self, server: &Server, host: &str, wait: Option<Duration>) -> Result<Vec<u8>> {
        let host = host.trim().trim_start_matches("www.").to_ascii_lowercase();
        if !valid(&host) {
            return Err(Failure::new(Code::NoUrl, "not a site name"));
        }
        if let Some(known) = self.0.known.lock().await.get(&host) {
            return known.clone().ok_or_else(none);
        }
        if self.0.failed.lock().await.get(&host).is_some_and(|at| at.elapsed() < RETRY_AFTER) {
            return Err(none());
        }
        if !self.0.fetching.lock().await.insert(host.clone()) && wait.is_some() {
            return Err(none());
        }
        let (icons, server) = (self.clone(), server.clone());
        let fetch = tokio::spawn(async move {
            let icon = icons.fetch(&server, &host).await;
            icons.0.fetching.lock().await.remove(&host);
            icon
        });
        let done = match wait {
            Some(wait) => tokio::time::timeout(wait, fetch).await.ok(),
            None => Some(fetch.await),
        };
        match done {
            Some(Ok(icon)) => icon,
            _ => Err(none()),
        }
    }

    async fn fetch(&self, server: &Server, host: &str) -> Result<Vec<u8>> {
        let _permit = self.0.permits.acquire().await.map_err(|_| Failure::new(Code::Failed, "busy"))?;
        let generic = {
            let mut generic = self.0.generic.lock().await;
            if generic.is_none() {
                *generic = server.icon("icon.invalid").await.ok();
            }
            generic.clone()
        };
        let icon = match server.icon(host).await {
            Ok(bytes) if generic.as_ref() != Some(&bytes) => Some(bytes),
            Err(_) => {
                self.0.failed.lock().await.insert(host.to_string(), Instant::now());
                return Err(none());
            }
            Ok(_) => None,
        };
        let mut known = self.0.known.lock().await;
        if known.len() >= KEEP {
            known.clear();
        }
        known.insert(host.to_string(), icon.clone());
        icon.ok_or_else(none)
    }

    /// Locking: the icons, and with them the sites, are forgotten.
    pub async fn forget(&self) {
        self.0.known.lock().await.clear();
        self.0.failed.lock().await.clear();
    }
}

fn none() -> Failure {
    Failure::new(Code::NoField, "no icon")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_names() {
        assert!(valid("github.com") && valid("login.example.co.uk") && valid("a-b.example"));
        for bad in ["", "localhost", "192.168.1.1", "../etc", "a..b", "exa mple.com", "Ex.com", "x/y.com", "é.com"] {
            assert!(!valid(bad), "{bad}");
        }
    }
}
