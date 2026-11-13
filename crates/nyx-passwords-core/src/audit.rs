//! The security report: weak, reused and old passwords, worked out in memory from the
//! unlocked vault; and, only when the user asks, which passwords appear in known data
//! breaches (Have I Been Pwned's k-anonymity range API: only the first five characters
//! of each password's SHA-1 hash leave the device).

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{Keys, breach_hash, password_digest};
use crate::model::{Cipher, Kind, Sync};
use crate::secret::Secret;

/// Have I Been Pwned's password range API.
pub const BREACH_API: &str = "https://api.pwnedpasswords.com";
/// The largest range answer read.
const RANGE_MAX: usize = 1 << 20;
/// A password unchanged for longer than this is reported as old.
pub const OLD_DAYS: u64 = 365;
/// zxcvbn scores below this (0 to 4) are weak, as in the official clients.
const STRONG_ENOUGH: u8 = 3;

/// What the report says about one login. Only logins with something to say are listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: Uuid,
    /// How many other logins use the same password.
    pub reused: usize,
    /// Those other logins.
    pub same_as: Vec<Uuid>,
    pub weak: bool,
    /// Days since the password last changed, when that's over `OLD_DAYS`.
    pub age_days: Option<u64>,
}

/// Strength results kept between reports: an item is scored again only when its
/// revision changes. Holds no passwords.
pub type StrengthCache = HashMap<Uuid, (String, bool)>;

/// The logins the report covers: live, readable, with a password this account may see.
fn audited<'a>(keys: &'a Keys, sync: &'a Sync) -> impl Iterator<Item = (&'a Cipher, Secret)> + 'a {
    sync.ciphers.iter().filter(|c| c.kind() == Kind::Login && !c.is_deleted() && c.can_view_password()).filter_map(move |c| {
        let password = c.login.as_ref()?.password.as_deref()?;
        let mut key = keys.item(c.organization_id, c.key.as_deref()).ok()?;
        let plain = key.decrypt(password).ok()?;
        (!plain.is_empty()).then_some((c, plain))
    })
}

pub fn audit(keys: &Keys, sync: &Sync, now: SystemTime, cache: &mut StrengthCache) -> Vec<Finding> {
    audit_some(keys, sync, now, cache, None)
}

/// The report for these logins only, as `audit` would find them: reuse is still counted
/// against every password (a digest each, which is quick), but only these are scored
/// for strength, which is what takes the time on a large vault.
pub fn audit_only(keys: &Keys, sync: &Sync, now: SystemTime, cache: &mut StrengthCache, ids: &[Uuid]) -> Vec<Finding> {
    audit_some(keys, sync, now, cache, Some(ids))
}

fn audit_some(keys: &Keys, sync: &Sync, now: SystemTime, cache: &mut StrengthCache, only: Option<&[Uuid]>) -> Vec<Finding> {
    let today = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() / 86_400);
    // Digests, not passwords, and only for the length of the report.
    let mut by_password: HashMap<[u8; 32], Vec<Uuid>> = HashMap::new();
    let mut rows = Vec::new();
    for (c, password) in audited(keys, sync) {
        let digest = password_digest(&password);
        by_password.entry(digest).or_default().push(c.id);
        if only.is_some_and(|ids| !ids.contains(&c.id)) {
            continue;
        }
        let weak = match cache.get(&c.id) {
            Some((revision, weak)) if *revision == c.revision_date => *weak,
            _ => {
                let weak = is_weak(keys, c, &password);
                cache.insert(c.id, (c.revision_date.clone(), weak));
                weak
            }
        };
        let changed = c.login.as_ref().and_then(|l| l.extra.get("passwordRevisionDate")).and_then(|v| v.as_str());
        let changed = changed.or(c.extra.get("creationDate").and_then(|v| v.as_str())).and_then(days_since_epoch);
        let age = changed.map(|d| today.saturating_sub(d)).filter(|&a| a > OLD_DAYS);
        rows.push((c.id, digest, weak, age));
    }
    rows.into_iter()
        .map(|(id, digest, weak, age_days)| {
            let same_as: Vec<Uuid> = by_password[&digest].iter().copied().filter(|other| *other != id).collect();
            Finding { id, reused: same_as.len(), same_as, weak, age_days }
        })
        .filter(|f| f.reused > 0 || f.weak || f.age_days.is_some())
        .collect()
}

/// zxcvbn's estimate, counting the item's own name and username against the password.
fn is_weak(keys: &Keys, c: &Cipher, password: &Secret) -> bool {
    let mut inputs = Vec::new();
    if let Ok(mut key) = keys.item(c.organization_id, c.key.as_deref()) {
        inputs.extend(key.decrypt(&c.name).ok());
        inputs.extend(c.login.as_ref().and_then(|l| key.decrypt_opt(l.username.as_deref()).ok().flatten()));
    }
    let inputs: Vec<&str> = inputs.iter().map(|s| s.expose()).collect();
    u8::from(zxcvbn::zxcvbn(password.expose(), &inputs).score()) < STRONG_ENOUGH
}

/// `2026-10-20T04:13:05.099Z` as whole days since the epoch.
fn days_since_epoch(date: &str) -> Option<u64> {
    let year: i64 = date.get(0..4)?.parse().ok()?;
    let month: i64 = date.get(5..7)?.parse().ok()?;
    let day: i64 = date.get(8..10)?.parse().ok()?;
    // Howard Hinnant's days-from-civil.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    u64::try_from(era * 146_097 + doe - 719_468).ok()
}

/// Each audited login's password as an upper-case SHA-1 hex digest, for the breach
/// check. Worked out under the vault lock; the lookups happen after it's released.
pub fn breach_hashes(keys: &Keys, sync: &Sync) -> Vec<(Uuid, Zeroizing<String>)> {
    audited(keys, sync).map(|(c, password)| (c.id, breach_hash(&password))).collect()
}

/// How often each password appears in Have I Been Pwned's breach data (`base` is
/// `BREACH_API`). Asks once per distinct five-character hash prefix, with padding on, so
/// neither the passwords nor their full hashes are sent. Logins with no breaches are
/// left out.
pub async fn breaches(base: &str, hashes: &[(Uuid, Zeroizing<String>)]) -> Result<Vec<(Uuid, u64)>, reqwest::Error> {
    let http = reqwest::Client::builder().user_agent("nyx-passwords").timeout(Duration::from_secs(30)).build()?;
    let mut by_prefix: HashMap<&str, Vec<(Uuid, &str)>> = HashMap::new();
    for (id, hash) in hashes {
        let (prefix, suffix) = hash.split_at(5);
        by_prefix.entry(prefix).or_default().push((*id, suffix));
    }
    let mut found = Vec::new();
    for (prefix, wanted) in by_prefix {
        let mut resp =
            http.get(format!("{base}/range/{prefix}")).header("Add-Padding", "true").send().await?.error_for_status()?;
        // A padded answer is around 30 KB; one far larger isn't an answer, and is skipped.
        let mut raw = Vec::new();
        let mut too_large = false;
        while let Some(chunk) = resp.chunk().await? {
            if raw.len() + chunk.len() > RANGE_MAX {
                too_large = true;
                break;
            }
            raw.extend_from_slice(&chunk);
        }
        if too_large {
            continue;
        }
        let body = String::from_utf8_lossy(&raw);
        let counts: HashMap<&str, u64> = body
            .lines()
            .filter_map(|line| line.trim().split_once(':'))
            .filter_map(|(suffix, count)| Some((suffix, count.trim().parse().ok()?)))
            .collect();
        for (id, suffix) in wanted {
            // Padding lines carry a count of 0.
            if let Some(&n) = counts.get(suffix).filter(|n| **n > 0) {
                found.push((id, n));
            }
        }
    }
    Ok(found)
}

/// Checks that need no password and no network: a login reached over plain `http://`,
/// logins that look like the same account twice, and records missing what they're for.
/// Heuristics, unlike a breach: they say "look at this", not "this was exposed".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hygiene {
    pub id: Uuid,
    /// One of its web addresses is `http://` to a public host.
    pub insecure_address: bool,
    /// Other logins for the same site and username.
    pub duplicates: Vec<Uuid>,
    /// What it lacks: `password`, `address`, `card number`.
    pub incomplete: Vec<&'static str>,
}

pub fn hygiene(keys: &Keys, sync: &Sync, view: &crate::vault::View) -> Vec<Hygiene> {
    let mut groups: HashMap<(String, String), Vec<Uuid>> = HashMap::new();
    let mut rows: Vec<Hygiene> = Vec::new();
    for e in view.entries.iter().filter(|e| !e.deleted && e.readable) {
        let Some(c) = sync.ciphers.iter().find(|c| c.id == e.id) else { continue };
        let mut row = Hygiene { id: e.id, ..Default::default() };
        match e.kind {
            Kind::Login => {
                row.insecure_address = e.uris.iter().any(|u| insecure(u.expose()));
                let passkeys = c.login.as_ref().and_then(|l| l.extra.get("fido2Credentials")).and_then(|v| v.as_array());
                let signs_in_with = custom_field(keys, c, nyx_passwords_proto::custom::SIGN_IN_WITH).is_some();
                if !e.has_password && passkeys.is_none_or(|p| p.is_empty()) && !signs_in_with && e.view_password {
                    row.incomplete.push("password");
                }
                // A template without an address (a Wi-Fi network, an API key) isn't missing one.
                let wants_address = match &e.template {
                    None => true,
                    Some(id) => crate::templates::builtin()
                        .iter()
                        .find(|t| t.id == *id)
                        .is_some_and(|t| t.label_for(crate::templates::Slot::Uri).is_some()),
                };
                if wants_address && e.uris.iter().all(|u| u.expose().trim().is_empty()) {
                    row.incomplete.push("address");
                }
                if let (Some(host), Some(user)) = (&e.host, &e.username) {
                    let user = user.expose().trim().to_lowercase();
                    if !user.is_empty() {
                        groups.entry((crate::matching::base_domain(host), user)).or_default().push(e.id);
                    }
                }
            }
            Kind::Card => {
                let number = c.card.as_ref().and_then(|v| v["number"].as_str()).filter(|n| !n.is_empty());
                if number.is_none() {
                    row.incomplete.push("card number");
                }
            }
            _ => {}
        }
        rows.push(row);
    }
    for ids in groups.values().filter(|ids| ids.len() > 1) {
        for row in rows.iter_mut().filter(|r| ids.contains(&r.id)) {
            row.duplicates = ids.iter().copied().filter(|id| *id != row.id).collect();
        }
    }
    rows.retain(|r| r.insecure_address || !r.duplicates.is_empty() || !r.incomplete.is_empty());
    rows
}

/// A plain-`http` address to a host on the internet. Loopback, private networks and
/// `.local`/`.lan` names (routers, printers) are left alone.
fn insecure(uri: &str) -> bool {
    let Ok(url) = url::Url::parse(uri.trim()) else { return false };
    if url.scheme() != "http" {
        return false;
    }
    match url.host() {
        Some(url::Host::Ipv4(ip)) => !(ip.is_loopback() || ip.is_private() || ip.is_link_local()),
        Some(url::Host::Ipv6(ip)) => !(ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()),
        Some(url::Host::Domain(d)) => {
            let d = d.trim_end_matches('.').to_ascii_lowercase();
            !(d == "localhost" || [".local", ".lan", ".home.arpa", ".internal", ".localhost"].iter().any(|s| d.ends_with(s)))
        }
        None => false,
    }
}

fn custom_field(keys: &Keys, c: &Cipher, name: &str) -> Option<String> {
    let mut key = keys.item(c.organization_id, c.key.as_deref()).ok()?;
    let f = c
        .fields
        .iter()
        .flatten()
        .find(|f| key.decrypt_opt(f.name.as_deref()).ok().flatten().is_some_and(|n| n.expose() == name))?;
    key.decrypt_opt(f.value.as_deref()).ok().flatten().map(|v| v.expose().to_string())
}

/// 2fa.directory's list of sites that offer one-time codes (TOTP). Downloaded whole, on
/// request, so no site of the vault's is sent anywhere; matched here.
pub const TWO_FACTOR_LIST: &str = "https://api.2fa.directory/v3/totp.json";
/// The list is about 300 KB; anything far larger isn't it.
const TWO_FACTOR_MAX: usize = 8 << 20;

/// Sites that offer one-time codes, by domain, with their how-to page when it's https.
#[derive(Debug, Default, Clone)]
pub struct TwoFactorSites {
    by_domain: HashMap<String, Option<String>>,
}

impl TwoFactorSites {
    pub fn parse(json: &[u8]) -> Option<TwoFactorSites> {
        let list: Vec<(String, serde_json::Value)> = serde_json::from_slice(json).ok()?;
        let mut by_domain = HashMap::new();
        for (_, site) in list {
            let docs =
                site["documentation"].as_str().filter(|u| u.starts_with("https://") && u.len() <= 2048).map(str::to_string);
            let extra = site["additional-domains"].as_array().cloned().unwrap_or_default();
            for domain in std::iter::once(&site["domain"]).chain(extra.iter()).filter_map(|d| d.as_str()) {
                let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
                if !domain.is_empty() && domain.len() <= 253 {
                    by_domain.entry(domain).or_insert_with(|| docs.clone());
                }
            }
        }
        (!by_domain.is_empty()).then_some(TwoFactorSites { by_domain })
    }

    pub async fn fetch(url: &str) -> Result<TwoFactorSites, String> {
        let http = reqwest::Client::builder()
            .user_agent("nyx-passwords")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| e.to_string())?;
        let unreachable = |_| "2fa.directory couldn't be reached".to_string();
        let mut resp = http.get(url).send().await.map_err(unreachable)?.error_for_status().map_err(unreachable)?;
        let mut raw = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(unreachable)? {
            if raw.len() + chunk.len() > TWO_FACTOR_MAX {
                return Err("2fa.directory's answer was too large".into());
            }
            raw.extend_from_slice(&chunk);
        }
        Self::parse(&raw).ok_or_else(|| "2fa.directory's answer wasn't understood".into())
    }

    /// The site's entry for a host: the host itself, or its base domain.
    fn find(&self, host: &str) -> Option<&Option<String>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.by_domain.get(&host).or_else(|| self.by_domain.get(&crate::matching::base_domain(&host)))
    }
}

/// Logins for sites that offer one-time codes but that have no one-time code key (or
/// passkey) saved, with the site's how-to page if known.
pub fn missing_two_factor(sync: &Sync, view: &crate::vault::View, sites: &TwoFactorSites) -> Vec<(Uuid, Option<String>)> {
    view.entries
        .iter()
        .filter(|e| e.kind == Kind::Login && !e.deleted && e.readable && !e.has_totp)
        .filter(|e| {
            let c = sync.ciphers.iter().find(|c| c.id == e.id);
            let passkeys = c.and_then(|c| c.login.as_ref()?.extra.get("fido2Credentials")?.as_array().map(|a| !a.is_empty()));
            !passkeys.unwrap_or(false)
        })
        .filter_map(|e| {
            let docs = e.uris.iter().filter_map(|u| crate::vault::host_of(u.expose())).find_map(|h| sites.find(&h).cloned())?;
            Some((e.id, docs))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_addresses() {
        assert!(insecure("http://shop.example.com/login"));
        assert!(!insecure("https://shop.example.com/login"));
        assert!(!insecure("http://192.168.1.1/admin"));
        assert!(!insecure("http://10.0.0.5"));
        assert!(!insecure("http://localhost:8080"));
        assert!(!insecure("http://printer.local"));
        assert!(!insecure("http://router.lan"));
        assert!(insecure("http://203.0.113.9/"));
        assert!(!insecure("androidapp://com.example"));
        assert!(!insecure("example.com"), "no scheme means https");
    }

    #[test]
    fn two_factor_list() {
        let json = br#"[["GitHub", {"domain": "github.com", "additional-domains": ["github.dev"], "tfa": ["totp"],
                         "documentation": "https://docs.github.com/2fa"}],
                        ["Odd", {"domain": "odd.example", "documentation": "javascript:alert(1)"}]]"#;
        let sites = TwoFactorSites::parse(json).unwrap();
        assert_eq!(sites.find("github.com"), Some(&Some("https://docs.github.com/2fa".to_string())));
        assert_eq!(sites.find("gist.github.com"), Some(&Some("https://docs.github.com/2fa".to_string())));
        assert!(sites.find("GITHUB.DEV.").is_some());
        assert_eq!(sites.find("odd.example"), Some(&None), "only https how-to pages");
        assert_eq!(sites.find("gitlab.com"), None);
        assert!(TwoFactorSites::parse(b"{}").is_none());
        assert!(TwoFactorSites::parse(b"[]").is_none());
    }

    #[test]
    fn dates() {
        assert_eq!(days_since_epoch("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(days_since_epoch("2000-03-01T12:00:00.5Z"), Some(11_017));
        assert_eq!(days_since_epoch("2026-10-20T04:13:05.099157Z"), Some(20_746));
        assert_eq!(days_since_epoch("soon"), None);
    }
}
