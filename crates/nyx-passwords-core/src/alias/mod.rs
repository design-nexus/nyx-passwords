//! Usernames for the generator: a random word, your address with a tag
//! (`you+tag@example.com`), an address at a catch-all domain, or a new alias from an
//! email forwarding service, as the official clients offer. Forwarding services are
//! asked with the user's own API token; only the site's name goes with the request.
//! The services themselves, and managing their aliases, are in `providers`.

mod providers;

use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};

pub use providers::{Account, Alias, Capabilities, Service};

use crate::secret::Secret;

/// The forwarding services: id and name.
pub const SERVICES: &[(&str, &str)] = &[
    ("simplelogin", "SimpleLogin"),
    ("addy", "addy.io"),
    ("relay", "Firefox Relay"),
    ("duckduckgo", "DuckDuckGo"),
    ("fastmail", "Fastmail"),
    ("forwardemail", "Forward Email"),
    ("cloudflare", "Cloudflare Email Routing"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UsernameKind {
    #[default]
    Word,
    /// `you+tag@example.com`.
    Plus,
    /// `tag@your-catch-all.example`.
    CatchAll,
    /// An alias from a forwarding service.
    Forwarded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UsernameRules {
    pub kind: UsernameKind,
    /// Random word: capitalized, with a number.
    pub capitalize: bool,
    pub number: bool,
    /// Plus addressing: your address.
    pub email: String,
    /// Catch-all: your domain.
    pub domain: String,
    /// Plus and catch-all: the tag is the site's name rather than random letters.
    pub by_site: bool,
    /// Forwarding: the service's id (`SERVICES`).
    pub service: String,
    /// addy.io, Forward Email and Cloudflare: the domain to make the alias at.
    pub service_domain: String,
    /// SimpleLogin and addy.io run on your own server: its address.
    pub service_url: String,
    /// Cloudflare: the zone's id, and the verified address its aliases forward to.
    pub zone_id: String,
    pub forward_to: String,
}

impl Default for UsernameRules {
    fn default() -> Self {
        UsernameRules {
            kind: UsernameKind::Word,
            capitalize: false,
            number: true,
            email: String::new(),
            domain: String::new(),
            by_site: false,
            service: "simplelogin".into(),
            service_domain: String::new(),
            service_url: String::new(),
            zone_id: String::new(),
            forward_to: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsernameError {
    /// The settings lack what this kind needs (an address, a domain, a service).
    Incomplete(&'static str),
    /// The service has no token saved.
    NoToken,
    /// The service refused or couldn't be reached; its own words when it gave some.
    Service(String),
    /// The service can't do that (DuckDuckGo can't list its aliases, say).
    Unsupported,
}

impl std::fmt::Display for UsernameError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Incomplete(what) => write!(f, "set {what} in Passwords' generator settings first"),
            Self::NoToken => f.write_str("save the service's API token in Passwords' generator settings first"),
            Self::Service(why) => f.write_str(why),
            Self::Unsupported => f.write_str("the service doesn't offer that"),
        }
    }
}

impl std::error::Error for UsernameError {}

/// Eight random lowercase letters and digits, for tags.
fn tag() -> String {
    let set: Vec<char> = ('a'..='z').chain('0'..='9').collect();
    let mut rng = rand::rng();
    (0..8).map(|_| *set.choose(&mut rng).expect("set isn't empty")).collect()
}

/// The site's name for a tag: its base domain (`github.com`), from a page address or host.
fn site_name(site: &str) -> Option<String> {
    let host = crate::vault::host_of(site)?;
    Some(crate::matching::base_domain(&host))
}

/// A username that doesn't need a service: a word, a tagged address or a catch-all one.
/// `site` is the login's address, for tags made from it.
pub fn local(rules: &UsernameRules, site: Option<&str>) -> Result<Secret, UsernameError> {
    let tag_for = |by_site: bool| site.filter(|_| by_site).and_then(site_name).unwrap_or_else(tag);
    match rules.kind {
        UsernameKind::Word => {
            let list = bitwarden_crypto::EFF_LONG_WORD_LIST;
            let mut rng = rand::rng();
            let mut word = list.choose(&mut rng).expect("word list isn't empty").to_string();
            if rules.capitalize
                && let Some(first) = word.get_mut(0..1)
            {
                first.make_ascii_uppercase();
            }
            if rules.number {
                word.push_str(&format!("{:04}", rand::random_range(0..10_000)));
            }
            Ok(Secret::new(word))
        }
        UsernameKind::Plus => {
            let (user, domain) = rules.email.trim().split_once('@').ok_or(UsernameError::Incomplete("your email address"))?;
            if user.is_empty() || domain.is_empty() {
                return Err(UsernameError::Incomplete("your email address"));
            }
            let user = user.split('+').next().unwrap_or(user);
            Ok(Secret::new(format!("{user}+{}@{domain}", tag_for(rules.by_site))))
        }
        UsernameKind::CatchAll => {
            let domain = rules.domain.trim().trim_start_matches('@');
            if domain.is_empty() {
                return Err(UsernameError::Incomplete("your catch-all domain"));
            }
            Ok(Secret::new(format!("{}@{domain}", tag_for(rules.by_site))))
        }
        UsernameKind::Forwarded => Err(UsernameError::Incomplete("a username kind")),
    }
}

/// A new alias from the configured forwarding service. `base` replaces the service's
/// public address (for tests); `rules.service_url` does for self-hosted ones.
pub async fn forwarded(
    rules: &UsernameRules,
    token: &Secret,
    site: Option<&str>,
    base: Option<&str>,
) -> Result<Secret, UsernameError> {
    create(rules, token, site, base).await.map(|a| Secret::new(a.email))
}

/// As `forwarded`, with the alias's id at its service, to link it to the login.
pub async fn create(
    rules: &UsernameRules,
    token: &Secret,
    site: Option<&str>,
    base: Option<&str>,
) -> Result<Alias, UsernameError> {
    Account::new(rules, token, base)?.create(site).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_usernames() {
        let mut rules = UsernameRules { number: false, ..UsernameRules::default() };
        let word = local(&rules, None).unwrap();
        assert!(word.expose().chars().all(|c| c.is_ascii_lowercase() || c == '-'), "{}", word.expose());
        rules.number = true;
        rules.capitalize = true;
        let word = local(&rules, None).unwrap();
        assert!(
            word.expose().chars().next().unwrap().is_ascii_uppercase() && word.expose().ends_with(|c: char| c.is_ascii_digit())
        );

        rules.kind = UsernameKind::Plus;
        assert_eq!(local(&rules, None).err(), Some(UsernameError::Incomplete("your email address")));
        rules.email = "me+old@example.com".into();
        let tagged = local(&rules, None).unwrap();
        assert!(
            tagged.expose().starts_with("me+")
                && tagged.expose().ends_with("@example.com")
                && tagged.expose().len() == "me+12345678@example.com".len()
        );
        rules.by_site = true;
        assert_eq!(local(&rules, Some("https://login.github.com/x")).unwrap().expose(), "me+github.com@example.com");

        rules.kind = UsernameKind::CatchAll;
        rules.domain = "@catch.example".into();
        assert_eq!(local(&rules, Some("github.com")).unwrap().expose(), "github.com@catch.example");
        rules.by_site = false;
        assert!(local(&rules, Some("github.com")).unwrap().expose().ends_with("@catch.example"));
    }
}
