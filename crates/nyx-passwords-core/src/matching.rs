//! Whether an item's web address belongs to a page, under Bitwarden's match rules
//! (each address may carry its own): base domain (the default), host, starts with,
//! exact, regular expression, never.
//!
//! One rule is stricter than Bitwarden's: a page served over plain `http://` matches
//! only addresses written with `http://`, so a downgraded or intercepted page doesn't
//! get credentials saved for the secure site.

use url::Url;

/// Bitwarden's `UriMatchType` numbers.
pub const DOMAIN: i64 = 0;
pub const HOST: i64 = 1;
pub const STARTS_WITH: i64 = 2;
pub const EXACT: i64 = 3;
pub const REGEX: i64 = 4;
pub const NEVER: i64 = 5;

/// Regular expressions from the vault are compiled with these limits.
const REGEX_SIZE: usize = 1 << 16;

/// Whether `item_uri` (as saved, under `rule`; `None` is the default, base domain)
/// matches the page at `page`.
pub fn matches(rule: Option<i64>, item_uri: &str, page: &Url) -> bool {
    matches_in(rule, item_uri, page, &[])
}

/// As `matches`, with the account's equivalent domains: groups of base domains that
/// count as one site under the base-domain rule (Bitwarden's "equivalent domains").
pub fn matches_in(rule: Option<i64>, item_uri: &str, page: &Url, equivalent: &[Vec<String>]) -> bool {
    let item_uri = item_uri.trim();
    if item_uri.is_empty() || !matches!(page.scheme(), "http" | "https") {
        return false;
    }
    if page.scheme() == "http" && !item_uri.to_ascii_lowercase().starts_with("http://") {
        return false;
    }
    match rule.unwrap_or(DOMAIN) {
        DOMAIN => match (web_url(item_uri), page.host_str()) {
            (Some(item), Some(page_host)) => item.host_str().is_some_and(|h| {
                let (item, page) = (base_domain(h), base_domain(page_host));
                item == page || equivalent.iter().any(|g| g.contains(&item) && g.contains(&page))
            }),
            _ => false,
        },
        HOST => match web_url(item_uri) {
            Some(item) => {
                item.host_str().is_some()
                    && item.host_str().map(str::to_ascii_lowercase) == page.host_str().map(str::to_ascii_lowercase)
                    && item.port_or_known_default() == page.port_or_known_default()
            }
            None => false,
        },
        STARTS_WITH => page.as_str().starts_with(item_uri),
        EXACT => page.as_str() == item_uri || web_url(item_uri).is_some_and(|i| i.as_str() == page.as_str()),
        REGEX => regex::RegexBuilder::new(item_uri)
            .size_limit(REGEX_SIZE)
            .dfa_size_limit(REGEX_SIZE)
            .build()
            .is_ok_and(|re| re.is_match(page.as_str())),
        // NEVER, and rules this client doesn't know.
        _ => false,
    }
}

/// An item address as a web URL: a missing scheme means https; other schemes
/// (`androidapp://`, `iosapp://`) aren't web addresses.
fn web_url(uri: &str) -> Option<Url> {
    let parsed = Url::parse(uri).ok().filter(|u| u.has_host()).or_else(|| Url::parse(&format!("https://{uri}")).ok())?;
    matches!(parsed.scheme(), "http" | "https").then_some(parsed)
}

/// How Bitwarden clients write an Android app's address: `androidapp://<package>`.
pub const ANDROID_SCHEME: &str = "androidapp://";

/// The package name in an `androidapp://` address, if it is one with a valid name.
pub fn android_package(uri: &str) -> Option<&str> {
    let uri = uri.trim();
    let package = uri
        .get(..ANDROID_SCHEME.len())
        .filter(|s| s.eq_ignore_ascii_case(ANDROID_SCHEME))
        .map(|_| &uri[ANDROID_SCHEME.len()..])?;
    valid_android_package(package).then_some(package)
}

/// The address Bitwarden Android matches for `package` (`com.example.app`), or `None`
/// if it isn't a valid package name. A pasted `androidapp://` address is taken as is.
pub fn android_uri(package: &str) -> Option<String> {
    let package = package.trim();
    let package = android_package(package).unwrap_or(package);
    valid_android_package(package).then(|| format!("{ANDROID_SCHEME}{package}"))
}

/// Android's rule for application ids: at least two dot-separated parts, each starting
/// with a letter and holding only letters, digits and underscores.
pub fn valid_android_package(package: &str) -> bool {
    package.len() <= 255
        && package.split('.').count() >= 2
        && package.split('.').all(|part| {
            let mut chars = part.chars();
            chars.next().is_some_and(|c| c.is_ascii_alphabetic()) && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// The registrable domain ("example.co.uk" for "login.example.co.uk"), lowercase. An
/// IP address, `localhost` or a name without a public suffix is its own base domain.
pub fn base_domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return host;
    }
    match psl::domain_str(&host) {
        Some(d) => d.to_string(),
        None => host,
    }
}

/// Whether a page may use passkeys for `rp_id` (WebAuthn's rule): the page is https
/// (or `localhost`), and the id is its host or a domain its host is under, never a
/// public suffix like `co.uk` or `github.io`.
pub fn valid_rp_id(rp_id: &str, page: &Url) -> bool {
    let Some(host) = page.host_str().map(str::to_ascii_lowercase) else { return false };
    let rp_id = rp_id.trim_end_matches('.').to_ascii_lowercase();
    if page.scheme() != "https" && host != "localhost" {
        return false;
    }
    if rp_id.is_empty() || !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
        return false;
    }
    host == "localhost" || psl::suffix_str(&rp_id) != Some(rp_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passkey_sites() {
        let p = page("https://login.example.co.uk/x");
        assert!(valid_rp_id("login.example.co.uk", &p) && valid_rp_id("example.co.uk", &p));
        assert!(!valid_rp_id("co.uk", &p) && !valid_rp_id("uk", &p) && !valid_rp_id("other.co.uk", &p));
        assert!(!valid_rp_id("ample.co.uk", &p), "a suffix of the name, not of the domain");
        assert!(!valid_rp_id("example.co.uk", &page("http://login.example.co.uk/")));
        assert!(valid_rp_id("localhost", &page("http://localhost:8080/")));
        assert!(!valid_rp_id("github.io", &page("https://alice.github.io/")));
        assert!(valid_rp_id("alice.github.io", &page("https://alice.github.io/")));
    }

    fn page(u: &str) -> Url {
        Url::parse(u).unwrap()
    }

    #[test]
    fn base_domains() {
        assert_eq!(base_domain("login.github.com"), "github.com");
        assert_eq!(base_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(base_domain("user.github.io"), "user.github.io");
        assert_eq!(base_domain("192.168.1.1"), "192.168.1.1");
        assert_eq!(base_domain("localhost"), "localhost");
        assert_eq!(base_domain("GitHub.COM."), "github.com");
    }

    #[test]
    fn domain_rule() {
        let p = page("https://github.com/login?return=/x");
        assert!(matches(None, "https://github.com/session", &p));
        assert!(matches(None, "github.com", &p));
        assert!(matches(Some(DOMAIN), "https://gist.github.com", &p));
        assert!(!matches(None, "https://github.io", &p));
        assert!(!matches(None, "https://evil-github.com", &p));
        assert!(!matches(None, "https://github.com.evil.com", &p));
        // One GitHub Pages site doesn't match another: github.io is a public suffix.
        assert!(!matches(None, "https://alice.github.io", &page("https://mallory.github.io/")));
        assert!(!matches(None, "androidapp://com.github.android", &p));
        assert!(!matches(None, "", &p));
    }

    #[test]
    fn equivalent_domains() {
        let groups = vec![vec!["apple.com".to_string(), "icloud.com".to_string()]];
        let p = page("https://www.icloud.com/");
        assert!(matches_in(None, "https://appleid.apple.com", &p, &groups));
        assert!(!matches(None, "https://appleid.apple.com", &p));
        // Only the base-domain rule widens; the others stay exact.
        assert!(!matches_in(Some(HOST), "https://www.apple.com", &p, &groups));
        assert!(!matches_in(None, "https://apple.com.evil.example", &p, &groups));
        assert!(!matches_in(None, "https://apple.com", &page("http://icloud.com/"), &groups));
    }

    #[test]
    fn plain_http_pages() {
        let p = page("http://github.com/login");
        assert!(!matches(None, "https://github.com", &p));
        assert!(!matches(None, "github.com", &p));
        assert!(matches(None, "http://github.com", &p));
        assert!(matches(None, "http://192.168.1.1", &page("http://192.168.1.1/admin")));
        assert!(!matches(None, "https://github.com", &page("ftp://github.com/")));
        assert!(!matches(None, "https://github.com", &page("file:///etc/passwd")));
    }

    #[test]
    fn other_rules() {
        let p = page("https://login.example.com:8443/app/sign-in");
        assert!(matches(Some(HOST), "https://login.example.com:8443", &p));
        assert!(!matches(Some(HOST), "https://login.example.com", &p));
        assert!(!matches(Some(HOST), "https://example.com:8443", &p));
        assert!(matches(Some(STARTS_WITH), "https://login.example.com:8443/app/", &p));
        assert!(!matches(Some(STARTS_WITH), "https://login.example.com:8443/admin", &p));
        assert!(matches(Some(EXACT), "https://login.example.com:8443/app/sign-in", &p));
        assert!(!matches(Some(EXACT), "https://login.example.com:8443/app", &p));
        assert!(matches(Some(REGEX), r"^https://login\.example\.com(:\d+)?/app/", &p));
        assert!(!matches(Some(REGEX), r"^https://other\.", &p));
        assert!(!matches(Some(REGEX), "(unclosed", &p));
        assert!(!matches(Some(NEVER), "https://login.example.com:8443", &p));
        assert!(!matches(Some(42), "https://login.example.com:8443", &p));
    }

    #[test]
    fn android_apps() {
        assert_eq!(android_package("androidapp://com.instagram.android"), Some("com.instagram.android"));
        assert_eq!(android_package(" AndroidApp://com.example.app_2 "), Some("com.example.app_2"));
        assert_eq!(android_package("https://com.instagram.android"), None);
        assert_eq!(android_package("androidapp://"), None);
        assert_eq!(android_package("androidapp://instagram"), None);
        assert_eq!(android_package("androidapp://com..x"), None);
        assert_eq!(android_package("androidapp://com.1x"), None);
        assert_eq!(android_package("androidapp://com.x/y"), None);
        assert_eq!(android_uri("com.instagram.android").as_deref(), Some("androidapp://com.instagram.android"));
        assert_eq!(android_uri("androidapp://com.x.y").as_deref(), Some("androidapp://com.x.y"));
        assert_eq!(android_uri("com.x-y.z"), None);
        assert_eq!(android_uri(&format!("a.{}", "b".repeat(254))), None);
        // Never a web match, under any rule.
        let p = page("https://instagram.com/");
        for rule in [DOMAIN, HOST, STARTS_WITH, EXACT, REGEX] {
            assert!(!matches(Some(rule), "androidapp://com.instagram.android", &p));
        }
    }

    #[test]
    fn huge_regexes_are_refused() {
        let p = page("https://example.com/");
        assert!(!matches(Some(REGEX), &format!("({}){{500}}", "a|".repeat(200) + "b"), &p));
    }
}
