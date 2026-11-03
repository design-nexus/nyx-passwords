//! Nyx Online Accounts, read for one thing: whether a Fastmail account is set up there,
//! which makes Fastmail the preferred email alias service. `ListAccounts` carries no
//! secrets; managing masked email still needs its own Fastmail API token (with the
//! Masked Email scope), because Online Accounts holds Fastmail only as an app password
//! for mail, calendars and contacts.

use std::time::Duration;

const BUS: &str = "io.github.design_nexus.nyx.Accounts.Preview";
const PATH: &str = "/io/github/design_nexus/nyx/Accounts";
const IFACE: &str = "io.github.design_nexus.nyx.Accounts1";

/// The address of the first Fastmail account in Nyx Online Accounts, if it's running
/// and has one.
pub async fn fastmail_account() -> Option<String> {
    let ask = async {
        let bus = zbus::Connection::session().await.ok()?;
        let reply = bus.call_method(Some(BUS), PATH, Some(IFACE), "ListAccounts", &()).await.ok()?;
        reply.body().deserialize::<String>().ok()
    };
    let json = tokio::time::timeout(Duration::from_secs(2), ask).await.ok().flatten()?;
    fastmail_in(&json)
}

fn fastmail_in(json: &str) -> Option<String> {
    let accounts: Vec<serde_json::Value> = serde_json::from_str(json).ok()?;
    accounts
        .iter()
        .find(|a| a["provider"] == "fastmail")
        .and_then(|a| a["identity"].as_str())
        .map(str::to_string)
        .filter(|identity| identity.contains('@') && identity.len() <= 320)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_fastmail_account() {
        let json = r#"[{"id":"1","provider":"google","identity":"me@gmail.com"},
                       {"id":"2","provider":"fastmail","identity":"me@fastmail.com","status":"ready"}]"#;
        assert_eq!(fastmail_in(json).as_deref(), Some("me@fastmail.com"));
        assert_eq!(fastmail_in(r#"[{"provider":"google","identity":"me@gmail.com"}]"#), None);
        assert_eq!(fastmail_in("not json"), None);
    }
}
