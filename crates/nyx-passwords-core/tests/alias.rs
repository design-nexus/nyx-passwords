//! The email alias services, against a stand-in that answers as each does and records
//! what it was asked. No real service is contacted.

use nyx_passwords_core::alias::{self, UsernameError, UsernameKind, UsernameRules};
use nyx_passwords_core::secret::Secret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Answers each request by its path and keeps the requests (lowercased headers).
async fn stand_in() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else { return };
            let mut buf = vec![0u8; 16384];
            let n = conn.read(&mut buf).await.unwrap();
            let mut request = String::from_utf8_lossy(&buf[..n]).to_string();
            // The body may come in a second packet.
            if !request.contains("\r\n\r\n{") && request.to_lowercase().contains("content-length") {
                let n = conn.read(&mut buf).await.unwrap_or(0);
                request.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
            let method = request.split_whitespace().next().unwrap_or_default().to_string();
            let path = request.split_whitespace().nth(1).unwrap_or_default().to_string();
            let (status, body) = match (method.as_str(), path.split('?').next().unwrap()) {
                (_, _) if request.to_lowercase().contains("bad") => (401, "{}".to_string()),
                ("POST", "/api/alias/random/new") => (201, r#"{"alias":"x1@simplelogin.example","id":11}"#.to_string()),
                ("GET", "/api/v2/aliases") if path.ends_with("page_id=0") => {
                    (200, r#"{"aliases":[{"id":11,"email":"x1@simplelogin.example","enabled":true,"note":"n"}]}"#.into())
                }
                ("GET", "/api/v2/aliases") => (200, r#"{"aliases":[]}"#.into()),
                ("GET", "/api/aliases/11") => (200, r#"{"id":11,"enabled":true}"#.into()),
                ("POST", "/api/aliases/11/toggle") => (200, r#"{"enabled":false}"#.into()),
                ("DELETE", "/api/aliases/11") => (200, r#"{"deleted":true}"#.into()),
                ("POST", "/api/v1/aliases") => (201, r#"{"data":{"id":"a2","email":"x2@addy.example"}}"#.into()),
                ("GET", "/api/v1/aliases") => (
                    200,
                    r#"{"data":[{"id":"a2","email":"x2@addy.example","active":false}],"meta":{"last_page":1}}"#.into(),
                ),
                ("POST", "/api/v1/active-aliases") | ("DELETE", "/api/v1/active-aliases/a2") | ("DELETE", "/api/v1/aliases/a2") => {
                    (204, String::new())
                }
                ("POST", "/api/v1/relayaddresses/") => (201, r#"{"id":3,"full_address":"x3@mozmail.com"}"#.into()),
                ("GET", "/api/v1/relayaddresses/") => {
                    (200, r#"[{"id":3,"full_address":"x3@mozmail.com","enabled":true,"generated_for":"github.com"}]"#.into())
                }
                ("PATCH" | "DELETE", "/api/v1/relayaddresses/3/") => (200, "{}".into()),
                (_, "/api/email/addresses") => (201, r#"{"address":"x4"}"#.into()),
                (_, "/jmap/session") => {
                    (200, r#"{"primaryAccounts":{"https://www.fastmail.com/dev/maskedemail":"acct1"}}"#.into())
                }
                (_, "/jmap/api/") if request.contains("MaskedEmail/get") => (
                    200,
                    r#"{"methodResponses":[["MaskedEmail/get",{"list":[
                        {"id":"m5","email":"x5@fastmail.example","state":"enabled","forDomain":"github.com"},
                        {"id":"m6","email":"gone@fastmail.example","state":"deleted"},
                        {"id":"m7","email":"off@fastmail.example","state":"disabled"}]},"0"]]}"#
                        .into(),
                ),
                (_, "/jmap/api/") if request.contains("\"update\"") => {
                    (200, r#"{"methodResponses":[["MaskedEmail/set",{"updated":{"m5":null}},"0"]]}"#.into())
                }
                (_, "/jmap/api/") => (
                    200,
                    r#"{"methodResponses":[["MaskedEmail/set",{"created":{"new":{"id":"m5","email":"x5@fastmail.example"}}},"0"]]}"#
                        .into(),
                ),
                ("GET", "/v1/domains/fwd.example/aliases") => {
                    (200, r#"[{"id":"f6","name":"x6","is_enabled":true,"labels":["github.com"]}]"#.into())
                }
                ("PUT" | "DELETE", "/v1/domains/fwd.example/aliases/f6") => (200, "{}".into()),
                (_, p) if p.starts_with("/v1/domains/") => (200, r#"{"id":"f6","name":"x6","domain":{"name":"fwd.example"}}"#.into()),
                ("POST", "/zones/z1/email/routing/rules") => (200, r#"{"success":true,"result":{"id":"r7"}}"#.into()),
                ("GET", "/zones/z1/email/routing/rules") => (
                    200,
                    r#"{"success":true,"result":[
                        {"id":"r7","enabled":true,"name":"n","matchers":[{"type":"literal","field":"to","value":"x7@cf.example"}]},
                        {"id":"all","enabled":true,"matchers":[{"type":"all"}]}],"result_info":{"total_pages":1}}"#
                        .into(),
                ),
                ("GET", "/zones/z1/email/routing/rules/r7") => (
                    200,
                    r#"{"success":true,"result":{"id":"r7","enabled":true,"actions":[{"type":"forward","value":["me@example.com"]}],
                        "matchers":[{"type":"literal","field":"to","value":"x7@cf.example"}],"name":"n","priority":0}}"#
                        .into(),
                ),
                ("PUT" | "DELETE", "/zones/z1/email/routing/rules/r7") => (200, r#"{"success":true}"#.into()),
                _ => (404, "{}".into()),
            };
            log.lock().unwrap().push(request.to_lowercase());
            let reply = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            conn.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    (base, seen)
}

#[tokio::test]
async fn each_service_makes_an_alias() {
    let (base, seen) = stand_in().await;
    let token = Secret::new("tok123");
    let site = Some("https://login.github.com/session");
    let mut rules =
        UsernameRules { kind: UsernameKind::Forwarded, service_domain: "fwd.example".into(), ..UsernameRules::default() };
    for (service, expected, header) in [
        ("simplelogin", "x1@simplelogin.example", "authentication: tok123"),
        ("addy", "x2@addy.example", "authorization: bearer tok123"),
        ("relay", "x3@mozmail.com", "authorization: token tok123"),
        ("duckduckgo", "x4@duck.com", "authorization: bearer tok123"),
        ("fastmail", "x5@fastmail.example", "authorization: bearer tok123"),
        ("forwardemail", "x6@fwd.example", "authorization: basic "),
    ] {
        rules.service = service.into();
        let made = alias::forwarded(&rules, &token, site, Some(&base)).await.unwrap_or_else(|e| panic!("{service}: {e}"));
        assert_eq!(made.expose(), expected, "{service}");
        let last = seen.lock().unwrap().last().cloned().unwrap();
        assert!(last.contains(header), "{service}: {last}");
        if service != "duckduckgo" {
            assert!(last.contains("github.com"), "{service} names the site: {last}");
        }
    }
    // SimpleLogin gets the site as `hostname`.
    assert!(seen.lock().unwrap()[0].contains("?hostname=github.com"));

    rules.service = "duckduckgo".into();
    let refused = alias::forwarded(&rules, &Secret::new("bad"), site, Some(&base)).await;
    assert_eq!(refused.err(), Some(UsernameError::Service("the service refused the token".into())));
    assert_eq!(alias::forwarded(&rules, &Secret::new(""), site, Some(&base)).await.err(), Some(UsernameError::NoToken));
    rules.service = "addy".into();
    rules.service_domain.clear();
    assert!(matches!(alias::forwarded(&rules, &token, site, Some(&base)).await, Err(UsernameError::Incomplete(_))));
}

/// Every service that allows it lists its aliases, turns one off and deletes it, through
/// the one interface; DuckDuckGo says it can't.
#[tokio::test]
async fn aliases_are_managed() {
    let (base, seen) = stand_in().await;
    let token = Secret::new("tok123");
    let rules = |service: &str| UsernameRules {
        kind: UsernameKind::Forwarded,
        service: service.into(),
        service_domain: if service == "cloudflare" { "cf.example".into() } else { "fwd.example".into() },
        zone_id: "z1".into(),
        forward_to: "me@example.com".into(),
        ..UsernameRules::default()
    };
    for (service, email, id, enabled) in [
        ("simplelogin", "x1@simplelogin.example", "11", true),
        ("addy", "x2@addy.example", "a2", false),
        ("relay", "x3@mozmail.com", "3", true),
        ("fastmail", "x5@fastmail.example", "m5", true),
        ("forwardemail", "x6@fwd.example", "f6", true),
        ("cloudflare", "x7@cf.example", "r7", true),
    ] {
        let r = rules(service);
        let account = alias::Account::new(&r, &token, Some(&base)).unwrap();
        let list = account.list().await.unwrap_or_else(|e| panic!("{service}: {e}"));
        let first = &list[0];
        assert_eq!((first.email.as_str(), first.id.as_str(), first.enabled), (email, id, enabled), "{service}");
        account.set_enabled(id, false).await.unwrap_or_else(|e| panic!("{service}: {e}"));
        account.delete(id).await.unwrap_or_else(|e| panic!("{service}: {e}"));
    }
    let log = seen.lock().unwrap().clone();
    let asked = |what: &str| log.iter().any(|r| r.starts_with(what));
    // SimpleLogin only flips: it was on, so it was flipped once.
    assert!(asked("post /api/aliases/11/toggle"));
    assert!(asked("delete /api/v1/active-aliases/a2") && asked("delete /api/v1/aliases/a2"));
    assert!(log.iter().any(|r| r.starts_with("patch /api/v1/relayaddresses/3/") && r.contains(r#""enabled":false"#)));
    assert!(log.iter().any(|r| r.contains(r#""update":{"m5":{"state":"disabled"}}"#)));
    assert!(log.iter().any(|r| r.contains(r#""update":{"m5":{"state":"deleted"}}"#)));
    assert!(log.iter().any(|r| r.starts_with("put /v1/domains/fwd.example/aliases/f6") && r.contains(r#""is_enabled":false"#)));
    assert!(log.iter().any(|r| r.starts_with("put /zones/z1/email/routing/rules/r7") && r.contains(r#""enabled":false"#)));
    assert!(asked("delete /zones/z1/email/routing/rules/r7"));

    // Fastmail's deleted aliases aren't listed; disabled ones are, as off.
    let r = rules("fastmail");
    let fastmail = alias::Account::new(&r, &token, Some(&base)).unwrap().list().await.unwrap();
    assert_eq!(
        fastmail.iter().map(|a| (a.email.as_str(), a.enabled)).collect::<Vec<_>>(),
        [("x5@fastmail.example", true), ("off@fastmail.example", false)]
    );
    // Cloudflare: a new alias is a forwarding rule for a fresh address at the domain;
    // the catch-all rule isn't an alias.
    let r = rules("cloudflare");
    let made = alias::create(&r, &token, Some("https://github.com/login"), Some(&base)).await.unwrap();
    assert!(made.email.starts_with("githubcom.") && made.email.ends_with("@cf.example") && made.id == "r7", "{made:?}");
    let rule = seen.lock().unwrap().last().cloned().unwrap();
    assert!(rule.contains(r#""value":["me@example.com"]"#) && rule.contains(&made.email.to_lowercase()), "{rule}");

    let r = rules("duckduckgo");
    let ddg = alias::Account::new(&r, &token, Some(&base)).unwrap();
    assert!(!alias::Service::DuckDuckGo.capabilities().list);
    assert_eq!(ddg.list().await.err(), Some(UsernameError::Unsupported));
    assert_eq!(ddg.delete("x").await.err(), Some(UsernameError::Unsupported));
    // An id that would leave its place in the URL is refused before anything is sent.
    let r = rules("relay");
    let relay = alias::Account::new(&r, &token, Some(&base)).unwrap();
    assert!(relay.delete("../profiles/1").await.is_err());
    assert!(!seen.lock().unwrap().iter().any(|r| r.contains("profiles")));
    // A refused token says so.
    let bad = Secret::new("bad");
    let refused = alias::Account::new(&rules("addy"), &bad, Some(&base)).unwrap().list().await;
    assert_eq!(refused.err(), Some(UsernameError::Service("the service refused the token".into())));
}
