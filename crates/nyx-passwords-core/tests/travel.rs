//! Travel Mode against the throwaway Vaultwarden, with `bw` as another device:
//!
//!   NYX_PW_TEST_SERVER=https://127.0.0.1:8087 NYX_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem \
//!     cargo test -p nyx-passwords-core --test travel -- --ignored

mod common;

use std::num::NonZeroU32;

use nyx_passwords_core::api::Server;
use nyx_passwords_core::edit::{CustomDraft, LoginDraft, Place};
use nyx_passwords_core::secret::Secret;
use nyx_passwords_core::session::{self, SignIn};
use nyx_passwords_core::store::Store;

fn login(name: &str, travel: bool) -> LoginDraft {
    LoginDraft {
        name: Secret::new(name),
        username: Some(Secret::new("me")),
        password: Some(Secret::new(format!("canary-{name}-Pw!9"))),
        totp: None,
        uris: vec![Secret::new("https://travel.example.com").into()],
        notes: None,
        folder: None,
        favorite: false,
        reprompt: false,
        place: Place::default(),
        custom: travel.then(|| {
            vec![CustomDraft {
                name: Secret::new(nyx_passwords_proto::custom::TRAVEL),
                value: Some(Secret::new("true")),
                kind: 2,
                from: None,
            }]
        }),
    }
}

#[tokio::test]
#[ignore = "needs NYX_PW_TEST_SERVER"]
async fn travel_mode_keeps_marked_items_off_this_device() {
    let email = common::fresh_email("travel");
    let password = "correct horse travel battery";
    common::register(&email, password, &bitwarden_crypto::Kdf::PBKDF2 { iterations: NonZeroU32::new(600_000).unwrap() }).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.sqlite");
    let mut store = Store::open(&path).unwrap();
    let server = Server::new(&common::server_url(), &[common::ca_pem()]).unwrap();
    let SignIn::Done(mut s) =
        session::sign_in(&mut store, &server, &email, &Secret::new(password), "nyx test", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    let refresh = Secret::new(s.refresh_token().unwrap().expose());
    let secret = s.create_login(&mut store, &server, &refresh, &login("Embassy", true)).await.unwrap();
    let plain = s.create_login(&mut store, &server, &refresh, &login("Weather", false)).await.unwrap();
    assert_eq!(s.travel_marked(), 1);

    // On: the marked item leaves memory and the file at once.
    assert_eq!(s.enter_travel(&mut store).unwrap(), 1);
    assert!(s.view.get(secret).is_none() && s.view.get(plain).is_some());
    let on_disk = |path: &std::path::Path| {
        let mut all = std::fs::read(path).unwrap();
        for extra in ["-wal", "-shm"] {
            all.extend(std::fs::read(format!("{}{extra}", path.display())).unwrap_or_default());
        }
        all
    };
    let id = secret.to_string();
    assert!(!on_disk(&path).windows(id.len()).any(|w| w == id.as_bytes()), "no trace of the item's id in the file");

    // Syncs, offline unlocks and edits made elsewhere don't bring it back.
    s.sync(&mut store, &server, &refresh).await.unwrap();
    assert!(s.view.get(secret).is_none());
    let bw = common::Bw::login(&email, password);
    let mut theirs = bw.item(&id);
    theirs["name"] = "Embassy (edited)".into();
    bw.edit(&id, &theirs);
    s.sync(&mut store, &server, &refresh).await.unwrap();
    assert!(s.view.get(secret).is_none());
    s.lock();
    let mut s = session::unlock(&mut store, &Secret::new(password)).await.unwrap();
    assert!(s.view.get(secret).is_none() && s.view.get(plain).is_some());
    assert!(store.travel().unwrap(), "the mode outlasts a lock");

    // A new marked item is saved to the server but not kept here.
    let refresh = Secret::new(store_refresh(&mut s, &server, &email, password, &mut store).await.expose());
    let packed = s.create_login(&mut store, &server, &refresh, &login("Visa papers", true)).await.unwrap();
    assert!(s.view.get(packed).is_none());
    assert_eq!(bw.item(&packed.to_string())["name"], "Visa papers", "the server keeps it");
    assert!(!bw.item(&id).is_null(), "nothing was deleted on the server");

    // Off, with a sync: everything is back.
    store.set_travel(false).unwrap();
    s.sync(&mut store, &server, &refresh).await.unwrap();
    assert_eq!(s.view.get(secret).unwrap().name.expose(), "Embassy (edited)");
    assert!(s.view.get(packed).is_some());
}

/// A refresh token after an offline unlock: sign in again (the test has no keyring).
async fn store_refresh(s: &mut session::Session, server: &Server, email: &str, password: &str, store: &mut Store) -> Secret {
    let SignIn::Done(fresh) = session::sign_in(store, server, email, &Secret::new(password), "nyx test", None).await.unwrap()
    else {
        panic!("two-step login")
    };
    *s = *fresh;
    Secret::new(s.refresh_token().unwrap().expose())
}
