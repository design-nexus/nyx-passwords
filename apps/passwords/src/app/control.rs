//! Passwords on the Nyx control interface (`nyx_core::control`, API 2), for
//! `nyx passwords …`, Glimpse's commands and Nyx Assistant: whether the vault is locked,
//! locking it now, and opening Passwords. Never an item, a field or a secret: those
//! stay behind the daemon's own socket and scopes.

use super::client;
use gtk::glib;
use nyx_actions::{Error, ErrorKind};
use nyx_core::control::Answer;
use serde_json::{Value, json};

pub fn description(app_id: &str) -> Value {
    let none = json!({"type": "object", "properties": {}, "additionalProperties": false});
    json!({
        "tools": [
            {"name": "passwords.status", "description": "Whether the vault is locked, unlocked or signed out. Nothing from the vault itself.",
             "inputSchema": none, "annotations": {"title": "Vault status", "readOnlyHint": true},
             "x-nyx": {"risk": "read_only", "result": "object"}},
            {"name": "passwords.lock", "description": "Lock the vault now.",
             "inputSchema": none, "annotations": {"title": "Lock the vault"},
             "x-nyx": {"risk": "writes", "confirmation": "never", "result": "message"}},
            {"name": "passwords.open", "description": "Open Passwords (on its unlock page while locked).",
             "inputSchema": none, "annotations": {"title": "Open Passwords"},
             "x-nyx": {"risk": "writes", "confirmation": "never", "aliases": ["unlock"], "result": "none"}}
        ],
        "nyx": {"api": 2, "app": app_id, "name": "Passwords", "icon": "io.github.design_nexus.nyx.Passwords", "namespaces": ["passwords"],
                "aliases": ["vault"], "bus_name": app_id, "activation": "dbus", "open": {"action": "passwords.open"}}
    })
}

/// Register the interface (from `connect_startup`).
pub fn serve(app: &gtk::Application) {
    use gtk::prelude::*;
    let id = app.application_id().map(|s| s.to_string()).unwrap_or_else(|| "io.github.design_nexus.nyx.Passwords".into());
    let window_app = app.clone();
    nyx_core::control::serve_with(app, description(&id), move |request, answer| handle(&window_app, &request.action, answer));
}

fn failed(e: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Failed, format!("Passwords' service didn't answer: {e}"))
}

fn handle(app: &gtk::Application, action: &str, answer: Answer) {
    match action {
        "passwords.status" => {
            glib::spawn_future_local(async move {
                answer(client::status().await.map(|(state, _, _)| json!({ "state": state, "locked": state != "unlocked" })).map_err(failed));
            });
        }
        "passwords.lock" => {
            glib::spawn_future_local(async move {
                answer(client::call("Lock", None).await.map(|_| json!({"message": "The vault is locked"})).map_err(failed));
            });
        }
        "passwords.open" => {
            let _ = super::ui::present(app, None);
            answer(Ok(Value::Null));
        }
        other => answer(Err(Error::new(ErrorKind::UnknownAction, format!("Passwords has no action {other}")))),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_description_is_api_2_and_reads_nothing_secret() {
        let d = nyx_actions::Description::from_value(&super::description("io.github.design_nexus.nyx.Passwords"), None).unwrap();
        let ids: Vec<&str> = d.actions.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, ["passwords.status", "passwords.lock", "passwords.open"]);
        assert!(d.actions.iter().all(|a| !a.asks()));
    }
}
