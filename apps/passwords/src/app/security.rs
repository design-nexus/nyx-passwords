//! The Security section: logins with a weak, reused or old password, from the daemon's
//! report; records with an `http://` address, a duplicate or something missing; and,
//! when asked, passwords found in known breaches (verified) and sites that offer
//! two-step login the login doesn't use. Each flagged item says what to do about it.

use std::collections::HashMap;

use gtk::{glib, prelude::*};
use nyx_ui::widgets as w;

use super::client;
use super::data::Entry;
use super::ui::{self, Ui};

#[derive(Debug, Clone, serde::Deserialize)]
struct Finding {
    id: String,
    reused: usize,
    weak: bool,
    age_days: Option<u64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Hygiene {
    id: String,
    insecure_address: bool,
    duplicates: Vec<String>,
    incomplete: Vec<String>,
}

#[derive(serde::Deserialize)]
struct Exposed {
    id: String,
    count: u64,
}

#[derive(serde::Deserialize)]
struct NoCode {
    id: String,
    docs: Option<String>,
}

/// One thing the report says about an item, and what fixes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// Verified: the password is in this many breaches.
    Exposed(u64),
    Reused(usize),
    Weak,
    Old(u64),
    /// The site offers one-time codes; its how-to page when known.
    NoTwoFactor(Option<String>),
    InsecureAddress,
    /// The other logins for the same site and username.
    Duplicate(Vec<String>),
    Missing(String),
}

impl Issue {
    /// Whether it's a fact (a breach) rather than advice.
    pub fn verified(&self) -> bool {
        matches!(self, Issue::Exposed(_))
    }

    pub fn text(&self) -> String {
        match self {
            Issue::Exposed(n) => format!("Exposed in {} breaches", thousands(*n)),
            Issue::Reused(1) => "Used by one other login".into(),
            Issue::Reused(n) => format!("Used by {n} other logins"),
            Issue::Weak => "Weak password".into(),
            Issue::Old(days) => match days / 365 {
                1 => "Password over a year old".into(),
                n => format!("Password over {n} years old"),
            },
            Issue::NoTwoFactor(_) => "The site offers one-time codes; none saved".into(),
            Issue::InsecureAddress => "Signs in over http://".into(),
            Issue::Duplicate(others) if others.len() == 1 => "Looks like the same account as one other login".into(),
            Issue::Duplicate(others) => format!("Looks like the same account as {} other logins", others.len()),
            Issue::Missing(what) => format!("No {what}"),
        }
    }
}

/// The latest report, and the checks' results once they've run. Dropped on lock.
#[derive(Default)]
pub struct Report {
    findings: HashMap<String, Finding>,
    hygiene: HashMap<String, Hygiene>,
    breaches: Option<HashMap<String, u64>>,
    two_factor: Option<HashMap<String, Option<String>>>,
}

impl Report {
    /// What the report says about an entry, verified first.
    pub fn issues(&self, e: &Entry) -> Vec<Issue> {
        let mut list = Vec::new();
        if e.deleted {
            return list;
        }
        if let Some(n) = self.breaches.as_ref().and_then(|b| b.get(&e.id)) {
            list.push(Issue::Exposed(*n));
        }
        if let Some(f) = self.findings.get(&e.id) {
            if f.reused > 0 {
                list.push(Issue::Reused(f.reused));
            }
            if f.weak {
                list.push(Issue::Weak);
            }
            if let Some(days) = f.age_days {
                list.push(Issue::Old(days));
            }
        }
        if let Some(docs) = self.two_factor.as_ref().and_then(|t| t.get(&e.id)) {
            list.push(Issue::NoTwoFactor(docs.clone()));
        }
        if let Some(h) = self.hygiene.get(&e.id) {
            if h.insecure_address {
                list.push(Issue::InsecureAddress);
            }
            if !h.duplicates.is_empty() {
                list.push(Issue::Duplicate(h.duplicates.clone()));
            }
            list.extend(h.incomplete.iter().map(|w| Issue::Missing(w.clone())));
        }
        list
    }

    pub fn flags(&self, e: &Entry) -> bool {
        !self.issues(e).is_empty()
    }

    /// The list's second line: the issues, most serious first.
    pub fn describe(&self, e: &Entry) -> String {
        self.issues(e).iter().map(Issue::text).collect::<Vec<_>>().join(" · ")
    }
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Asks the daemon for a fresh report, then updates the sidebar count and, in the
/// Security section, the list.
pub fn refresh(ui: &Ui) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let Ok(json) = client::text("Report", None).await else { return };
        let Ok(list) = serde_json::from_str::<Vec<Finding>>(&json) else { return };
        // A daemon from before these checks has no `Hygiene`: the rest still shows.
        let hygiene = client::text("Hygiene", None).await.ok();
        let hygiene: Vec<Hygiene> = hygiene.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();
        {
            let mut report = ui.security.borrow_mut();
            report.findings = list.into_iter().map(|f| (f.id.clone(), f)).collect();
            report.hygiene = hygiene.into_iter().map(|h| (h.id.clone(), h)).collect();
        }
        ui::nav(&ui);
        if *ui.section.borrow() == "security" {
            ui::refresh_list(&ui);
        }
    });
}

/// The Security section's header actions: the breach check and the two-step check.
pub fn toolbar(ui: &Ui) -> gtk::Box {
    let bar = w::hbox(0);
    let check =
        w::bar_button("security-high-symbolic", "Check for breaches: look up your passwords in Have I Been Pwned's breach data");
    let u = ui.clone();
    check.connect_clicked(move |b| ask_and_check(&u, b));
    bar.append(&check);
    let codes = w::bar_button("dialog-password-symbolic", "Check two-step login: which of your sites offer one-time codes");
    let u = ui.clone();
    codes.connect_clicked(move |b| ask_and_check_codes(&u, b));
    bar.append(&codes);
    bar
}

async fn ask(window: Option<&gtk::Window>, message: &str, detail: &str, action: &str) -> bool {
    let dialog = gtk::AlertDialog::builder()
        .modal(true)
        .message(message)
        .detail(detail)
        .buttons(["Cancel", action])
        .cancel_button(0)
        .default_button(1)
        .build();
    dialog.choose_future(window).await == Ok(1)
}

fn ask_and_check(ui: &Ui, button: &gtk::Button) {
    let window = button.root().and_downcast::<gtk::Window>();
    let (ui, button) = (ui.clone(), button.clone());
    glib::spawn_future_local(async move {
        let detail = "Have I Been Pwned (api.pwnedpasswords.com) gets the first five characters of each password's SHA-1 \
                      hash and answers with every breached hash that starts the same way; the match is made here. Your \
                      passwords and their full hashes never leave this device.";
        if !ask(window.as_ref(), "Check your passwords against known breaches?", detail, "Check").await {
            return;
        }
        button.set_sensitive(false);
        ui::toast(&ui, "Checking…");
        let reply = client::text("CheckBreaches", None).await;
        button.set_sensitive(true);
        match reply.map(|json| serde_json::from_str::<Vec<Exposed>>(&json).unwrap_or_default()) {
            // Locked while it ran: nothing of the vault goes back into the window.
            Ok(_) if *ui.state.borrow() != nyx_passwords_proto::state::UNLOCKED => {}
            Ok(found) => {
                let n = found.len();
                ui.security.borrow_mut().breaches = Some(found.into_iter().map(|e| (e.id, e.count)).collect());
                ui::nav(&ui);
                ui::refresh_list(&ui);
                ui::toast(
                    &ui,
                    &match n {
                        0 => "None of your passwords are in known breaches.".to_string(),
                        1 => "One password is in known breaches: change it.".to_string(),
                        n => format!("{n} passwords are in known breaches: change them."),
                    },
                );
            }
            Err(e) => ui::toast(&ui, &e.to_string()),
        }
    });
}

fn ask_and_check_codes(ui: &Ui, button: &gtk::Button) {
    let window = button.root().and_downcast::<gtk::Window>();
    let (ui, button) = (ui.clone(), button.clone());
    glib::spawn_future_local(async move {
        let detail = "Passwords downloads 2fa.directory's public list of sites that offer one-time codes (about 300 KB) \
                      and compares it with your logins here. Nothing about your vault is sent. The list is kept until \
                      the vault locks.";
        if !ask(window.as_ref(), "Check which of your sites offer two-step login?", detail, "Check").await {
            return;
        }
        button.set_sensitive(false);
        ui::toast(&ui, "Checking…");
        let reply = client::text("CheckTwoFactor", None).await;
        button.set_sensitive(true);
        match reply.map(|json| serde_json::from_str::<Vec<NoCode>>(&json).unwrap_or_default()) {
            Ok(_) if *ui.state.borrow() != nyx_passwords_proto::state::UNLOCKED => {}
            Ok(found) => {
                let n = found.len();
                ui.security.borrow_mut().two_factor = Some(found.into_iter().map(|f| (f.id, f.docs)).collect());
                ui::nav(&ui);
                ui::refresh_list(&ui);
                ui::toast(
                    &ui,
                    &match n {
                        0 => "Every login whose site offers one-time codes has one saved.".to_string(),
                        1 => "One site offers one-time codes you don't use yet.".to_string(),
                        n => format!("{n} sites offer one-time codes you don't use yet."),
                    },
                );
            }
            Err(e) => ui::toast(&ui, &e.to_string()),
        }
    });
}
