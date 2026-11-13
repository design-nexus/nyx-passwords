//! The Security page: logins with a weak, reused or old password, from the daemon's
//! report; records with an `http://` address, a duplicate or something missing; and,
//! when asked, passwords found in known breaches (verified) and sites that offer
//! two-step login the login doesn't use. Each problem has its fix beside it.

use std::collections::HashMap;
use std::time::Duration;

use gtk::{glib, prelude::*};
use nyx_ui::widgets as w;

use super::client;
use super::data::Entry;
use super::editor;
use super::home::monogram;
use super::ui::{self, Ui};

#[derive(Debug, Clone, serde::Deserialize)]
struct Finding {
    id: String,
    reused: usize,
    /// A daemon from before `same_as` sends only the count.
    #[serde(default)]
    same_as: Vec<String>,
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

    /// Whether it makes the login less safe, rather than untidy (a duplicate, a record
    /// missing something): these count towards the vault's health.
    pub fn risky(&self) -> bool {
        !matches!(self, Issue::Duplicate(_) | Issue::Missing(_))
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

/// What Home shows: how many logins could be safer, and of which kind.
pub struct Summary {
    /// Live logins with a password.
    pub logins: usize,
    /// Items with at least one problem that makes them less safe.
    pub risky_items: usize,
    pub weak: usize,
    pub reused: usize,
    pub old: usize,
    /// `None` until two-step login has been checked.
    pub no_code: Option<usize>,
}

impl Summary {
    /// 0 to 100: the share of logins with nothing to fix.
    pub fn score(&self) -> u32 {
        if self.logins == 0 {
            return 100;
        }
        let safe = self.logins.saturating_sub(self.risky_items);
        ((safe * 100 + self.logins / 2) / self.logins) as u32
    }
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

    /// Whether the entry has something that makes it less safe (the sidebar's badge).
    pub fn flags(&self, e: &Entry) -> bool {
        self.issues(e).iter().any(Issue::risky)
    }

    /// The other logins with the same password.
    fn same_as(&self, id: &str) -> &[String] {
        self.findings.get(id).map_or(&[], |f| f.same_as.as_slice())
    }

    pub fn summary(&self, entries: &[Entry]) -> Summary {
        let live: Vec<&Entry> = entries.iter().filter(|e| !e.deleted).collect();
        let count = |f: &dyn Fn(&Issue) -> bool| live.iter().filter(|e| self.issues(e).iter().any(f)).count();
        Summary {
            logins: live.iter().filter(|e| e.kind == "login" && e.readable && e.has_password).count(),
            risky_items: live.iter().filter(|e| self.flags(e)).count(),
            weak: count(&|i| matches!(i, Issue::Weak)),
            reused: count(&|i| matches!(i, Issue::Reused(_))),
            old: count(&|i| matches!(i, Issue::Old(_))),
            no_code: self.two_factor.as_ref().map(|_| count(&|i| matches!(i, Issue::NoTwoFactor(_)))),
        }
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

/// Asks the daemon for a fresh report, then updates the sidebar count and the page
/// showing.
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
        ui::refresh_views(&ui);
    });
}

/// A kind of problem: id, heading, colour, and whether an issue is of that kind.
type Group = (&'static str, &'static str, &'static str, fn(&Issue) -> bool);

/// The kinds of problem, in the page's order.
const GROUPS: &[Group] = &[
    ("exposed", "Found in breaches", "red", |i| matches!(i, Issue::Exposed(_))),
    ("weak", "Weak passwords", "red", |i| matches!(i, Issue::Weak)),
    ("reused", "Used more than once", "amber", |i| matches!(i, Issue::Reused(_))),
    ("old", "Over a year old", "teal", |i| matches!(i, Issue::Old(_))),
    ("no-code", "Two-step login is off", "violet", |i| matches!(i, Issue::NoTwoFactor(_))),
    ("insecure", "Not secure", "teal", |i| matches!(i, Issue::InsecureAddress)),
    ("duplicate", "Looks like the same account", "graphite", |i| matches!(i, Issue::Duplicate(_))),
    ("missing", "Missing something", "graphite", |i| matches!(i, Issue::Missing(_))),
];

/// Every problem with the entry it's about, grouped as the page shows them.
fn grouped(ui: &Ui) -> Vec<(usize, Vec<(Entry, Issue)>)> {
    let listing = ui.listing.borrow();
    let report = ui.security.borrow();
    let mut entries: Vec<&Entry> = listing.entries.iter().filter(|e| !e.deleted).collect();
    entries.sort_by_key(|e| e.name.to_lowercase());
    let mut groups: Vec<(usize, Vec<(Entry, Issue)>)> = (0..GROUPS.len()).map(|i| (i, Vec::new())).collect();
    for e in entries {
        for issue in report.issues(e) {
            if let Some(g) = GROUPS.iter().position(|(_, _, _, is)| is(&issue)) {
                groups[g].1.push((e.clone(), issue));
            }
        }
    }
    groups.retain(|(_, rows)| !rows.is_empty());
    groups
}

/// What the row says about the problem, in a few words.
fn why(ui: &Ui, e: &Entry, issue: &Issue) -> String {
    let names = |ids: &[String]| {
        let listing = ui.listing.borrow();
        let mut names: Vec<String> =
            ids.iter().filter_map(|id| listing.entries.iter().find(|o| o.id == *id)).map(|o| o.name.clone()).collect();
        names.sort_by_key(|n| n.to_lowercase());
        match names.len() {
            0 => None,
            1 => Some(names.remove(0)),
            2 => Some(format!("{} and {}", names[0], names[1])),
            n => Some(format!("{}, {} and {} others", names[0], names[1], n - 2)),
        }
    };
    match issue {
        Issue::Exposed(n) => format!("Seen {} times in known breaches", thousands(*n)),
        Issue::Weak => "Easy to guess".into(),
        Issue::Reused(n) => match names(ui.security.borrow().same_as(&e.id)) {
            Some(others) => format!("Same as {others}"),
            None if *n == 1 => "Same as one other login".into(),
            None => format!("Same as {n} other logins"),
        },
        Issue::Old(days) => match days / 365 {
            1 => "Unchanged for over a year".into(),
            n => format!("Unchanged for over {n} years"),
        },
        Issue::NoTwoFactor(_) => format!("{} offers one-time codes", e.host.as_deref().unwrap_or(&e.name)),
        Issue::InsecureAddress => "Its address starts with http://".into(),
        Issue::Duplicate(others) => match names(others) {
            Some(others) => format!("Same site and username as {others}"),
            None => issue.text(),
        },
        Issue::Missing(what) => format!("No {what}"),
    }
}

type Fix = (&'static str, &'static str, Box<dyn Fn()>);

/// What fixes the problem, most direct first: a label, a tooltip and the action.
fn fixes(ui: &Ui, e: &Entry, issue: &Issue) -> Vec<Fix> {
    let can_edit = e.editable && editor::KINDS.contains(&e.kind.as_str());
    let (u, entry) = (ui.clone(), e.clone());
    let mut list: Vec<Fix> = Vec::new();
    match issue {
        Issue::Exposed(_) | Issue::Reused(_) | Issue::Weak | Issue::Old(_) if can_edit && e.view_password => {
            list.push((
                "Change…",
                "Generate a new password in the editor; change it on the site too",
                Box::new(move || editor::open_fix(&u, entry.clone(), editor::Fix::NewPassword)),
            ));
        }
        Issue::NoTwoFactor(docs) => {
            if can_edit {
                let (u, entry) = (u.clone(), entry.clone());
                list.push((
                    "Add code…",
                    "Save the site's one-time code key here once you've turned it on",
                    Box::new(move || editor::open_fix(&u, entry.clone(), editor::Fix::TotpKey)),
                ));
            }
            if let Some(docs) = docs.clone() {
                list.push((
                    "How to",
                    "The site's page about turning on two-step login",
                    Box::new(move || {
                        let _ = gtk::gio::AppInfo::launch_default_for_uri(&docs, None::<&gtk::gio::AppLaunchContext>);
                    }),
                ));
            }
        }
        Issue::InsecureAddress if can_edit => {
            list.push((
                "Use https…",
                "Change its http:// addresses to https:// in the editor",
                Box::new(move || editor::open_fix(&u, entry.clone(), editor::Fix::Https)),
            ));
        }
        Issue::Duplicate(others) => {
            let others = others.clone();
            list.push((
                "Show",
                "Pick this login and the others, to compare or move them",
                Box::new(move || {
                    let mut ids = vec![entry.id.clone()];
                    ids.extend(others.iter().cloned());
                    ui::show_several(&u, ids);
                }),
            ));
        }
        Issue::Missing(_) if can_edit => {
            list.push(("Edit…", "Fill it in", Box::new(move || editor::open(&u, Some(entry.clone())))));
        }
        _ => {}
    }
    list
}

/// The problem's fixes as buttons.
pub fn fix_buttons(ui: &Ui, e: &Entry, issue: &Issue) -> gtk::Box {
    let actions = w::hbox(6);
    actions.set_valign(gtk::Align::Center);
    for (label, tip, run) in fixes(ui, e, issue) {
        let b = gtk::Button::with_label(label);
        b.set_tooltip_text(Some(tip));
        b.set_valign(gtk::Align::Center);
        b.connect_clicked(move |_| run());
        actions.append(&b);
    }
    actions
}

/// Home's "Fix the first one": the page's first problem that has a fix. Without one,
/// the Security page.
pub fn fix_first(ui: &Ui) {
    for (_, rows) in grouped(ui) {
        for (e, issue) in rows.iter().filter(|(_, i)| i.risky()) {
            if let Some((_, _, run)) = fixes(ui, e, issue).into_iter().next() {
                run();
                return;
            }
        }
    }
    ui::navigate(ui, "security");
}

/// The page's fixed part: its title, what the checks send, and the two checks.
pub fn bar() -> gtk::Box {
    let page = w::vbox(0);
    let bar = w::hbox(10);
    bar.add_css_class("security-bar");
    let text = w::vbox(2);
    text.set_hexpand(true);
    text.append(&w::label("Security", "page-title"));
    let about = ui::label(
        "Worked out on this computer. Breach checks send only the first five characters of each password's fingerprint.",
        "dim",
    );
    about.set_max_width_chars(60);
    about.add_css_class("page-about");
    text.append(&about);
    bar.append(&text);
    let breaches = w::labeled_button("security-high-symbolic", "Check for breaches…");
    breaches.set_tooltip_text(Some("Look up your passwords in Have I Been Pwned's breach data"));
    breaches.set_valign(gtk::Align::Center);
    breaches.connect_clicked(|b| {
        if let Some(ui) = ui::current() {
            ask_and_check(&ui, b);
        }
    });
    bar.append(&breaches);
    let codes = w::labeled_button("system-lock-screen-symbolic", "Check two-step login…");
    codes.set_tooltip_text(Some("Which of your sites offer one-time codes"));
    codes.set_valign(gtk::Align::Center);
    codes.connect_clicked(|b| {
        if let Some(ui) = ui::current() {
            ask_and_check_codes(&ui, b);
        }
    });
    bar.append(&codes);
    page.append(&bar);
    page.append(&nyx_ui::frame::pane_line(gtk::Orientation::Horizontal));
    page
}

/// Fills the page's list from the report.
pub fn page(ui: &Ui) {
    ui::clear(&ui.security_list);
    let groups = grouped(ui);
    if groups.is_empty() {
        ui.security_list.append(&w::empty_state(
            "security-high-symbolic",
            "Nothing to fix",
            "No weak, reused or old passwords, and no records missing anything. Check for breaches or two-step login to look further.",
            None,
        ));
        return;
    }
    for (g, rows) in groups {
        let (id, title, colour, _) = GROUPS[g];
        let head = w::hbox(8);
        head.add_css_class("fix-group-title");
        head.set_widget_name(id);
        let section = format!("swatch-{colour}");
        nyx_ui::sidebar::set_section(&head, &section);
        let name = w::label(title, "");
        nyx_ui::sidebar::set_section(&name, &section);
        head.append(&name);
        let count = w::label(&rows.len().to_string(), "count-pill");
        nyx_ui::sidebar::set_section(&count, &section);
        head.append(&count);
        ui.security_list.append(&head);
        let card = w::vbox(0);
        card.add_css_class("group-list");
        card.add_css_class("fix-list");
        for (e, issue) in &rows {
            card.append(&fix_row(ui, e, issue));
        }
        ui.security_list.append(&card);
    }
}

fn fix_row(ui: &Ui, e: &Entry, issue: &Issue) -> gtk::Box {
    let row = w::hbox(8);
    row.add_css_class("fix-row");
    let open = gtk::Button::new();
    open.add_css_class("flat");
    open.add_css_class("fix-open");
    open.set_hexpand(true);
    open.set_tooltip_text(Some("Show this item"));
    let face = w::hbox(12);
    face.set_halign(gtk::Align::Fill);
    face.append(&monogram(&e.name, 30));
    let text = w::vbox(2);
    text.set_valign(gtk::Align::Center);
    text.set_hexpand(true);
    let line = w::hbox(6);
    let name = w::label(&e.name, "fix-name");
    name.set_ellipsize(gtk::pango::EllipsizeMode::End);
    line.append(&name);
    if let Some(user) = e.username.as_deref().filter(|u| !u.is_empty()) {
        let user = w::label(user, "fix-user");
        user.set_ellipsize(gtk::pango::EllipsizeMode::End);
        line.append(&user);
    }
    text.append(&line);
    let why = w::label(&why(ui, e, issue), "fix-why");
    why.set_ellipsize(gtk::pango::EllipsizeMode::End);
    text.append(&why);
    face.append(&text);
    open.set_child(Some(&face));
    let (u, id) = (ui.clone(), e.id.clone());
    open.connect_clicked(move |_| ui::show_item(&u, &id));
    row.append(&open);
    let fixes = fix_buttons(ui, e, issue);
    fixes.add_css_class("fix-actions");
    row.append(&fixes);
    row
}

/// Brings the group `id` to the top of the page, once it's laid out.
pub fn scroll_to(ui: &Ui, id: &str) {
    let (ui, id) = (ui.clone(), id.to_string());
    glib::timeout_add_local_once(Duration::from_millis(80), move || {
        let mut child = ui.security_list.first_child();
        while let Some(c) = child {
            if c.widget_name() == id {
                if let Some(p) = c.compute_point(&ui.security_list, &gtk::graphene::Point::new(0.0, 0.0)) {
                    ui.security_scroll.vadjustment().set_value(f64::from(p.y()));
                }
                return;
            }
            child = c.next_sibling();
        }
    });
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

pub fn ask_and_check(ui: &Ui, button: &gtk::Button) {
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
                ui::refresh_views(&ui);
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

pub fn ask_and_check_codes(ui: &Ui, button: &gtk::Button) {
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
                ui::refresh_views(&ui);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores() {
        let s = |logins, risky_items| Summary { logins, risky_items, weak: 0, reused: 0, old: 0, no_code: None }.score();
        assert_eq!(s(0, 0), 100);
        assert_eq!(s(248, 0), 100);
        assert_eq!(s(248, 9), 96);
        assert_eq!(s(4, 4), 0);
        assert_eq!(s(3, 1), 67);
    }

    #[test]
    fn untidy_isnt_risky() {
        assert!(Issue::Weak.risky() && Issue::Exposed(3).risky() && Issue::NoTwoFactor(None).risky());
        assert!(!Issue::Missing("address".into()).risky() && !Issue::Duplicate(vec![]).risky());
    }
}
