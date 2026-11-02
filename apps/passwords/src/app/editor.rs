//! Creating and editing logins, notes, cards, identities and SSH keys. An existing
//! item's secret fields are fetched one by one when the editor opens; the draft goes to
//! the daemon as JSON when saved.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gtk::{gdk, gio, glib, prelude::*};
use nyx_passwords_proto::Error as Code;
use nyx_passwords_proto::custom;
use nyx_passwords_proto::fields::{self, Spec};
use nyx_ui::widgets as w;
use serde_json::json;

use super::client;
use super::data::{self, Entry};
use super::detail::{self, FieldRow};
use super::prefs;
use super::templates::{self, Slot, Template};
use super::ui::{self, Ui, label};

/// The kinds the editor makes.
pub const KINDS: &[&str] = &["login", "note", "card", "identity", "ssh"];

/// "card", "secure note", "SSH key": the kind's name inside a sentence.
fn noun(kind: &str) -> String {
    let name = data::kind_name(kind);
    if kind == "ssh" { name.to_string() } else { name.to_lowercase() }
}

/// Larger files can't be private keys.
const KEY_FILE_LIMIT: usize = 64 * 1024;

/// Fields with fixed choices, as the official clients offer them: `(value, label)`.
fn choices(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    match name {
        "card.brand" => Some(&[
            ("Visa", "Visa"),
            ("Mastercard", "Mastercard"),
            ("Amex", "American Express"),
            ("Discover", "Discover"),
            ("Diners Club", "Diners Club"),
            ("JCB", "JCB"),
            ("Maestro", "Maestro"),
            ("UnionPay", "UnionPay"),
            ("RuPay", "RuPay"),
            ("Other", "Other"),
        ]),
        "card.expMonth" => Some(&[
            ("1", "01 · January"),
            ("2", "02 · February"),
            ("3", "03 · March"),
            ("4", "04 · April"),
            ("5", "05 · May"),
            ("6", "06 · June"),
            ("7", "07 · July"),
            ("8", "08 · August"),
            ("9", "09 · September"),
            ("10", "10 · October"),
            ("11", "11 · November"),
            ("12", "12 · December"),
        ]),
        "identity.title" => Some(&[("Mr", "Mr"), ("Mrs", "Mrs"), ("Ms", "Ms"), ("Mx", "Mx"), ("Dr", "Dr")]),
        _ => None,
    }
}

/// One field of a note, card or identity.
enum Control {
    Text(gtk::Entry),
    Secret(gtk::PasswordEntry),
    /// The values behind the drop-down's rows; the first row is "none".
    Choice(gtk::DropDown, RefCell<Vec<String>>),
    /// An SSH private key: held, never shown.
    Key(Rc<KeyPicker>),
}

/// An SSH key in the editor: the private key stays out of sight; its type, fingerprint
/// and public key are shown, with buttons to generate a new key or import one.
struct KeyPicker {
    private: RefCell<String>,
    summary: gtk::Label,
    public: gtk::Label,
    buttons: gtk::Box,
    body: gtk::Box,
}

impl KeyPicker {
    fn new(ui: &Ui) -> Rc<KeyPicker> {
        let body = w::vbox(6);
        let summary = label("No key yet: generate one, or import a private key file.", "dim");
        let public = label("", "dim");
        public.set_selectable(true);
        // Keys and fingerprints wrap anywhere, without the hyphens Pango would add.
        let unhyphenated = gtk::pango::AttrList::new();
        unhyphenated.insert(gtk::pango::AttrInt::new_insert_hyphens(false));
        for l in [&summary, &public] {
            l.set_wrap_mode(gtk::pango::WrapMode::WordChar);
            l.set_attributes(Some(&unhyphenated));
        }
        public.set_visible(false);
        body.append(&summary);
        body.append(&public);
        let buttons = w::hbox(6);
        let generate = gtk::Button::from_icon_name("view-refresh-symbolic");
        generate.set_tooltip_text(Some("Generate a new Ed25519 key"));
        let import = gtk::Button::from_icon_name("document-open-symbolic");
        import.set_tooltip_text(Some("Import a private key file…"));
        buttons.append(&generate);
        buttons.append(&import);
        body.append(&buttons);
        let picker = Rc::new(KeyPicker { private: RefCell::new(String::new()), summary, public, buttons, body });
        let (u, p) = (ui.clone(), picker.clone());
        generate.connect_clicked(move |_| {
            let (u, p) = (u.clone(), p.clone());
            glib::spawn_future_local(async move {
                match client::text("GenerateSshKey", None).await {
                    Ok(json) => {
                        let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
                        *p.private.borrow_mut() = v["private"].as_str().unwrap_or_default().to_string();
                        p.show(v["public"].as_str().unwrap_or_default(), v["fingerprint"].as_str().unwrap_or_default());
                    }
                    Err(e) => ui::toast(&u, &e.to_string()),
                }
            });
        });
        let (u, p) = (ui.clone(), picker.clone());
        import.connect_clicked(move |b| p.import(&u, b));
        picker
    }

    fn show(&self, public: &str, fingerprint: &str) {
        let kind = match public.split(' ').next().unwrap_or_default() {
            "ssh-ed25519" => "Ed25519",
            "ssh-rsa" => "RSA",
            "ecdsa-sha2-nistp256" => "ECDSA P-256",
            "ecdsa-sha2-nistp384" => "ECDSA P-384",
            "ecdsa-sha2-nistp521" => "ECDSA P-521",
            other => other,
        };
        self.summary.set_text(&format!("{kind} key · {fingerprint}"));
        self.public.set_text(public);
        self.public.set_visible(true);
    }

    /// Takes a private key: asks the daemon for its public key and fingerprint, and keeps
    /// it only if the daemon can read it.
    fn take(self: &Rc<Self>, ui: Option<&Ui>, private: String) {
        let (ui, p) = (ui.cloned(), self.clone());
        glib::spawn_future_local(async move {
            match client::text("ReadSshKey", Some((private.as_str(),).to_variant())).await {
                Ok(json) => {
                    let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
                    *p.private.borrow_mut() = private;
                    p.show(v["public"].as_str().unwrap_or_default(), v["fingerprint"].as_str().unwrap_or_default());
                }
                // The daemon's words for a key with a passphrase (`ssh::SshError::Encrypted`).
                Err(e) if ui.is_some() && e.message.contains("has a passphrase") => {
                    p.ask_passphrase(ui.as_ref().expect("checked"), private);
                }
                Err(e) => match ui {
                    Some(ui) => ui::toast(&ui, &e.to_string()),
                    None => p.summary.set_text(&format!("The saved key can't be read: {e}")),
                },
            }
        });
    }

    /// Opens an imported key that has a passphrase. The item keeps the key without it,
    /// as the official clients do; the vault's encryption protects it instead.
    fn ask_passphrase(self: &Rc<Self>, ui: &Ui, private: String) {
        let (dialog, card) = w::dialog("This key has a passphrase", 420);
        card.append(&label("Enter it to import the key. It's saved without the passphrase, encrypted in your vault.", "dim"));
        let entry = gtk::PasswordEntry::new();
        entry.set_show_peek_icon(true);
        card.append(&entry);
        let buttons = w::hbox(8);
        buttons.set_halign(gtk::Align::End);
        let cancel = gtk::Button::with_label("Cancel");
        let open = gtk::Button::with_label("Import");
        open.add_css_class("suggested-action");
        buttons.append(&cancel);
        buttons.append(&open);
        card.append(&buttons);
        let d = dialog.clone();
        cancel.connect_clicked(move |_| d.close());
        let submit = {
            let (ui, p, d, e, private) = (ui.clone(), self.clone(), dialog.clone(), entry.clone(), Rc::new(private));
            Rc::new(move || {
                let (ui, p, d, e, private) = (ui.clone(), p.clone(), d.clone(), e.clone(), private.clone());
                glib::spawn_future_local(async move {
                    let args = (private.as_str(), e.text().as_str()).to_variant();
                    match client::text("OpenSshKey", Some(args)).await {
                        Ok(json) => {
                            let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
                            *p.private.borrow_mut() = v["private"].as_str().unwrap_or_default().to_string();
                            p.show(v["public"].as_str().unwrap_or_default(), v["fingerprint"].as_str().unwrap_or_default());
                            d.close();
                        }
                        Err(err) => {
                            e.add_css_class("error");
                            ui::toast(&ui, &err.to_string());
                        }
                    }
                });
            })
        };
        let s = submit.clone();
        open.connect_clicked(move |_| s());
        entry.connect_activate(move |_| submit());
        dialog.present();
        entry.grab_focus();
    }

    fn import(self: &Rc<Self>, ui: &Ui, button: &gtk::Button) {
        let parent = button.root().and_downcast::<gtk::Window>();
        let (ui, p) = (ui.clone(), self.clone());
        gtk::FileDialog::builder().title("Import a private key").modal(true).build().open(
            parent.as_ref(),
            gio::Cancellable::NONE,
            move |picked| {
                let Ok(file) = picked else { return };
                glib::spawn_future_local(async move {
                    match file.load_contents_future().await {
                        Ok((bytes, _)) if bytes.len() <= KEY_FILE_LIMIT => match String::from_utf8(bytes.to_vec()) {
                            Ok(text) => p.take(Some(&ui), text),
                            Err(_) => ui::toast(&ui, "That file isn't a private key."),
                        },
                        Ok(_) => ui::toast(&ui, "That file is too large to be a private key."),
                        Err(e) => ui::toast(&ui, &e.to_string()),
                    }
                });
            },
        );
    }
}

impl Control {
    fn new(spec: &Spec) -> Control {
        if let Some(options) = choices(spec.name) {
            let mut rows = vec![(String::new(), "—".to_string())];
            rows.extend(options.iter().map(|(v, l)| (v.to_string(), l.to_string())));
            let values = rows.iter().map(|(v, _)| v.clone()).collect();
            return Control::Choice(w::dropdown(&rows, ""), RefCell::new(values));
        }
        if spec.secret {
            let p = gtk::PasswordEntry::new();
            p.set_show_peek_icon(true);
            return Control::Secret(p);
        }
        Control::Text(gtk::Entry::new())
    }

    fn widget(&self) -> gtk::Widget {
        match self {
            Control::Text(e) => e.clone().upcast(),
            Control::Secret(p) => p.clone().upcast(),
            Control::Choice(d, _) => d.clone().upcast(),
            Control::Key(k) => k.body.clone().upcast(),
        }
    }

    fn text(&self) -> String {
        match self {
            Control::Text(e) => e.text().trim().to_string(),
            Control::Secret(p) => p.text().trim().to_string(),
            Control::Choice(d, values) => values.borrow().get(d.selected() as usize).cloned().unwrap_or_default(),
            Control::Key(k) => k.private.borrow().clone(),
        }
    }

    /// A value another client saved that isn't one of the choices is added as its own row.
    fn set(&self, value: &str) {
        match self {
            Control::Text(e) => e.set_text(value),
            Control::Secret(p) => p.set_text(value),
            Control::Choice(d, values) => {
                let at = values.borrow().iter().position(|v| v == value);
                let at = at.unwrap_or_else(|| {
                    if let Some(list) = d.model().and_downcast::<gtk::StringList>() {
                        list.append(value);
                    }
                    values.borrow_mut().push(value.to_string());
                    values.borrow().len() - 1
                });
                d.set_selected(at as u32);
            }
            Control::Key(k) => k.take(None, value.to_string()),
        }
    }
}

/// A custom field's value: text, hidden text, or true or false.
enum CustomValue {
    Text(gtk::Entry),
    Hidden(gtk::PasswordEntry),
    Flag(gtk::Switch),
}

/// The custom field types the editor makes: `(type, name)`.
const CUSTOM_KINDS: &[(i64, &str)] = &[(0, "Text"), (1, "Hidden"), (2, "True or false")];

/// One custom field in the editor. `source` is its position in the item it came from
/// (for revealing it, and, unless the item is being copied, for keeping what isn't
/// edited). A `locked` field is hidden from this account: its value stays as stored.
struct CustomRow {
    source: Option<usize>,
    keep_source: bool,
    kind: i64,
    name: gtk::Entry,
    value: CustomValue,
    locked: bool,
    root: gtk::Box,
    remove: gtk::Button,
    /// Laid out by the item's template: its name is the template's label.
    fixed: Cell<bool>,
}

impl CustomRow {
    /// The field for the draft; `None` for a template's field left empty, which the
    /// template brings back the next time the item is edited.
    fn json(&self) -> Option<serde_json::Value> {
        let value = match &self.value {
            _ if self.locked => None,
            CustomValue::Text(e) => Some(e.text().to_string()),
            CustomValue::Hidden(p) => Some(p.text().to_string()),
            CustomValue::Flag(s) => Some(s.is_active().to_string()),
        };
        if self.fixed.get() && self.kind != 2 && value.as_deref().is_some_and(|v| v.trim().is_empty()) {
            return None;
        }
        Some(json!({
            "name": self.name.text().trim(),
            "value": value,
            "kind": self.kind,
            "from": if self.keep_source { self.source } else { None },
        }))
    }

    fn is_empty(&self) -> bool {
        match &self.value {
            CustomValue::Text(e) => e.text().trim().is_empty(),
            CustomValue::Hidden(p) => p.text().trim().is_empty(),
            CustomValue::Flag(s) => !s.is_active(),
        }
    }

    /// Makes it one of the template's fields: the name can't be changed or the row removed.
    fn fix(&self, hint: &str) {
        self.fixed.set(true);
        self.name.set_editable(false);
        self.name.set_can_focus(false);
        self.name.add_css_class("template-label");
        self.remove.set_visible(false);
        if !hint.is_empty() {
            match &self.value {
                CustomValue::Text(e) => e.set_placeholder_text(Some(hint)),
                CustomValue::Hidden(p) => p.set_placeholder_text(Some(hint)),
                CustomValue::Flag(_) => {}
            }
        }
    }

    fn set(&self, value: &str) {
        match &self.value {
            CustomValue::Text(e) => e.set_text(value),
            CustomValue::Hidden(p) => p.set_text(value),
            CustomValue::Flag(s) => s.set_active(value == "true"),
        }
    }
}

/// Bitwarden's match rules for a web address, as the drop-down offers them: `(value,
/// label)`; an empty value is the account's default.
const MATCH_RULES: &[(&str, &str)] = &[
    ("", "Default match"),
    ("0", "Base domain"),
    ("1", "Host"),
    ("2", "Starts with"),
    ("3", "Exact"),
    ("4", "Regular expression"),
    ("5", "Never"),
];

/// One login address in the editor: a web address with its match rule, or an Android
/// app by package name (saved as `androidapp://<package>`).
struct AddressRow {
    entry: gtk::Entry,
    /// Web addresses only.
    rule: Option<gtk::DropDown>,
    root: gtk::Box,
}

impl AddressRow {
    fn json(&self) -> Option<serde_json::Value> {
        let text = self.entry.text().trim().to_string();
        if text.is_empty() {
            return None;
        }
        Some(match &self.rule {
            Some(rule) => {
                let value = MATCH_RULES.get(rule.selected() as usize).map_or("", |(v, _)| v);
                json!({"uri": text, "match": value.parse::<i64>().ok()})
            }
            // The rule an app's address had stays with it.
            None => json!(nyx_passwords_core::matching::android_uri(&text).unwrap_or(text)),
        })
    }

    /// An Android row whose package name isn't one.
    fn invalid(&self) -> bool {
        self.rule.is_none()
            && !self.entry.text().trim().is_empty()
            && nyx_passwords_core::matching::android_uri(&self.entry.text()).is_none()
    }
}

/// A login's web addresses and Android apps.
struct Addresses {
    web: gtk::Box,
    apps: gtk::Box,
    rows: RefCell<Vec<Rc<AddressRow>>>,
}

impl Addresses {
    fn new() -> Rc<Addresses> {
        Rc::new(Addresses { web: w::vbox(6), apps: w::vbox(6), rows: RefCell::new(Vec::new()) })
    }

    /// Adds a row; `rule` is the stored match rule of a web address.
    fn add(self: &Rc<Self>, android: bool, text: &str, rule: Option<i64>) -> Rc<AddressRow> {
        let root = w::hbox(6);
        let entry = gtk::Entry::new();
        entry.set_hexpand(true);
        entry.set_text(text);
        root.append(&entry);
        let rule = if android {
            entry.set_placeholder_text(Some("com.example.app"));
            entry.connect_changed(|e| {
                let text = e.text();
                let bad = !text.trim().is_empty() && nyx_passwords_core::matching::android_uri(&text).is_none();
                if bad { e.add_css_class("error") } else { e.remove_css_class("error") }
            });
            None
        } else {
            entry.set_placeholder_text(Some("https://example.com"));
            let rows: Vec<(String, String)> = MATCH_RULES.iter().map(|(v, l)| (v.to_string(), l.to_string())).collect();
            let current = rule.map(|r| r.to_string()).unwrap_or_default();
            let drop = w::dropdown(&rows, &current);
            drop.set_tooltip_text(Some("How this address is matched to pages"));
            root.append(&drop);
            Some(drop)
        };
        let remove = w::bar_button("user-trash-symbolic", if android { "Remove this app" } else { "Remove this address" });
        root.append(&remove);
        let row = Rc::new(AddressRow { entry, rule, root });
        if android { &self.apps } else { &self.web }.append(&row.root);
        self.rows.borrow_mut().push(row.clone());
        let (a, r) = (Rc::downgrade(self), Rc::downgrade(&row));
        remove.connect_clicked(move |_| {
            if let (Some(a), Some(r)) = (a.upgrade(), r.upgrade()) {
                if let Some(parent) = r.root.parent().and_downcast::<gtk::Box>() {
                    parent.remove(&r.root);
                }
                a.rows.borrow_mut().retain(|x| !Rc::ptr_eq(x, &r));
            }
        });
        row
    }

    /// Fills in an item's addresses: Android apps in their own group.
    fn load(self: &Rc<Self>, uris: &[String], rules: &[Option<i64>]) {
        for (i, uri) in uris.iter().enumerate() {
            match nyx_passwords_core::matching::android_package(uri) {
                Some(package) => self.add(true, package, None),
                None => self.add(false, uri, rules.get(i).copied().flatten()),
            };
        }
    }

    /// Web addresses first, then apps, each in the order shown.
    fn json(&self) -> Vec<serde_json::Value> {
        let rows = self.rows.borrow();
        let (web, apps): (Vec<_>, Vec<_>) = rows.iter().partition(|r| r.rule.is_some());
        web.iter().chain(apps.iter()).filter_map(|r| r.json()).collect()
    }

    fn first_web(&self) -> String {
        self.rows
            .borrow()
            .iter()
            .filter(|r| r.rule.is_some())
            .map(|r| r.entry.text().trim().to_string())
            .find(|t| !t.is_empty())
            .unwrap_or_default()
    }

    fn invalid(&self) -> Option<gtk::Entry> {
        self.rows.borrow().iter().find(|r| r.invalid()).map(|r| r.entry.clone())
    }
}

struct Form {
    kind: Cell<&'static str>,
    name: gtk::Entry,
    login: gtk::Box,
    username: gtk::Entry,
    password: gtk::PasswordEntry,
    totp: gtk::Entry,
    addresses: Rc<Addresses>,
    /// A note's, card's or identity's own fields, rebuilt when the kind changes.
    others: gtk::Box,
    fields: RefCell<Vec<(&'static str, Control)>>,
    notes: gtk::TextView,
    folder: gtk::DropDown,
    folder_ids: Vec<Option<String>>,
    favorite: gtk::Switch,
    reprompt: gtk::Switch,
    banner: gtk::Box,
    /// `None` for "Me", else an organization's id; the item's own when it has one.
    owner: gtk::DropDown,
    owner_ids: Vec<Option<String>>,
    /// The chosen organization's collections, as checkboxes.
    collections: gtk::Box,
    collection_checks: RefCell<Vec<(String, gtk::CheckButton)>>,
    /// Said when a personal item is about to move into an organization.
    move_note: gtk::Label,
    custom_box: gtk::Box,
    custom: RefCell<Vec<Rc<CustomRow>>>,
    /// The item's custom fields are all in the form (an edit sends them only then, so a
    /// failed load can't wipe them).
    custom_ready: Cell<bool>,
    /// A login's "Sign in with …" provider (empty: its password), and whether it's filled
    /// as its page loads; kept as custom fields (`proto::custom`), from these positions.
    sign_in_with: gtk::DropDown,
    provider_ids: Vec<String>,
    fill_on_load: gtk::Switch,
    special_from: Cell<(Option<usize>, Option<usize>)>,
    /// The labels and parts a template changes or leaves out.
    parts: Parts,
    /// The kind's own fields: name, the part holding label and control, the label.
    kind_parts: RefCell<Vec<(&'static str, gtk::Box, gtk::Label)>>,
    template: RefCell<Option<Template>>,
    /// The template saved with the item (`nyx:template`), from this position. It may be
    /// one this machine doesn't know; it's kept anyway.
    template_id: RefCell<Option<String>>,
    template_from: Cell<Option<usize>>,
    /// The email alias the username is, `(address, "<service>:<id>")`, kept as the
    /// `nyx:alias` field (from this position) while the username stays that address.
    alias_link: RefCell<Option<(String, String)>>,
    alias_from: Cell<Option<usize>>,
    /// A security fix to make once the item's fields are in.
    fix: Cell<Option<Fix>>,
    /// Travel-sensitive (`nyx:travel`), kept from this position.
    travel: gtk::Switch,
    travel_from: Cell<Option<usize>>,
}

/// A login's parts, by what a template can relabel or leave out.
struct Parts {
    username: gtk::Label,
    password: gtk::Label,
    totp: gtk::Label,
    web: gtk::Label,
    notes: gtk::Label,
    notes_hint: gtk::Label,
    custom: gtk::Label,
    totp_box: gtk::Box,
    web_box: gtk::Box,
    apps_box: gtk::Box,
    browser_box: gtk::Box,
}

impl Form {
    /// Adds a custom field row; `name` and `value` for one the item already has.
    fn add_custom(
        self: &Rc<Self>,
        kind: i64,
        source: Option<usize>,
        keep_source: bool,
        name: &str,
        locked: bool,
    ) -> Rc<CustomRow> {
        let root = w::hbox(6);
        let name_entry = gtk::Entry::new();
        name_entry.set_placeholder_text(Some("Name"));
        name_entry.set_width_chars(12);
        name_entry.set_text(name);
        root.append(&name_entry);
        let value = match kind {
            1 => {
                let p = gtk::PasswordEntry::new();
                p.set_show_peek_icon(true);
                p.set_hexpand(true);
                if locked {
                    p.set_sensitive(false);
                    p.set_placeholder_text(Some("Hidden by its organization"));
                }
                root.append(&p);
                CustomValue::Hidden(p)
            }
            2 => {
                let s = gtk::Switch::new();
                s.set_valign(gtk::Align::Center);
                let spacer = w::hbox(0);
                spacer.set_hexpand(true);
                root.append(&s);
                root.append(&spacer);
                CustomValue::Flag(s)
            }
            _ => {
                let e = gtk::Entry::new();
                e.set_placeholder_text(Some("Value"));
                e.set_hexpand(true);
                root.append(&e);
                CustomValue::Text(e)
            }
        };
        let remove = w::bar_button("user-trash-symbolic", "Remove this field");
        root.append(&remove);
        let row = Rc::new(CustomRow {
            source,
            keep_source,
            kind,
            name: name_entry,
            value,
            locked,
            root,
            remove: remove.clone(),
            fixed: Cell::new(false),
        });
        self.custom_box.append(&row.root);
        self.custom.borrow_mut().push(row.clone());
        let (f, r) = (Rc::downgrade(self), Rc::downgrade(&row));
        remove.connect_clicked(move |_| {
            if let (Some(f), Some(r)) = (f.upgrade(), r.upgrade()) {
                f.custom_box.remove(&r.root);
                f.custom.borrow_mut().retain(|x| !Rc::ptr_eq(x, &r));
            }
        });
        row
    }

    fn clear_custom(&self) {
        for row in self.custom.borrow_mut().drain(..) {
            self.custom_box.remove(&row.root);
        }
    }

    /// Lays the form out for `template` (or the plain kind): its labels and examples, its
    /// custom fields, and only the parts it uses. A part it doesn't use stays visible
    /// while it holds something, so nothing an item has is hidden.
    fn apply_template(self: &Rc<Self>, template: Option<Template>) {
        let t = template.as_ref();
        let label_for = |slot: Slot, plain: &str| t.and_then(|t| t.label_for(slot)).unwrap_or(plain).to_string();
        let hint_for = |slot: Slot| {
            t.and_then(|t| t.fields.iter().find(|f| f.slot(&t.kind) == Some(slot))).map_or("", |f| f.hint.as_str()).to_string()
        };
        let uses = |slot: Slot| t.is_none_or(|t| t.label_for(slot).is_some());
        let parts = &self.parts;
        parts.username.set_text(&label_for(Slot::Username, "Username"));
        parts.password.set_text(&label_for(Slot::Password, "Password"));
        parts.totp.set_text(&label_for(Slot::Totp, "One-time code key"));
        parts.web.set_text(&label_for(Slot::Uri, "Web addresses"));
        parts.notes.set_text(&label_for(Slot::Notes, "Notes"));
        parts.custom.set_text(if t.is_some_and(|t| t.custom_fields().next().is_some()) { "Details" } else { "Custom fields" });
        let hint = hint_for(Slot::Username);
        self.username.set_placeholder_text((!hint.is_empty()).then_some(hint.as_str()));
        let hint = hint_for(Slot::Notes);
        if let Some(rows) = self.addresses.rows.borrow().iter().find(|r| r.rule.is_some()) {
            let web = hint_for(Slot::Uri);
            rows.entry.set_placeholder_text(Some(if web.is_empty() { "https://example.com" } else { web.as_str() }));
        }
        parts.notes_hint.set_text(&hint);
        parts.notes_hint.set_visible(!hint.is_empty());
        let rows = self.addresses.rows.borrow();
        let has_web = rows.iter().any(|r| r.rule.is_some() && !r.entry.text().trim().is_empty());
        let has_app = rows.iter().any(|r| r.rule.is_none() && !r.entry.text().trim().is_empty());
        drop(rows);
        parts.totp_box.set_visible(uses(Slot::Totp) || !self.totp.text().trim().is_empty());
        parts.web_box.set_visible(uses(Slot::Uri) || has_web);
        parts.apps_box.set_visible(t.is_none() || has_app);
        parts.browser_box.set_visible(t.is_none() || self.sign_in_with.selected() != 0);
        for (name, wrap, label) in self.kind_parts.borrow().iter() {
            let spec = fields::of_kind(self.kind.get()).iter().find(|s| s.name == *name);
            let filled = self.fields.borrow().iter().any(|(n, c)| n == name && !c.text().is_empty());
            label.set_text(&label_for(Slot::Own(name), spec.map_or(*name, |s| s.label)));
            wrap.set_visible(uses(Slot::Own(name)) || filled || self.kind.get() == "ssh");
        }
        // The last template's fields that were left empty go; filled ones stay as fields
        // of their own.
        let gone: Vec<Rc<CustomRow>> = self.custom.borrow().iter().filter(|r| r.fixed.get() && r.is_empty()).cloned().collect();
        for row in gone {
            self.custom_box.remove(&row.root);
            self.custom.borrow_mut().retain(|x| !Rc::ptr_eq(x, &row));
        }
        for row in self.custom.borrow().iter() {
            row.fixed.set(false);
            row.name.set_editable(true);
            row.name.set_can_focus(true);
            row.name.remove_css_class("template-label");
            row.remove.set_visible(true);
        }
        if let Some(t) = t {
            for f in &t.fields {
                let Some(Slot::Custom(kind)) = f.slot(&t.kind) else { continue };
                let existing = self.custom.borrow().iter().find(|r| r.name.text().trim() == f.label && r.kind == kind).cloned();
                let row = existing.unwrap_or_else(|| self.add_custom(kind, None, false, &f.label, false));
                row.fix(&f.hint);
            }
        }
        *self.template.borrow_mut() = template;
    }

    fn organization(&self) -> Option<String> {
        self.owner_ids.get(self.owner.selected() as usize).cloned().flatten()
    }

    /// Lists the chosen organization's collections; `current` are ticked. Ones this
    /// account can't write to can't be ticked or unticked.
    fn show_collections(&self, ui: &Ui, current: &[String]) {
        ui::clear(&self.collections);
        let mut checks = Vec::new();
        if let Some(org) = self.organization() {
            self.collections.append(&label("Collections", "account-field"));
            for c in ui.listing.borrow().collections.iter().filter(|c| c.organization == org) {
                let check = gtk::CheckButton::with_label(&c.name);
                check.set_active(current.contains(&c.id));
                check.set_sensitive(c.writable);
                if !c.writable {
                    check.set_tooltip_text(Some("Read-only for you"));
                }
                self.collections.append(&check);
                checks.push((c.id.clone(), check));
            }
        }
        self.collections.set_visible(!checks.is_empty());
        *self.collection_checks.borrow_mut() = checks;
    }

    /// For an item whose organization hides its secrets: those fields can't be seen or
    /// changed here, and keep their stored values when saved.
    fn hide_secrets(&self) {
        for (name, control) in self.fields.borrow().iter() {
            let secret = fields::of_kind(self.kind.get()).iter().any(|s| s.name == *name && s.secret);
            match control {
                Control::Key(k) => {
                    k.summary.set_text("Hidden by its organization; the key stays as it is.");
                    k.public.set_visible(false);
                    k.buttons.set_sensitive(false);
                }
                Control::Secret(p) if secret => {
                    p.set_sensitive(false);
                    p.set_placeholder_text(Some("Hidden by its organization"));
                }
                _ => {}
            }
        }
    }

    fn chosen_collections(&self) -> Vec<String> {
        self.collection_checks.borrow().iter().filter(|(_, c)| c.is_active()).map(|(id, _)| id.clone()).collect()
    }
    /// Shows the fields of `kind`: the login form, or the kind's own fields. An SSH key's
    /// public key and fingerprint come from its private key, so only that is edited.
    fn show_kind(&self, ui: &Ui, kind: &'static str) {
        self.kind.set(kind);
        self.login.set_visible(kind == "login");
        ui::clear(&self.others);
        let mut controls = Vec::new();
        let mut parts = Vec::new();
        if kind == "ssh" {
            let control = Control::Key(KeyPicker::new(ui));
            let (wrap, title) = part(&self.others, "Key", &control.widget());
            controls.push(("ssh.privateKey", control));
            parts.push(("ssh.privateKey", wrap, title));
        } else {
            for spec in fields::of_kind(kind) {
                let control = Control::new(spec);
                let (wrap, title) = part(&self.others, spec.label, &control.widget());
                controls.push((spec.name, control));
                parts.push((spec.name, wrap, title));
            }
        }
        self.others.set_visible(!controls.is_empty());
        *self.fields.borrow_mut() = controls;
        *self.kind_parts.borrow_mut() = parts;
    }
}

/// What a new item starts as: the sidebar's kind (`Ok`) or template (`Err(id)`) when
/// one is open, else a login.
fn starting_kind(ui: &Ui) -> Result<&'static str, String> {
    let section = ui.section.borrow();
    if let Some(id) = section.strip_prefix("template:") {
        return Err(id.to_string());
    }
    Ok(KINDS.iter().copied().find(|k| *k == section.as_str()).unwrap_or("login"))
}

/// The editor: a card over the window rather than a window of its own, so it can't fall
/// behind the main window or keep the app from closing.
#[derive(Clone)]
pub struct Sheet {
    veil: gtk::Box,
    ui: std::rc::Weak<ui::State>,
}

impl Sheet {
    pub fn close(&self) {
        if let Some(overlay) = self.veil.parent().and_downcast::<gtk::Overlay>() {
            if let Some(child) = overlay.child() {
                child.set_sensitive(true);
            }
            overlay.remove_overlay(&self.veil);
        }
        if let Some(ui) = self.ui.upgrade()
            && let Ok(mut editor) = ui.editor.try_borrow_mut()
        {
            editor.take();
        }
    }

    pub fn present(&self) {
        self.veil.child_focus(gtk::DirectionType::TabForward);
    }
}

pub fn open(ui: &Ui, entry: Option<Entry>) {
    open_with(ui, entry, false, None);
}

/// A fix from the security report, made in the editor once the item's fields are in;
/// nothing is saved until the user saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fix {
    /// A new password from the generator.
    NewPassword,
    /// `http://` addresses become `https://`.
    Https,
    /// The one-time code key field, ready to paste into.
    TotpKey,
}

pub fn open_fix(ui: &Ui, entry: Entry, fix: Fix) {
    open_with(ui, Some(entry), false, Some(fix));
}

/// Applies a security fix once the form holds the item, and says what changed.
fn apply_fix(ui: &Ui, form: &Rc<Form>) {
    let Some(fix) = form.fix.take() else { return };
    let say = |text: &str| {
        ui::clear(&form.banner);
        form.banner.append(&w::banner(text, false));
    };
    match fix {
        Fix::NewPassword => {
            say("A new password is filled in. Save, then change it on the site to the same one.");
            generate_password(ui, form);
        }
        Fix::Https => {
            for row in form.addresses.rows.borrow().iter().filter(|r| r.rule.is_some()) {
                let text = row.entry.text();
                if let Some(rest) = text.trim().strip_prefix("http://") {
                    row.entry.set_text(&format!("https://{rest}"));
                }
            }
            say("Its http:// addresses now start with https://. Check the site opens that way, then save.");
        }
        Fix::TotpKey => {
            form.parts.totp_box.set_visible(true);
            form.totp.grab_focus();
            say("Turn on two-step login on the site, then paste its setup key or otpauth:// link here and save.");
        }
    }
}

/// Fills the password field from the generator settings.
fn generate_password(ui: &Ui, form: &Rc<Form>) {
    let (u, f) = (ui.clone(), form.clone());
    glib::spawn_future_local(async move {
        let p = prefs::get().vault;
        let rules = if p.generate_passphrase {
            let mut v = serde_json::to_value(&p.passphrase_rules).unwrap_or_default();
            v["kind"] = "passphrase".into();
            v
        } else {
            let mut v = serde_json::to_value(&p.password_rules).unwrap_or_default();
            v["kind"] = "password".into();
            v
        };
        match client::text("GeneratePassword", Some((rules.to_string(),).to_variant())).await {
            Ok(made) => {
                f.password.set_text(&made);
                f.password.set_show_peek_icon(true);
            }
            Err(e) => ui::toast(&u, &e.to_string()),
        }
    });
}

/// A new item with another's contents: its secrets, custom fields and notes, but not
/// its attachments or passkeys.
pub fn open_copy(ui: &Ui, entry: Entry) {
    open_with(ui, Some(entry), true, None);
}

fn open_with(ui: &Ui, entry: Option<Entry>, copy: bool, fix: Option<Fix>) {
    if let Some(e) = ui.editor.borrow().as_ref() {
        e.present();
        return;
    }
    // A new item starts as the sidebar's template or kind; the picker lists the plain
    // kinds, then the templates (`t:<id>`).
    let start = starting_kind(ui);
    let kind = match &entry {
        Some(e) => match KINDS.iter().copied().find(|k| *k == e.kind) {
            Some(k) => k,
            None => return,
        },
        None => KINDS.iter().copied().find(|k| start.as_ref().is_ok_and(|s| s == k)).unwrap_or("login"),
    };
    let start_template = match &entry {
        Some(e) => e.template.as_deref().and_then(templates::find),
        None => start.as_ref().err().and_then(|id| templates::find(id)),
    };
    let kind = start_template.as_ref().and_then(|t| KINDS.iter().copied().find(|k| *k == t.kind)).unwrap_or(kind);
    let what = start_template.as_ref().map_or_else(|| noun(kind), |t| t.name.to_lowercase());
    let title = match &entry {
        Some(_) if copy => format!("Copy {what}"),
        Some(_) => format!("Edit {what}"),
        None => "New item".to_string(),
    };
    let veil = w::vbox(0);
    veil.add_css_class("settings-veil");
    veil.set_hexpand(true);
    veil.set_vexpand(true);
    let card = w::vbox(12);
    card.add_css_class("dialog-card");
    card.add_css_class("editor-sheet");
    card.set_halign(gtk::Align::Center);
    card.set_valign(gtk::Align::Center);
    card.set_vexpand(true);
    card.set_size_request(560, -1);
    card.append(&w::label(&title, "section-title"));
    veil.append(&card);
    // The window behind can't be clicked or tabbed into while the editor is open.
    if let Some(child) = ui.overlay.child() {
        child.set_sensitive(false);
    }
    ui.overlay.add_overlay(&veil);
    ui.overlay.set_measure_overlay(&veil, false);
    ui::raise_toast(ui);
    let dialog = Sheet { veil: veil.clone(), ui: Rc::downgrade(ui) };
    *ui.editor.borrow_mut() = Some(dialog.clone());

    let body = w::vbox(8);
    let scroll = ui::scroll(&body);
    scroll.set_vexpand(false);
    scroll.set_propagate_natural_height(true);
    scroll.set_min_content_height(280);
    scroll.set_max_content_height(520);
    card.append(&scroll);
    let banner = w::vbox(0);
    body.append(&banner);

    let mut kind_rows: Vec<(String, String)> = KINDS.iter().map(|k| (k.to_string(), data::kind_name(k).to_string())).collect();
    kind_rows.extend(templates::all().into_iter().map(|t| (format!("t:{}", t.id), t.name)));
    let picked = start_template.as_ref().map_or_else(|| kind.to_string(), |t| format!("t:{}", t.id));
    let kind_choice = w::dropdown(&kind_rows, &picked);
    kind_choice.set_enable_search(true);
    if entry.is_none() {
        field(&body, "Template", &kind_choice);
    }
    let kind_ids: Vec<String> = kind_rows.iter().map(|(id, _)| id.clone()).collect();

    let name = gtk::Entry::new();
    let username = gtk::Entry::new();
    let password = gtk::PasswordEntry::new();
    password.set_show_peek_icon(true);
    password.set_hexpand(true);
    let totp = gtk::Entry::new();
    totp.set_placeholder_text(Some("otpauth://… or the setup key"));
    let addresses = Addresses::new();
    let notes = text_view(4);
    let listing = ui.listing.borrow();
    let mut folder_ids = vec![None];
    let mut folder_names = vec![("".to_string(), "No folder".to_string())];
    for f in &listing.folders {
        folder_ids.push(Some(f.id.clone()));
        folder_names.push((f.id.clone(), f.name.clone()));
    }
    drop(listing);
    let current_folder = entry.as_ref().and_then(|e| e.folder.clone()).unwrap_or_default();
    let folder = w::dropdown(&folder_names, &current_folder);
    let favorite = gtk::Switch::new();
    let reprompt = gtk::Switch::new();

    // Owner: "Me" or an organization with a collection this account can write to. An
    // organization item stays in its organization.
    let listing = ui.listing.borrow();
    // A copy is a new item: it may go anywhere a new item may, starting where the original is.
    let item_org = entry.as_ref().filter(|_| !copy).and_then(|e| e.organization.clone());
    let owner_current = entry.as_ref().and_then(|e| e.organization.clone()).unwrap_or_default();
    let mut owner_ids = vec![None];
    let mut owner_names = vec![(String::new(), "Me".to_string())];
    for o in &listing.organizations {
        let writable = listing.collections.iter().any(|c| c.organization == o.id && c.writable);
        if item_org.as_deref() == Some(o.id.as_str()) || item_org.is_none() && writable {
            owner_ids.push(Some(o.id.clone()));
            owner_names.push((o.id.clone(), o.name.clone()));
        }
    }
    drop(listing);
    if item_org.is_some() {
        owner_ids.remove(0);
        owner_names.remove(0);
    }
    let owner = w::dropdown(&owner_names, &owner_current);
    owner.set_sensitive(owner_ids.len() > 1);
    let collections = w::vbox(4);
    let move_note = label("Once it's in an organization, it can't be moved back here.", "dim");
    move_note.set_visible(false);

    field(&body, "Name", &name);
    let login = w::vbox(8);
    let user_line = w::hbox(6);
    username.set_hexpand(true);
    user_line.append(&username);
    let generate_user = w::bar_button("media-playlist-shuffle-symbolic", "Generate a username (see Settings → Generator)");
    user_line.append(&generate_user);
    let (_, username_label) = part(&login, "Username", &user_line);
    let pw_line = w::hbox(6);
    pw_line.append(&password);
    let generate = w::bar_button("media-playlist-shuffle-symbolic", "Generate a password");
    pw_line.append(&generate);
    let history = w::bar_button("document-open-recent-symbolic", "What the generators made while the vault was open");
    pw_line.append(&history);
    let u = ui.clone();
    history.connect_clicked(move |_| show_history(&u));
    body.append(&login);
    let others = w::vbox(8);
    body.append(&others);
    let hidden_note = label("Its organization hides this login's password from you; it stays as it is.", "dim");
    hidden_note.set_visible(entry.as_ref().is_some_and(|e| !e.view_password));
    let password_label = label("Password", "account-field");
    let (totp_box, totp_label) = (w::vbox(8), label("One-time code key", "account-field"));
    if !hidden_note.is_visible() {
        login.append(&password_label);
        login.append(&pw_line);
        totp_box.append(&totp_label);
        totp_box.append(&totp);
        login.append(&totp_box);
    } else {
        login.append(&hidden_note);
    }
    let web_box = w::vbox(8);
    let web_label = label("Web addresses", "account-field");
    web_box.append(&web_label);
    web_box.append(&addresses.web);
    let add_address = gtk::Button::with_label("Add address");
    add_address.set_halign(gtk::Align::Start);
    web_box.append(&add_address);
    login.append(&web_box);
    let a = addresses.clone();
    add_address.connect_clicked(move |_| {
        a.add(false, "", None).entry.grab_focus();
    });
    let apps_box = w::vbox(8);
    apps_box.append(&label("Android apps", "account-field"));
    apps_box
        .append(&label("Package names the Bitwarden Android app fills this login into, such as com.instagram.android.", "dim"));
    apps_box.append(&addresses.apps);
    let add_app = gtk::Button::with_label("Add app");
    add_app.set_halign(gtk::Align::Start);
    apps_box.append(&add_app);
    login.append(&apps_box);
    let a = addresses.clone();
    add_app.connect_clicked(move |_| {
        a.add(true, "", None).entry.grab_focus();
    });
    let mut provider_rows = vec![(String::new(), "Its password".to_string())];
    provider_rows.extend(custom::PROVIDERS.iter().map(|(id, name)| (id.to_string(), format!("“Sign in with {name}”"))));
    let provider_ids: Vec<String> = provider_rows.iter().map(|(id, _)| id.clone()).collect();
    let sign_in_with = w::dropdown(&provider_rows, "");
    let browser_box = w::vbox(8);
    field(&browser_box, "Signs in with", &sign_in_with);
    let fill_on_load = gtk::Switch::new();
    fill_on_load.set_active(true);
    let load_rows = w::vbox(0);
    load_rows.add_css_class("group-list");
    load_rows.append(&w::row(
        "Fill as the page loads",
        "In paired browsers, when that's on in Settings → Browsers.",
        Some(fill_on_load.upcast_ref()),
    ));
    browser_box.append(&load_rows);
    login.append(&browser_box);
    let custom_box = w::vbox(6);
    let custom_label = label("Custom fields", "account-field");
    body.append(&custom_label);
    body.append(&custom_box);
    let add_line = w::hbox(6);
    let custom_kinds: Vec<(String, String)> = CUSTOM_KINDS.iter().map(|(k, n)| (k.to_string(), n.to_string())).collect();
    let add_kind = w::dropdown(&custom_kinds, "0");
    let add_custom = gtk::Button::with_label("Add field");
    add_line.append(&add_kind);
    add_line.append(&add_custom);
    body.append(&add_line);
    if owner_ids.len() > 1 || item_org.is_some() {
        field(&body, "Owner", &owner);
        body.append(&move_note);
        body.append(&collections);
    }
    field(&body, "Folder", &folder);
    let rows = w::vbox(0);
    rows.add_css_class("group-list");
    rows.append(&w::row("Favorite", "Show it under Favorites.", Some(favorite.upcast_ref())));
    rows.append(&w::row(
        "Ask for master password",
        "Ask for it again before showing or copying this item's secrets.",
        Some(reprompt.upcast_ref()),
    ));
    let travel = gtk::Switch::new();
    travel.set_active(entry.as_ref().is_some_and(|e| e.travel));
    rows.append(&w::row(
        "Travel-sensitive",
        "Leave it off this device while Travel Mode is on (Settings → Travel Mode).",
        Some(travel.upcast_ref()),
    ));
    body.append(&rows);
    let notes_label = label("Notes", "account-field");
    body.append(&notes_label);
    let notes_hint = label("", "dim");
    notes_hint.set_visible(false);
    body.append(&notes_hint);
    body.append(&frame(&notes));
    let parts = Parts {
        username: username_label,
        password: password_label,
        totp: totp_label,
        web: web_label,
        notes: notes_label,
        notes_hint,
        custom: custom_label,
        totp_box,
        web_box,
        apps_box,
        browser_box,
    };

    let form = Rc::new(Form {
        kind: Cell::new(kind),
        name,
        login,
        username,
        password,
        totp,
        addresses,
        others,
        fields: RefCell::new(Vec::new()),
        notes,
        folder,
        folder_ids,
        favorite,
        reprompt,
        banner,
        owner,
        owner_ids,
        collections,
        collection_checks: RefCell::new(Vec::new()),
        move_note,
        custom_box,
        custom: RefCell::new(Vec::new()),
        custom_ready: Cell::new(entry.is_none()),
        sign_in_with,
        provider_ids,
        fill_on_load,
        special_from: Cell::new((None, None)),
        parts,
        kind_parts: RefCell::new(Vec::new()),
        template: RefCell::new(None),
        template_id: RefCell::new(entry.as_ref().and_then(|e| e.template.clone())),
        template_from: Cell::new(None),
        alias_link: RefCell::new(None),
        alias_from: Cell::new(None),
        fix: Cell::new(fix),
        travel,
        travel_from: Cell::new(None),
    });
    form.show_kind(ui, kind);
    form.show_collections(ui, &entry.as_ref().map(|e| e.collections.clone()).unwrap_or_default());
    let f = form.clone();
    add_custom.connect_clicked(move |_| {
        let kind = CUSTOM_KINDS.get(add_kind.selected() as usize).map_or(0, |(k, _)| *k);
        f.add_custom(kind, None, false, "", false).name.grab_focus();
    });
    let personal = !copy && entry.as_ref().is_some_and(|e| e.organization.is_none());
    let (u, f) = (ui.clone(), form.clone());
    form.owner.connect_selected_notify(move |_| {
        f.show_collections(&u, &[]);
        f.move_note.set_visible(personal && f.organization().is_some());
    });
    let (u, f) = (ui.clone(), form.clone());
    kind_choice.connect_selected_notify(move |d| {
        let Some(id) = kind_ids.get(d.selected() as usize) else { return };
        let template = id.strip_prefix("t:").and_then(templates::find);
        let kind = template.as_ref().map_or(id.as_str(), |t| t.kind.as_str());
        if let Some(k) = KINDS.iter().copied().find(|k| *k == kind) {
            f.show_kind(&u, k);
        }
        *f.template_id.borrow_mut() = template.as_ref().map(|t| t.id.clone());
        f.apply_template(template);
    });
    let id = entry.as_ref().filter(|_| !copy).map(|e| e.id.clone());
    if let Some(e) = &entry {
        form.name.set_text(&if copy { format!("{} (copy)", e.name) } else { e.name.clone() });
        form.username.set_text(e.username.as_deref().unwrap_or(""));
        form.addresses.load(&e.uris, &e.uri_rules);
        form.favorite.set_active(e.favorite);
        form.reprompt.set_active(e.reprompt);
        fill_secrets(ui, &e.id, &form, &dialog, copy);
    }
    if form.addresses.rows.borrow().is_empty() {
        form.addresses.add(false, "", None);
    }
    // An item being edited is laid out once its fields are in (`fill_secrets`).
    if entry.is_none() {
        *form.template_id.borrow_mut() = start_template.as_ref().map(|t| t.id.clone());
        form.apply_template(start_template);
    }

    let (u, f) = (ui.clone(), form.clone());
    generate.connect_clicked(move |_| generate_password(&u, &f));

    let (u, f) = (ui.clone(), form.clone());
    generate_user.connect_clicked(move |b| {
        let site = f.addresses.first_web();
        let (u, f, b) = (u.clone(), f.clone(), b.clone());
        b.set_sensitive(false);
        let forwarded = prefs::get().vault.username_rules.kind == nyx_passwords_core::alias::UsernameKind::Forwarded;
        glib::spawn_future_local(async move {
            // An alias from a service is made so the login can remember which it is.
            let method = if forwarded { "CreateAlias" } else { "GenerateUsername" };
            match client::text(method, Some((site.as_str(),).to_variant())).await {
                Ok(made) if forwarded => {
                    let v: serde_json::Value = serde_json::from_str(&made).unwrap_or_default();
                    let email = v["email"].as_str().unwrap_or_default().to_string();
                    f.username.set_text(&email);
                    let (service, id) = (v["service"].as_str().unwrap_or_default(), v["id"].as_str().unwrap_or_default());
                    if !id.is_empty() {
                        *f.alias_link.borrow_mut() = Some((email, format!("{service}:{id}")));
                    }
                }
                Ok(made) => f.username.set_text(&made),
                Err(e) => ui::toast(&u, &e.to_string()),
            }
            b.set_sensitive(true);
        });
    });

    let cancel = gtk::Button::with_label("Cancel");
    let save = gtk::Button::with_label("Save");
    save.add_css_class("suggested-action");
    save.set_tooltip_text(Some("Save (Ctrl+S)"));
    let actions = w::hbox(8);
    actions.set_halign(gtk::Align::End);
    actions.append(&cancel);
    actions.append(&save);
    card.append(&actions);
    let d = dialog.clone();
    cancel.connect_clicked(move |_| d.close());
    let submit = {
        let (u, f, d, save) = (ui.clone(), form.clone(), dialog.clone(), save.clone());
        Rc::new(move || submit(&u, &f, id.clone(), &d, &save))
    };
    let s = submit.clone();
    save.connect_clicked(move |_| s());
    let keys = gtk::EventControllerKey::new();
    let (s, d) = (submit.clone(), dialog.clone());
    keys.connect_key_pressed(move |_, key, _, mods| {
        if mods.contains(gdk::ModifierType::CONTROL_MASK) && matches!(key, gdk::Key::s | gdk::Key::S) {
            s();
            return glib::Propagation::Stop;
        }
        if key == gdk::Key::Escape {
            d.close();
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    veil.add_controller(keys);
    form.name.grab_focus();
}

/// The generator history: what was made while the vault was open, newest first, each
/// hidden until shown. Copies go through the daemon, which clears them later.
fn show_history(ui: &Ui) {
    #[derive(serde::Deserialize)]
    struct Made {
        what: String,
        value: String,
        when: u64,
    }
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let list = match client::text("GeneratorHistory", None).await {
            Ok(json) => serde_json::from_str::<Vec<Made>>(&json).unwrap_or_default(),
            Err(e) => return ui::toast(&ui, &e.to_string()),
        };
        let (dialog, card) = w::dialog("Generator history", 480);
        crate::dialog_dismissal::add(&dialog, &card, "Close");
        dialog.set_transient_for(Some(&ui.window));
        if list.is_empty() {
            card.append(&label("Nothing generated since the vault was unlocked.", "dim"));
        }
        let rows = w::vbox(0);
        rows.add_css_class("group-list");
        for (i, m) in list.into_iter().enumerate() {
            let value = gtk::PasswordEntry::new();
            value.set_text(&m.value);
            value.set_editable(false);
            value.set_show_peek_icon(true);
            value.set_hexpand(true);
            let copy = w::bar_button("edit-copy-symbolic", "Copy");
            let u = ui.clone();
            copy.connect_clicked(move |_| {
                let u = u.clone();
                glib::spawn_future_local(async move {
                    match client::call("CopyGenerated", Some((i as u32,).to_variant())).await {
                        Ok(_) => ui::toast(&u, "Copied."),
                        Err(e) => ui::toast(&u, &e.to_string()),
                    }
                });
            });
            let line = w::hbox(6);
            line.append(&value);
            line.append(&copy);
            let what = if m.what == "username" { "Username" } else { "Password" };
            rows.append(&w::row(&format!("{what} · {}", data::ago(m.when)), "", Some(line.upcast_ref())));
        }
        card.append(&rows);
        dialog.present();
    });
}

fn field(body: &gtk::Box, title: &str, control: &impl IsA<gtk::Widget>) {
    body.append(&label(title, "account-field"));
    body.append(control);
}

/// A field as one part that can be hidden: its label and control. Returns the part and
/// its label.
fn part(body: &gtk::Box, title: &str, control: &impl IsA<gtk::Widget>) -> (gtk::Box, gtk::Label) {
    let wrap = w::vbox(8);
    let title = label(title, "account-field");
    wrap.append(&title);
    wrap.append(control);
    body.append(&wrap);
    (wrap, title)
}

fn text_view(lines: i32) -> gtk::TextView {
    let t = gtk::TextView::new();
    t.set_wrap_mode(gtk::WrapMode::WordChar);
    t.set_accepts_tab(false);
    t.set_size_request(-1, lines * 22);
    t.add_css_class("editor-text");
    t
}

fn frame(view: &gtk::TextView) -> gtk::Box {
    let b = w::vbox(0);
    b.add_css_class("editor-frame");
    b.append(view);
    b
}

fn text_of(view: &gtk::TextView) -> String {
    let buf = view.buffer();
    buf.text(&buf.start_iter(), &buf.end_iter(), false).to_string()
}

/// Fetches the item's fields into the form: a login's password and one-time code key,
/// or a note's, card's or identity's own fields; its custom fields; then the notes. For
/// a copy, custom fields don't point back at the original.
fn fill_secrets(ui: &Ui, id: &str, form: &Rc<Form>, dialog: &Sheet, copy: bool) {
    let (ui, id, form, dialog) = (ui.clone(), id.to_string(), form.clone(), dialog.clone());
    glib::spawn_future_local(async move {
        let entry = ui.listing.borrow().entries.iter().find(|e| e.id == id).cloned();
        let mut wanted: Vec<String> = Vec::new();
        let visible = entry.as_ref().is_none_or(|e| e.view_password);
        if form.kind.get() == "login" {
            if visible && entry.as_ref().is_some_and(|e| e.has_password) {
                wanted.push("password".into());
            }
            if visible && entry.as_ref().is_some_and(|e| e.has_totp) {
                wanted.push("totp_seed".into());
            }
        }
        let listed = match client::text("Fields", Some((id.as_str(),).to_variant())).await {
            Ok(json) => serde_json::from_str::<Vec<FieldRow>>(&json).unwrap_or_default(),
            Err(e) => {
                ui::toast(&ui, &e.to_string());
                dialog.close();
                return;
            }
        };
        form.clear_custom();
        for row in listed {
            if let Some(n) = row.name.strip_prefix("custom:").and_then(|n| n.parse::<usize>().ok()) {
                // Passwords' own fields have controls of their own.
                let keep = if copy { None } else { Some(n) };
                if row.label == custom::SIGN_IN_WITH {
                    let value = row.value.clone().unwrap_or_default();
                    if let Some(at) = form.provider_ids.iter().position(|p| *p == value) {
                        form.sign_in_with.set_selected(at as u32);
                    }
                    form.special_from.set((keep, form.special_from.get().1));
                    continue;
                }
                if row.label == custom::NO_FILL_ON_LOAD {
                    form.fill_on_load.set_active(row.value.as_deref() != Some("true"));
                    form.special_from.set((form.special_from.get().0, keep));
                    continue;
                }
                if row.label == custom::TEMPLATE && row.kind == 0 {
                    form.template_from.set(keep);
                    continue;
                }
                if row.label == custom::TRAVEL && row.kind == 2 {
                    form.travel.set_active(row.value.as_deref() == Some("true"));
                    form.travel_from.set(keep);
                    continue;
                }
                if row.label == custom::ALIAS && row.kind == 0 {
                    let email = form.username.text().trim().to_string();
                    *form.alias_link.borrow_mut() = row.value.clone().map(|v| (email, v));
                    form.alias_from.set(keep);
                    continue;
                }
                let locked = row.secret && !visible;
                let custom = form.add_custom(row.kind, Some(n), !copy, &row.label, locked);
                match row.value {
                    Some(value) => custom.set(&value),
                    None if row.secret && visible => wanted.push(row.name),
                    None => {}
                }
                continue;
            }
            match row.value {
                Some(value) => set_field(&form, &row.name, &value),
                None if row.secret && visible => wanted.push(row.name),
                None => {}
            }
        }
        if !visible && form.kind.get() != "login" {
            form.hide_secrets();
        }
        wanted.push("notes".into());
        for field in wanted {
            match client::reveal(&id, &field).await {
                Ok(v) => match field.as_str() {
                    "password" => form.password.set_text(&v),
                    "totp_seed" => form.totp.set_text(&v),
                    "notes" => form.notes.buffer().set_text(&v),
                    other => match other.strip_prefix("custom:").and_then(|n| n.parse::<usize>().ok()) {
                        Some(n) => {
                            if let Some(row) = form.custom.borrow().iter().find(|r| r.source == Some(n)) {
                                row.set(&v);
                            }
                        }
                        None => set_field(&form, other, &v),
                    },
                },
                Err(e) if e.is(Code::NoField) => {}
                Err(e) if e.is(Code::Reprompt) => {
                    let (u, i, f, d) = (ui.clone(), id.clone(), form.clone(), dialog.clone());
                    super::account::confirm(&ui, move || fill_secrets(&u, &i, &f, &d, copy));
                    return;
                }
                Err(e) => {
                    ui::toast(&ui, &e.to_string());
                    dialog.close();
                    return;
                }
            }
        }
        let template = form.template_id.borrow().as_deref().and_then(templates::find);
        form.apply_template(template);
        form.custom_ready.set(true);
        apply_fix(&ui, &form);
    });
}

fn set_field(form: &Form, name: &str, value: &str) {
    if let Some((_, control)) = form.fields.borrow().iter().find(|(n, _)| *n == name) {
        control.set(value);
    }
}

fn submit(ui: &Ui, form: &Rc<Form>, id: Option<String>, dialog: &Sheet, save: &gtk::Button) {
    let name = form.name.text().trim().to_string();
    let kind = form.kind.get();
    if name.is_empty() {
        ui::toast(ui, &format!("Give the {} a name.", noun(kind)));
        form.name.grab_focus();
        return;
    }
    let hidden = id.as_ref().is_some_and(|id| ui.listing.borrow().entries.iter().any(|e| e.id == *id && !e.view_password));
    if kind == "ssh" && !hidden && form.fields.borrow().iter().all(|(_, c)| c.text().is_empty()) {
        ui::toast(ui, "Generate a key or import one first.");
        return;
    }
    let folder = form.folder_ids.get(form.folder.selected() as usize).cloned().flatten();
    let organization = form.organization();
    let collections = form.chosen_collections();
    if organization.is_some() && collections.is_empty() {
        ui::toast(ui, "Choose at least one collection.");
        return;
    }
    if !form.custom_ready.get() {
        ui::toast(ui, "Still loading the item; try again in a moment.");
        return;
    }
    let mut custom: Vec<serde_json::Value> = form.custom.borrow().iter().filter_map(|r| r.json()).collect();
    if let Some(template) = form.template_id.borrow().as_ref() {
        custom.push(json!({"name": custom::TEMPLATE, "value": template, "kind": 0, "from": form.template_from.get()}));
    }
    if form.travel.is_active() {
        custom.push(json!({"name": custom::TRAVEL, "value": "true", "kind": 2, "from": form.travel_from.get()}));
    }
    if kind == "login" {
        let (provider_from, load_from) = form.special_from.get();
        let provider = form.provider_ids.get(form.sign_in_with.selected() as usize).cloned().unwrap_or_default();
        if !provider.is_empty() {
            custom.push(json!({"name": custom::SIGN_IN_WITH, "value": provider, "kind": 0, "from": provider_from}));
        }
        if !form.fill_on_load.is_active() {
            custom.push(json!({"name": custom::NO_FILL_ON_LOAD, "value": "true", "kind": 2, "from": load_from}));
        }
        // A username changed away from the alias drops the link.
        if let Some((email, marker)) = form.alias_link.borrow().as_ref()
            && form.username.text().trim().eq_ignore_ascii_case(email)
        {
            custom.push(json!({"name": custom::ALIAS, "value": marker, "kind": 0, "from": form.alias_from.get()}));
        }
    }
    if kind == "login"
        && let Some(bad) = form.addresses.invalid()
    {
        ui::toast(ui, "That isn't an Android package name; they look like com.example.app.");
        bad.grab_focus();
        return;
    }
    let draft = if kind == "login" {
        let uris = form.addresses.json();
        json!({
            "name": name,
            "username": form.username.text().to_string(),
            "password": form.password.text().to_string(),
            "totp": form.totp.text().trim().to_string(),
            "uris": uris,
            "notes": text_of(&form.notes),
            "folder": folder,
            "favorite": form.favorite.is_active(),
            "reprompt": form.reprompt.is_active(),
            "organization": organization,
            "collections": collections,
            "custom": custom,
        })
    } else {
        let fields: serde_json::Map<String, serde_json::Value> =
            form.fields.borrow().iter().map(|(n, c)| (n.to_string(), c.text().into())).collect();
        json!({
            "kind": kind,
            "name": name,
            "fields": fields,
            "notes": text_of(&form.notes),
            "folder": folder,
            "favorite": form.favorite.is_active(),
            "reprompt": form.reprompt.is_active(),
            "organization": organization,
            "collections": collections,
            "custom": custom,
        })
    }
    .to_string();
    let (create, update) = if kind == "login" { ("CreateLogin", "UpdateLogin") } else { ("CreateItem", "UpdateItem") };
    save.set_sensitive(false);
    let (ui, form, dialog, save) = (ui.clone(), form.clone(), dialog.clone(), save.clone());
    glib::spawn_future_local(async move {
        let reply = match &id {
            Some(id) => client::call(update, Some((id.as_str(), draft.as_str()).to_variant())).await.map(|_| id.clone()),
            None => client::text(create, Some((draft.as_str(),).to_variant())).await,
        };
        save.set_sensitive(true);
        match reply {
            Ok(saved) => {
                dialog.close();
                *ui.selected.borrow_mut() = Some(saved);
                ui.showing_detail.set(true);
                ui::reload(&ui);
                ui::toast(&ui, "Saved.");
            }
            Err(e) if e.is(Code::Conflict) => {
                // The daemon now has the server's copy; saving again replaces it with this draft.
                ui::clear(&form.banner);
                form.banner.append(&w::banner(
                    "This item was changed in another app since you opened it. Your edit wasn't saved; save again to replace the other change with yours.",
                    true,
                ));
                ui::reload(&ui);
            }
            Err(e) => {
                if e.is(Code::NotFound) {
                    dialog.close();
                }
                detail::handle(&ui, e, || {});
            }
        }
    });
}
