//! Email aliases: a service's aliases with the logins that use them, copying one,
//! turning one off or on (after asking), and deleting one where the service allows it.
//! Everything goes through the daemon, which holds the services' tokens.

use std::cell::RefCell;
use std::rc::Rc;

use gtk::{glib, prelude::*};
use nyx_ui::widgets as w;
use serde::Deserialize;

use super::client;
use super::ui::{self, Ui, label};

#[derive(Debug, Clone, Deserialize)]
pub struct ServiceInfo {
    pub id: String,
    pub name: String,
    pub list: bool,
    pub toggle: bool,
    pub delete: bool,
    pub token: bool,
    pub chosen: bool,
    pub preferred: bool,
    pub account: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Alias {
    id: String,
    email: String,
    enabled: bool,
    #[serde(default)]
    site: String,
    #[serde(default)]
    note: String,
}

pub async fn services() -> Result<Vec<ServiceInfo>, client::Fail> {
    let json = client::text("AliasServices", None).await?;
    Ok(serde_json::from_str(&json).unwrap_or_default())
}

/// The logins whose username is this alias, or that recorded it (`nyx:alias`).
fn used_by(ui: &Ui, service: &str, a: &Alias) -> Vec<String> {
    let marker = format!("{service}:{}", a.id);
    ui.listing
        .borrow()
        .entries
        .iter()
        .filter(|e| !e.deleted && e.kind == "login")
        .filter(|e| {
            e.alias.as_deref() == Some(marker.as_str())
                || e.username.as_deref().is_some_and(|u| u.trim().eq_ignore_ascii_case(&a.email))
        })
        .map(|e| e.name.clone())
        .collect()
}

pub fn open(ui: &Ui) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let all = match services().await {
            Ok(s) => s,
            Err(e) => return ui::toast(&ui, &e.to_string()),
        };
        let listable: Vec<ServiceInfo> = all.into_iter().filter(|s| s.list).collect();
        let (dialog, card) = w::dialog("Email aliases", 640);
        crate::dialog_dismissal::add(&dialog, &card, "Close");
        dialog.set_transient_for(Some(&ui.window));
        card.append(&label(
            "Aliases from your email alias services, and the logins that use them. DuckDuckGo can only make aliases, so it isn't listed.",
            "dim",
        ));
        let start = listable
            .iter()
            .find(|s| s.chosen && s.token)
            .or_else(|| listable.iter().find(|s| s.preferred))
            .or_else(|| listable.iter().find(|s| s.token))
            .or(listable.first())
            .map(|s| s.id.clone())
            .unwrap_or_default();
        let rows: Vec<(String, String)> = listable
            .iter()
            .map(|s| {
                let mut name = s.name.clone();
                if let Some(account) = s.account.as_ref().filter(|_| s.preferred) {
                    name.push_str(&format!(" · {account} in Online Accounts"));
                }
                if !s.token {
                    name.push_str(" · no token");
                }
                (s.id.clone(), name)
            })
            .collect();
        let pick = w::dropdown(&rows, &start);
        let set_token = gtk::Button::with_label("Set token…");
        let line = w::hbox(8);
        pick.set_hexpand(true);
        line.append(&pick);
        line.append(&set_token);
        card.append(&line);
        let status = w::vbox(0);
        card.append(&status);
        let search = gtk::SearchEntry::new();
        search.set_placeholder_text(Some("Search aliases"));
        card.append(&search);
        let list = w::vbox(0);
        list.add_css_class("group-list");
        let scroll = ui::scroll(&list);
        scroll.set_min_content_height(240);
        scroll.set_max_content_height(420);
        scroll.set_propagate_natural_height(true);
        card.append(&scroll);

        let state = Rc::new(Page { ui: ui.clone(), services: listable, pick, status, search, list, shown: RefCell::default() });
        let s = state.clone();
        state.pick.connect_selected_notify(move |_| s.load());
        let s = state.clone();
        state.search.connect_search_changed(move |_| s.draw());
        let s = state.clone();
        set_token.connect_clicked(move |_| {
            if let Some(service) = s.service() {
                ask_token(&s.ui, &service, {
                    let s = s.clone();
                    move || s.load()
                });
            }
        });
        dialog.present();
        state.load();
    });
}

struct Page {
    ui: Ui,
    services: Vec<ServiceInfo>,
    pick: gtk::DropDown,
    status: gtk::Box,
    search: gtk::SearchEntry,
    list: gtk::Box,
    shown: RefCell<Vec<Alias>>,
}

impl Page {
    fn service(&self) -> Option<ServiceInfo> {
        self.services.get(self.pick.selected() as usize).cloned()
    }

    fn say(&self, text: &str, warning: bool) {
        ui::clear(&self.status);
        if !text.is_empty() {
            self.status.append(&w::banner(text, warning));
        }
    }

    /// Asks the service for its aliases.
    fn load(self: &Rc<Self>) {
        let Some(service) = self.service() else {
            self.say("No email alias service can list its aliases.", false);
            return;
        };
        self.shown.borrow_mut().clear();
        self.draw();
        self.say(&format!("Asking {}…", service.name), false);
        let page = self.clone();
        glib::spawn_future_local(async move {
            match client::text("ListAliases", Some((service.id.as_str(),).to_variant())).await {
                Ok(json) => {
                    *page.shown.borrow_mut() = serde_json::from_str(&json).unwrap_or_default();
                    let n = page.shown.borrow().len();
                    page.say(&format!("{} alias{} at {}.", n, if n == 1 { "" } else { "es" }, service.name), false);
                    page.draw();
                }
                Err(e) => page.say(&format!("{}: {e}", service.name), true),
            }
        });
    }

    fn draw(self: &Rc<Self>) {
        ui::clear(&self.list);
        let Some(service) = self.service() else { return };
        let query = self.search.text().to_lowercase();
        for a in self.shown.borrow().iter() {
            let users = used_by(&self.ui, &service.id, a);
            let hay = format!("{} {} {} {}", a.email, a.site, a.note, users.join(" ")).to_lowercase();
            if !query.split_whitespace().all(|q| hay.contains(q)) {
                continue;
            }
            let mut desc = Vec::new();
            desc.push(if a.enabled { "Active".to_string() } else { "Off".to_string() });
            if !a.site.is_empty() {
                desc.push(a.site.clone());
            }
            if users.is_empty() {
                desc.push("no login uses it".into());
            } else {
                desc.push(format!("used by {}", users.join(", ")));
            }
            let actions = w::hbox(4);
            let copy = w::bar_button("edit-copy-symbolic", "Copy address");
            let (win, email) = (self.ui.window.clone(), a.email.clone());
            copy.connect_clicked(move |_| win.clipboard().set_text(&email));
            actions.append(&copy);
            if service.toggle {
                let on = gtk::Switch::new();
                on.set_active(a.enabled);
                on.set_valign(gtk::Align::Center);
                on.set_tooltip_text(Some("Receive mail at this alias"));
                let (page, id, email) = (self.clone(), a.id.clone(), a.email.clone());
                on.connect_state_set(move |sw, wanted| {
                    page.toggle(sw, &id, &email, wanted);
                    glib::Propagation::Stop
                });
                actions.append(&on);
            }
            if service.delete {
                let delete = w::bar_button("user-trash-symbolic", "Delete this alias");
                let (page, id, email) = (self.clone(), a.id.clone(), a.email.clone());
                delete.connect_clicked(move |_| page.delete(&id, &email));
                actions.append(&delete);
            }
            let row = w::row(&a.email, &glib::markup_escape_text(&desc.join(" · ")), Some(actions.upcast_ref()));
            if !a.enabled {
                row.add_css_class("dim");
            }
            self.list.append(&row);
        }
        self.list.set_visible(self.list.first_child().is_some());
    }

    /// Turns an alias off (after asking: mail to it stops arriving) or on.
    fn toggle(self: &Rc<Self>, sw: &gtk::Switch, id: &str, email: &str, on: bool) {
        let Some(service) = self.service() else { return };
        let (page, sw, id, email) = (self.clone(), sw.clone(), id.to_string(), email.to_string());
        glib::spawn_future_local(async move {
            if !on {
                let detail = format!(
                    "Mail sent to {email} will no longer reach you. Sites that use it may lock you out until you turn it back on."
                );
                if !ui::confirm(&page.ui, "Turn this alias off?", &detail, "Turn off").await {
                    sw.set_active(true);
                    return;
                }
            }
            let args = (service.id.as_str(), id.as_str(), on).to_variant();
            match client::call("SetAliasEnabled", Some(args)).await {
                Ok(_) => {
                    sw.set_state(on);
                    if let Some(a) = page.shown.borrow_mut().iter_mut().find(|a| a.id == id) {
                        a.enabled = on;
                    }
                    page.draw();
                }
                Err(e) => {
                    sw.set_active(!on);
                    page.say(&format!("{}: {e}", service.name), true);
                }
            }
        });
    }

    fn delete(self: &Rc<Self>, id: &str, email: &str) {
        let Some(service) = self.service() else { return };
        let (page, id, email) = (self.clone(), id.to_string(), email.to_string());
        glib::spawn_future_local(async move {
            let detail = format!(
                "Mail sent to {email} will bounce. Logins that use it keep it as their username; change it on those sites first."
            );
            if !ui::confirm(&page.ui, "Delete this alias?", &detail, "Delete").await {
                return;
            }
            match client::call("DeleteAlias", Some((service.id.as_str(), id.as_str()).to_variant())).await {
                Ok(_) => {
                    page.shown.borrow_mut().retain(|a| a.id != id);
                    page.draw();
                }
                Err(e) => page.say(&format!("{}: {e}", service.name), true),
            }
        });
    }
}

/// Asks for a service's API token and saves it in the keyring through the daemon.
pub fn ask_token(ui: &Ui, service: &ServiceInfo, done: impl Fn() + 'static) {
    let (dialog, card) = w::dialog(&format!("{} token", service.name), 440);
    crate::dialog_dismissal::add(&dialog, &card, "Cancel");
    dialog.set_transient_for(Some(&ui.window));
    let hint = match service.id.as_str() {
        "fastmail" => "Make one in Fastmail: Settings → Privacy & Security → API tokens, with the Masked Email scope only.",
        "cloudflare" => "Make an API token in Cloudflare with only Email Routing Rules: Edit, for the zone your aliases are at.",
        _ => "Paste the API token from the service's settings.",
    };
    card.append(&label(&format!("{hint} Leave it empty to remove the saved one. It's kept in your desktop keyring."), "dim"));
    let entry = gtk::PasswordEntry::new();
    entry.set_show_peek_icon(true);
    card.append(&entry);
    let save = gtk::Button::with_label("Save");
    save.add_css_class("suggested-action");
    save.set_halign(gtk::Align::End);
    card.append(&save);
    let (d, u, id) = (dialog.clone(), ui.clone(), service.id.clone());
    let done = Rc::new(done);
    save.connect_clicked(move |_| {
        let token = entry.text().trim().to_string();
        entry.set_text("");
        let (d, u, id, done) = (d.clone(), u.clone(), id.clone(), done.clone());
        glib::spawn_future_local(async move {
            match client::call("SetForwarderToken", Some((id.as_str(), token.as_str()).to_variant())).await {
                Ok(_) => {
                    d.close();
                    done();
                }
                Err(e) => ui::toast(&u, &e.to_string()),
            }
        });
    });
    dialog.present();
}
