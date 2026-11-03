//! The settings card. Vault, clipboard and generator settings are read by the daemon
//! from the same file, within a second of a change.

use std::cell::Cell;
use std::rc::Rc;

use gtk::{glib, prelude::*};
use nyx_passwords_proto::Error as Code;
use nyx_ui::widgets as w;

use super::client;
use super::prefs;
use super::templates;
use super::theme;
use super::ui::{self, Ui, label};

fn group(body: &gtk::Box, name: &str) -> gtk::Box {
    let outer = w::vbox(0);
    outer.add_css_class("settings-group");
    outer.set_widget_name(name);
    outer.append(&label(&name.to_uppercase(), "group-title"));
    let rows = w::vbox(0);
    rows.add_css_class("group-list");
    outer.append(&rows);
    body.append(&outer);
    rows
}

/// A dropdown row over `choices` of (value, label), storing the value with `set`.
fn choice(
    rows: &gtk::Box,
    title: &str,
    desc: &str,
    choices: &[(u64, &str)],
    current: u64,
    set: impl Fn(&mut prefs::Prefs, u64) + 'static,
) {
    let opts: Vec<(String, String)> = choices.iter().map(|(v, l)| (v.to_string(), l.to_string())).collect();
    let values: Vec<u64> = choices.iter().map(|(v, _)| *v).collect();
    let current = if values.contains(&current) { current } else { values[0] };
    let (row, _) = w::choice_row(title, desc, opts, &current.to_string(), move |id| {
        if let Ok(v) = id.parse::<u64>() {
            prefs::update(|p| set(p, v));
        }
    });
    rows.append(&row);
}

fn switch(rows: &gtk::Box, title: &str, desc: &str, on: bool, set: impl Fn(&mut prefs::Prefs, bool) + 'static) {
    let (row, _) = w::switch_row(title, desc, on, move |v| prefs::update(|p| set(p, v)));
    rows.append(&row);
}

/// The username generator: what it makes, and each kind's settings (shown for the
/// chosen kind only). Alias service tokens go to the keyring through the daemon.
fn username_rows(ui: &Ui, g: &gtk::Box, r: &nyx_passwords_core::alias::UsernameRules) {
    use nyx_passwords_core::alias::{SERVICES, UsernameKind};
    let kinds = w::opts(&[
        ("word", "A random word"),
        ("plus", "Your email with a tag"),
        ("catch_all", "An address at your catch-all domain"),
        ("forwarded", "An alias from an email service"),
    ]);
    let current = match r.kind {
        UsernameKind::Word => "word",
        UsernameKind::Plus => "plus",
        UsernameKind::CatchAll => "catch_all",
        UsernameKind::Forwarded => "forwarded",
    };
    let entry_row = |title: &str, desc: &str, value: &str, set: fn(&mut prefs::Prefs, String)| {
        let e = gtk::Entry::new();
        e.set_text(value);
        e.set_width_chars(22);
        e.connect_changed(move |e| prefs::update(|p| set(p, e.text().trim().to_string())));
        w::row(title, desc, Some(e.upcast_ref()))
    };
    let email =
        entry_row("Your email address", "Tagged as you+tag@example.com.", &r.email, |p, x| p.vault.username_rules.email = x);
    let domain = entry_row("Catch-all domain", "A domain that takes mail for any name.", &r.domain, |p, x| {
        p.vault.username_rules.domain = x
    });
    let (by_site, _) = w::switch_row("Tag with the site's name", "github.com rather than random letters.", r.by_site, |on| {
        prefs::update(|p| p.vault.username_rules.by_site = on)
    });
    let services: Vec<(String, String)> = SERVICES.iter().map(|(id, name)| (id.to_string(), name.to_string())).collect();
    let (service, service_choice) = w::choice_row("Email alias service", "", services, &r.service, |id| {
        prefs::update(|p| p.vault.username_rules.service = id)
    });
    let token_state = label("", "dim");
    let set_token = gtk::Button::with_label("Set token…");
    let token_line = w::hbox(8);
    token_line.append(&token_state);
    token_line.append(&set_token);
    let token = w::row("API token", "Kept in your desktop keyring.", Some(token_line.upcast_ref()));
    let service_domain =
        entry_row("Alias domain", "For addy.io and Forward Email: the domain to make aliases at.", &r.service_domain, |p, x| {
            p.vault.username_rules.service_domain = x
        });
    let service_url = entry_row(
        "Your own server",
        "For a self-hosted SimpleLogin or addy.io; empty for the hosted one.",
        &r.service_url,
        |p, x| p.vault.username_rules.service_url = x,
    );
    let (word_number, _) = w::switch_row("Add a number", "To the random word.", r.number, |on| {
        prefs::update(|p| p.vault.username_rules.number = on)
    });
    let zone =
        entry_row("Cloudflare zone id", "For Cloudflare Email Routing: the zone of the alias domain.", &r.zone_id, |p, x| {
            p.vault.username_rules.zone_id = x
        });
    let forward_to = entry_row(
        "Forward to",
        "For Cloudflare Email Routing: a verified destination address the aliases forward to.",
        &r.forward_to,
        |p, x| p.vault.username_rules.forward_to = x,
    );
    let manage = {
        let u = ui.clone();
        w::button_row("Email aliases", "See your aliases, the logins that use them, and turn them off.", "Open…", move |_| {
            super::aliases::open(&u)
        })
        .0
    };
    // A Fastmail account in Nyx Online Accounts makes Fastmail the service to suggest.
    let suggestion = w::vbox(0);
    let rows: [(&gtk::Box, &[&str]); 12] = [
        (&word_number, &["word"]),
        (&email, &["plus"]),
        (&domain, &["catch_all"]),
        (&by_site, &["plus", "catch_all"]),
        (&service, &["forwarded"]),
        (&suggestion, &["forwarded"]),
        (&token, &["forwarded"]),
        (&service_domain, &["forwarded"]),
        (&service_url, &["forwarded"]),
        (&zone, &["forwarded"]),
        (&forward_to, &["forwarded"]),
        (&manage, &["forwarded"]),
    ];
    {
        let (suggestion, service_choice) = (suggestion.clone(), service_choice.clone());
        glib::spawn_future_local(async move {
            let Ok(services) = super::aliases::services().await else { return };
            let Some(fastmail) = services.into_iter().find(|s| s.preferred && !s.chosen) else { return };
            let account = fastmail.account.clone().unwrap_or_default();
            let (row, _) = w::button_row(
                "Fastmail is in Online Accounts",
                &glib::markup_escape_text(&format!(
                    "{account} is set up there. Its masked email needs its own API token, with only the Masked Email scope."
                )),
                "Use Fastmail",
                move |b| {
                    prefs::update(|p| p.vault.username_rules.service = "fastmail".into());
                    let at = SERVICES.iter().position(|(id, _)| *id == "fastmail").unwrap_or(0);
                    service_choice.set_selected(at as u32);
                    b.set_sensitive(false);
                },
            );
            suggestion.append(&row);
        });
    }
    let show_for = {
        let rows: Vec<(gtk::Box, Vec<&'static str>)> = rows.iter().map(|(r, k)| ((*r).clone(), k.to_vec())).collect();
        move |kind: &str| {
            for (row, kinds) in &rows {
                row.set_visible(kinds.contains(&kind));
            }
        }
    };
    let (kind_row, _) = w::choice_row("Generate usernames", "What the editor's username generator makes.", kinds, current, {
        let show_for = show_for.clone();
        move |id| {
            let kind = match id.as_str() {
                "plus" => UsernameKind::Plus,
                "catch_all" => UsernameKind::CatchAll,
                "forwarded" => UsernameKind::Forwarded,
                _ => UsernameKind::Word,
            };
            prefs::update(|p| p.vault.username_rules.kind = kind);
            show_for(&id);
        }
    });
    g.append(&kind_row);
    for (row, _) in rows {
        g.append(row);
    }
    show_for(current);

    // Whether the chosen service has a token: asked of the keyring through the daemon.
    let refresh_token_state = {
        let token_state = token_state.clone();
        move || {
            let token_state = token_state.clone();
            glib::spawn_future_local(async move {
                let service = prefs::get().vault.username_rules.service;
                let saved = super::client::text("ForwarderTokens", None)
                    .await
                    .ok()
                    .and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok())
                    .is_some_and(|v| v[&service] == true);
                token_state.set_text(if saved { "Saved" } else { "Not set" });
            });
        }
    };
    refresh_token_state();
    let r2 = refresh_token_state.clone();
    service_choice.connect_selected_notify(move |_| r2());
    let u = ui.clone();
    set_token.connect_clicked(move |_| {
        let (dialog, card) = w::dialog("Alias service token", 440);
        crate::dialog_dismissal::add(&dialog, &card, "Cancel");
        dialog.set_transient_for(Some(&u.window));
        card.append(&label("Paste the API token from the service's settings. Leave it empty to remove the saved one.", "dim"));
        let entry = gtk::PasswordEntry::new();
        entry.set_show_peek_icon(true);
        card.append(&entry);
        let save = gtk::Button::with_label("Save");
        save.add_css_class("suggested-action");
        save.set_halign(gtk::Align::End);
        card.append(&save);
        let (d, refresh, u) = (dialog.clone(), refresh_token_state.clone(), u.clone());
        save.connect_clicked(move |_| {
            let token = entry.text().trim().to_string();
            entry.set_text("");
            let (d, refresh, u) = (d.clone(), refresh.clone(), u.clone());
            glib::spawn_future_local(async move {
                let service = prefs::get().vault.username_rules.service;
                match super::client::call("SetForwarderToken", Some((service.as_str(), token.as_str()).to_variant())).await {
                    Ok(_) => {
                        d.close();
                        refresh();
                    }
                    Err(e) => ui::toast(&u, &e.to_string()),
                }
            });
        });
        dialog.present();
    });
}

/// Other Nyx apps' access: the grants in force, each revocable, and what other programs
/// (apps, Glimpse, the Assistant, ssh) did with the vault.
fn access_rows(ui: &Ui, g: &gtk::Box) {
    #[derive(serde::Deserialize)]
    struct Grant {
        app: String,
        search: bool,
        copy: bool,
        ask_each_copy: bool,
        expires: u64,
    }
    let (ui, g) = (ui.clone(), g.clone());
    glib::spawn_future_local(async move {
        ui::clear(&g);
        let list: Vec<Grant> = match client::text("Grants", None).await {
            Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
            Err(_) => return,
        };
        if list.is_empty() {
            g.append(&w::row("No app has access", "Nyx apps ask here before they can find or copy logins.", None));
        }
        for grant in list {
            let mut can = Vec::new();
            if grant.search {
                can.push("find logins");
            }
            if grant.copy {
                can.push(if grant.ask_each_copy { "copy, asking each time" } else { "copy" });
            }
            let until = glib::DateTime::from_unix_local(grant.expires as i64)
                .and_then(|d| d.format("%b %-d, %H:%M"))
                .map(|s| s.to_string())
                .unwrap_or_default();
            let revoke = gtk::Button::with_label("Revoke");
            revoke.add_css_class("destructive-action");
            revoke.set_valign(gtk::Align::Center);
            let (u, gg, app) = (ui.clone(), g.clone(), grant.app.clone());
            revoke.connect_clicked(move |_| {
                let (u, gg, app) = (u.clone(), gg.clone(), app.clone());
                glib::spawn_future_local(async move {
                    match client::call("RevokeGrant", Some((app.as_str(),).to_variant())).await {
                        Ok(_) => access_rows(&u, &gg),
                        Err(e) => ui::toast(&u, &e.to_string()),
                    }
                });
            });
            let desc = format!("May {} · until {until}", can.join(" and "));
            g.append(&w::row(&grant.app, &glib::markup_escape_text(&desc), Some(revoke.upcast_ref())));
        }
        let u = ui.clone();
        let (row, _) = w::button_row(
            "Activity",
            "What other programs did with the vault: copies, SSH signatures, requests. No values are kept.",
            "Show…",
            move |_| show_activity(&u),
        );
        g.append(&row);
    });
}

fn show_activity(ui: &Ui) {
    #[derive(serde::Deserialize)]
    struct Event {
        at: u64,
        who: String,
        what: String,
        item: Option<String>,
        outcome: String,
    }
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let list: Vec<Event> = match client::text("Activity", None).await {
            Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
            Err(e) => return ui::toast(&ui, &e.to_string()),
        };
        let (dialog, card) = w::dialog("Activity", 560);
        crate::dialog_dismissal::add(&dialog, &card, "Close");
        dialog.set_transient_for(Some(&ui.window));
        if list.is_empty() {
            card.append(&label("Nothing yet.", "dim"));
        }
        let rows = w::vbox(0);
        rows.add_css_class("group-list");
        let names: std::collections::HashMap<String, String> =
            ui.listing.borrow().entries.iter().map(|e| (e.id.clone(), e.name.clone())).collect();
        for e in list.iter().take(200) {
            let item = e.item.as_ref().map(|id| names.get(id).cloned().unwrap_or_else(|| "an item no longer here".into()));
            let title = match item {
                Some(name) => format!("{} · {}", e.what, name),
                None => e.what.clone(),
            };
            let desc = format!("{} · {} · {}", e.who, e.outcome, super::data::ago(e.at));
            rows.append(&w::row(&title, &glib::markup_escape_text(&desc), None));
        }
        let scroll = ui::scroll(&rows);
        scroll.set_min_content_height(320);
        card.append(&scroll);
        dialog.present();
    });
}

/// Travel Mode: whether it's on, and turning it on (after saying what it does and
/// doesn't do) or off (with the master password, then a sync).
fn travel_rows(ui: &Ui, g: &gtk::Box) {
    let (ui, g) = (ui.clone(), g.clone());
    glib::spawn_future_local(async move {
        ui::clear(&g);
        let Ok(json) = client::text("TravelMode", None).await else { return };
        let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
        let on = v["on"].as_bool().unwrap_or(false);
        let marked = v["marked"].as_u64().unwrap_or(0);
        let desc = if on {
            "On: items marked travel-sensitive aren't on this device. Turning it off needs your master password and the server."
                .to_string()
        } else {
            format!(
                "Off. {marked} item{} marked travel-sensitive (in the editor) would leave this device.",
                if marked == 1 { " is" } else { "s are" }
            )
        };
        let (row, button) = w::button_row("Travel Mode", &desc, if on { "Turn off…" } else { "Turn on…" }, |_| {});
        g.append(&row);
        let (u, gg) = (ui.clone(), g.clone());
        button.connect_clicked(move |_| {
            let (u, gg) = (u.clone(), gg.clone());
            if on {
                let (u2, gg2) = (u.clone(), gg.clone());
                super::account::confirm_for(
                    &u,
                    "Turning Travel Mode off brings the travel-sensitive items back from the server.",
                    move || {
                        let (u, gg) = (u2.clone(), gg2.clone());
                        glib::spawn_future_local(async move {
                            match client::call("SetTravelMode", Some((false,).to_variant())).await {
                                Ok(_) => {
                                    ui::toast(&u, "Travel Mode is off; the items are back.");
                                    ui::reload(&u);
                                    travel_rows(&u, &gg);
                                }
                                Err(e) => ui::toast(&u, &e.to_string()),
                            }
                        });
                    },
                );
                return;
            }
            glib::spawn_future_local(async move {
                let detail = format!(
                    "{marked} travel-sensitive item{} will be removed from this device now and kept off it until you \
                     turn Travel Mode off. They stay on your server and your other devices; nothing is deleted there.\n\n\
                     What it can't do: anyone with your master password and your server's address can bring them back, \
                     and a disk may keep old copies of removed data. Turning it off needs your master password and a \
                     connection to the server.",
                    if marked == 1 { "" } else { "s" }
                );
                if !ui::confirm(&u, "Turn on Travel Mode?", &detail, "Turn on").await {
                    return;
                }
                match client::call("SetTravelMode", Some((true,).to_variant())).await {
                    Ok(reply) => {
                        let gone = reply.get::<(u32,)>().map_or(0, |(n,)| n);
                        ui::toast(
                            &u,
                            &format!("Travel Mode is on: {gone} item{} left this device.", if gone == 1 { "" } else { "s" }),
                        );
                        ui::reload(&u);
                        travel_rows(&u, &gg);
                    }
                    Err(e) => ui::toast(&u, &e.to_string()),
                }
            });
        });
    });
}

/// The user's own templates: each with Edit and Delete, and a way to make one. Built-in
/// templates are listed by name only.
fn template_rows(ui: &Ui, g: &gtk::Box) {
    ui::clear(g);
    let builtin: Vec<String> = nyx_passwords_core::templates::builtin().into_iter().map(|t| t.name).collect();
    g.append(&w::row("Built-in templates", &glib::markup_escape_text(&builtin.join(", ")), None));
    let own = templates::custom();
    for (i, t) in own.iter().enumerate() {
        let actions = w::hbox(4);
        let edit = w::bar_button("document-edit-symbolic", "Edit this template");
        let delete = w::bar_button("user-trash-symbolic", "Delete this template");
        actions.append(&edit);
        actions.append(&delete);
        let fields = t.fields.iter().map(|f| f.label.as_str()).collect::<Vec<_>>().join(", ");
        let desc = format!("{} · {}", super::data::kind_name(&t.kind), if fields.is_empty() { "no fields" } else { &fields });
        g.append(&w::row(&t.name, &glib::markup_escape_text(&desc), Some(actions.upcast_ref())));
        let (u, gg, t2) = (ui.clone(), g.clone(), t.clone());
        edit.connect_clicked(move |_| edit_template(&u, &gg, Some(i), t2.clone()));
        let (u, gg, name) = (ui.clone(), g.clone(), t.name.clone());
        delete.connect_clicked(move |_| {
            let (u, gg, name) = (u.clone(), gg.clone(), name.clone());
            glib::spawn_future_local(async move {
                let ask = format!("Items made with “{name}” keep their fields and show them as custom fields.");
                if !ui::confirm(&u, "Delete this template?", &ask, "Delete").await {
                    return;
                }
                let mut own = templates::custom();
                if i < own.len() {
                    own.remove(i);
                }
                match templates::save(&own) {
                    Ok(()) => template_rows(&u, &gg),
                    Err(e) => ui::toast(&u, &e),
                }
            });
        });
    }
    let (row, _) = {
        let (u, gg) = (ui.clone(), g.clone());
        w::button_row(
            "New template",
            "Your own layout for an item: its kind and the fields it asks for. Kept on this computer; the fields themselves sync with the item.",
            "New…",
            move |_| {
                let blank =
                    templates::Template { id: String::new(), name: String::new(), kind: "note".into(), fields: Vec::new() };
                edit_template(&u, &gg, None, blank)
            },
        )
    };
    g.append(&row);
}

/// Makes or changes one of the user's templates (`at`: its place in the file).
fn edit_template(ui: &Ui, group: &gtk::Box, at: Option<usize>, t: templates::Template) {
    let (dialog, card) = w::dialog(if at.is_some() { "Edit template" } else { "New template" }, 520);
    crate::dialog_dismissal::add(&dialog, &card, "Cancel");
    dialog.set_transient_for(Some(&ui.window));
    let name = gtk::Entry::new();
    name.set_text(&t.name);
    name.set_placeholder_text(Some("Gym membership"));
    card.append(&label("Name", "account-field"));
    card.append(&name);
    let kinds: Vec<(String, String)> =
        nyx_passwords_core::templates::KINDS.iter().map(|k| (k.to_string(), super::data::kind_name(k).to_string())).collect();
    let kind = w::dropdown(&kinds, &t.kind);
    card.append(&label("Kind of item", "account-field"));
    card.append(&kind);
    card.append(&label("Fields", "account-field"));
    let list = w::vbox(6);
    card.append(&list);
    type Row = (gtk::Box, gtk::Entry, gtk::DropDown, Rc<std::cell::RefCell<Vec<String>>>);
    let rows: Rc<std::cell::RefCell<Vec<Row>>> = Rc::default();
    let kind_of = {
        let (kind, kinds) = (kind.clone(), kinds.clone());
        move || kinds.get(kind.selected() as usize).map_or("note".to_string(), |(k, _)| k.clone())
    };
    let add_row = {
        let (list, rows, kind_of) = (list.clone(), rows.clone(), kind_of.clone());
        Rc::new(move |label_text: &str, slot: &str| {
            let line = w::hbox(6);
            let entry = gtk::Entry::new();
            entry.set_text(label_text);
            entry.set_placeholder_text(Some("Label"));
            entry.set_hexpand(true);
            let choices = templates::slot_choices(&kind_of());
            let slots = Rc::new(std::cell::RefCell::new(choices.iter().map(|(s, _)| s.clone()).collect::<Vec<_>>()));
            let drop = w::dropdown(&choices, if slot.is_empty() { "text" } else { slot });
            let remove = w::bar_button("user-trash-symbolic", "Remove this field");
            line.append(&entry);
            line.append(&drop);
            line.append(&remove);
            list.append(&line);
            rows.borrow_mut().push((line.clone(), entry.clone(), drop, slots));
            let (list, rows) = (list.clone(), rows.clone());
            remove.connect_clicked(move |_| {
                list.remove(&line);
                rows.borrow_mut().retain(|(l, ..)| l != &line);
            });
            entry.grab_focus();
        })
    };
    for f in &t.fields {
        add_row(&f.label, &f.slot);
    }
    // The choices depend on the kind: a changed kind offers its own, keeping custom
    // fields' types where they still fit.
    {
        let (rows, kind_of) = (rows.clone(), kind_of.clone());
        kind.connect_selected_notify(move |_| {
            let choices = templates::slot_choices(&kind_of());
            for (_, _, drop, slots) in rows.borrow().iter() {
                let old = slots.borrow().get(drop.selected() as usize).cloned().unwrap_or_default();
                let list = gtk::StringList::new(&choices.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>());
                drop.set_model(Some(&list));
                *slots.borrow_mut() = choices.iter().map(|(s, _)| s.clone()).collect();
                drop.set_selected(slots.borrow().iter().position(|s| *s == old).unwrap_or(0) as u32);
            }
        });
    }
    let add = gtk::Button::with_label("Add field");
    add.set_halign(gtk::Align::Start);
    let a = add_row.clone();
    add.connect_clicked(move |_| a("", "text"));
    card.append(&add);
    let save = gtk::Button::with_label("Save");
    save.add_css_class("suggested-action");
    save.set_halign(gtk::Align::End);
    card.append(&save);
    let (u, g, d, id, name_entry) = (ui.clone(), group.clone(), dialog.clone(), t.id.clone(), name.clone());
    save.connect_clicked(move |_| {
        let name = name_entry.text().trim().to_string();
        let fields = rows
            .borrow()
            .iter()
            .map(|(_, entry, drop, slots)| templates::TemplateField {
                label: entry.text().trim().to_string(),
                slot: slots.borrow().get(drop.selected() as usize).cloned().unwrap_or_else(|| "text".into()),
                hint: String::new(),
            })
            .collect();
        let id = if id.is_empty() { nyx_passwords_core::templates::custom_id(&name) } else { id.clone() };
        let made = templates::Template { id, name, kind: kind_of(), fields };
        if let Some(problem) = made.problem() {
            return ui::toast(&u, &format!("This template can't be saved: {problem}."));
        }
        let mut own = templates::custom();
        let clash = own.iter().enumerate().any(|(i, t)| t.id == made.id && Some(i) != at);
        if clash {
            return ui::toast(&u, "You already have a template with that name.");
        }
        match at {
            Some(i) if i < own.len() => own[i] = made,
            _ => own.push(made),
        }
        match templates::save(&own) {
            Ok(()) => {
                d.close();
                template_rows(&u, &g);
            }
            Err(e) => ui::toast(&u, &e),
        }
    });
    dialog.present();
    name.grab_focus();
}

/// A quick-unlock switch. Not a preference: the daemon saves the vault's key (in the
/// desktop keyring, or sealed by Nyx Biometrics) or removes it, and the switch shows which
/// is the case.
fn unlock_switch(
    ui: &Ui,
    title: &str,
    desc: &str,
    methods: (&'static str, &'static str),
    done: (&'static str, &'static str),
) -> gtk::Box {
    let (get, set) = methods;
    let (row, sw) = w::switch_row(title, desc, false, |_| {});
    // Set while the switch is moved from here rather than by the user.
    let quiet = Rc::new(Cell::new(true));
    let (s, q) = (sw.clone(), quiet.clone());
    glib::spawn_future_local(async move {
        let on = client::call(get, None).await.ok().and_then(|v| v.get::<(bool,)>()).is_some_and(|(on,)| on);
        s.set_active(on);
        q.set(false);
    });
    let u = ui.clone();
    sw.connect_active_notify(move |s| {
        if quiet.get() {
            return;
        }
        let (ui, s, quiet, on) = (u.clone(), s.clone(), quiet.clone(), s.is_active());
        glib::spawn_future_local(async move {
            match client::call(set, Some((on,).to_variant())).await {
                Ok(_) => ui::toast(&ui, if on { done.0 } else { done.1 }),
                Err(e) => {
                    quiet.set(true);
                    s.set_active(!on);
                    quiet.set(false);
                    if e.is(Code::Reprompt) {
                        // Turning it on needs the master password: ask, then try again.
                        super::account::confirm(&ui, move || s.set_active(true));
                    } else {
                        ui::toast(&ui, &e.to_string());
                    }
                }
            }
        });
    });
    row
}

fn keyring_row(ui: &Ui) -> gtk::Box {
    unlock_switch(
        ui,
        "Unlock with the keyring",
        "Keep the vault's key in your desktop keyring, which opens when you log in, and unlock without the master password. \
         Anyone using your session, and any program running as you, can then open the vault too: leave it off on shared \
         or unattended computers.",
        ("KeyringUnlock", "SetKeyringUnlock"),
        ("The keyring can unlock the vault now.", "The key is gone from the keyring."),
    )
}

/// Shown when Nyx Biometrics' key service is installed.
fn face_row(ui: &Ui) -> Option<gtk::Box> {
    std::path::Path::new(nyx_auth_proto::keyd::SOCKET).exists().then(|| {
        unlock_switch(
            ui,
            "Unlock with your face",
            "Seal the vault's key with this computer's TPM. Unlocking then asks you to confirm it's you, with your face, \
             fingerprint, security key or password as Sign-in & Security is set up. The key never sits in your session, \
             and the master password always works too.",
            ("FaceUnlock", "SetFaceUnlock"),
            ("Your face can unlock the vault now.", "Unlocking with your face is off."),
        )
    })
}

pub fn open(ui: &Ui) {
    let p = prefs::get();
    let v = p.vault.clone();
    let body = w::vbox(0);
    body.add_css_class("settings-page");
    body.set_hexpand(true);
    let root = ui::scroll(&body);

    let g = group(&body, "Vault");
    let account = ui.listing.borrow().account.clone();
    if !account.email.is_empty() {
        g.append(&w::row(&account.email, &glib::markup_escape_text(&account.server), None));
    }
    choice(
        &g,
        "Lock after",
        "Lock the vault when it hasn't been used for this long.",
        &[
            (1, "1 minute"),
            (5, "5 minutes"),
            (15, "15 minutes"),
            (30, "30 minutes"),
            (60, "1 hour"),
            (240, "4 hours"),
            (0, "Never"),
        ],
        v.lock_minutes,
        |p, x| p.vault.lock_minutes = x,
    );
    switch(&g, "Lock when the screen locks", "Lock the vault as soon as the desktop locks.", v.lock_on_screen_lock, |p, x| {
        p.vault.lock_on_screen_lock = x
    });
    switch(&g, "Lock on sleep", "Lock the vault before the computer suspends.", v.lock_on_sleep, |p, x| {
        p.vault.lock_on_sleep = x
    });
    if let Some(face) = face_row(ui) {
        g.append(&face);
    }
    g.append(&keyring_row(ui));
    choice(
        &g,
        "Sync",
        "Fetch changes from the server while the vault is open.",
        &[
            (5, "Every 5 minutes"),
            (15, "Every 15 minutes"),
            (30, "Every 30 minutes"),
            (60, "Every hour"),
            (0, "Only when unlocking"),
        ],
        v.sync_minutes,
        |p, x| p.vault.sync_minutes = x,
    );
    switch(
        &g,
        "Live sync",
        "Hear from the server as soon as the vault changes on another device, and sync then.",
        v.live_sync,
        |p, x| p.vault.live_sync = x,
    );
    switch(
        &g,
        "Website icons",
        "Show each login's site icon. Your server fetches them from the sites, so it learns which sites you have logins for. They're kept in memory only, while the vault is open.",
        v.icons,
        |p, x| p.vault.icons = x,
    );
    let ca_desc = v
        .extra_ca
        .as_ref()
        .map(|c| glib::markup_escape_text(&c.display().to_string()).to_string())
        .unwrap_or_else(|| "For a server whose certificate comes from your own authority.".into());
    let (row, button) = w::button_row("Extra certificate", &ca_desc, "", |_| {});
    // One button: choose a file, or remove the one chosen.
    let shows = |b: &gtk::Button, chosen: bool| {
        b.set_icon_name(if chosen { "edit-delete-symbolic" } else { "document-open-symbolic" });
        b.set_tooltip_text(Some(if chosen { "Remove the certificate" } else { "Choose a certificate file…" }));
    };
    shows(&button, v.extra_ca.is_some());
    let u = ui.clone();
    button.connect_clicked(move |b| {
        if prefs::get().vault.extra_ca.is_some() {
            prefs::update(|p| p.vault.extra_ca = None);
            shows(b, false);
            return;
        }
        let dialog = gtk::FileDialog::builder().title("Certificate authority (PEM)").build();
        let b = b.clone();
        dialog.open(Some(&u.window), gtk::gio::Cancellable::NONE, move |file| {
            if let Some(path) = file.ok().and_then(|f| f.path()) {
                prefs::update(|p| p.vault.extra_ca = Some(path));
                shows(&b, true);
            }
        });
    });
    g.append(&row);

    if *ui.state.borrow() == nyx_passwords_proto::state::UNLOCKED {
        let g = group(&body, "Import and export");
        let u = ui.clone();
        let (row, _) = w::button_row(
            "Import",
            "From Bitwarden (JSON or CSV, with or without a password), 1Password (.1pux), Chrome, Firefox or KeePassXC (CSV).",
            "Import…",
            move |_| super::transfer::import(&u),
        );
        g.append(&row);
        let u = ui.clone();
        let (row, _) = w::button_row(
            "Import Wi-Fi networks",
            "The networks this computer has saved, with their passwords, as Wi-Fi network items.",
            "Import…",
            move |_| super::transfer::import_wifi(&u),
        );
        g.append(&row);
        let u = ui.clone();
        let (row, _) =
            w::button_row("Export", "Your items in Bitwarden's formats, for a backup or another app.", "Export…", move |_| {
                super::transfer::export(&u)
            });
        g.append(&row);

        let g = group(&body, "Emergency access");
        let u = ui.clone();
        let (row, _) = w::button_row(
            "Emergency access",
            "Trusted people who can ask to view your vault, and the vaults others trust you with.",
            "Open…",
            move |_| super::emergency::open(&u),
        );
        g.append(&row);
    }

    let g = group(&body, "Clipboard");
    choice(
        &g,
        "Clear copied values",
        "Empty the clipboard this long after copying, if it still holds the copy.",
        &[
            (10, "After 10 seconds"),
            (20, "After 20 seconds"),
            (30, "After 30 seconds"),
            (60, "After 1 minute"),
            (120, "After 2 minutes"),
            (0, "Never"),
        ],
        v.clipboard_seconds,
        |p, x| p.vault.clipboard_seconds = x,
    );
    switch(
        &g,
        "Paste once",
        "Clear the clipboard after the first paste. Some apps paste twice and get nothing.",
        v.paste_once,
        |p, x| p.vault.paste_once = x,
    );
    switch(&g, "Notify on copy", "Show a notification naming what was copied (never the value).", v.notify_copies, |p, x| {
        p.vault.notify_copies = x
    });
    g.append(&w::row(
        "Clipboard history",
        "Copies are marked as passwords. Clipboard managers that honor the mark keep them out of history; others may store them.",
        None,
    ));

    let g = group(&body, "Generator");
    let kinds = w::opts(&[("password", "Password"), ("passphrase", "Passphrase")]);
    let (row, _) = w::choice_row(
        "Generate",
        "What the editor and Glimpse's “pw generate” make.",
        kinds,
        if v.generate_passphrase { "passphrase" } else { "password" },
        |id| prefs::update(|p| p.vault.generate_passphrase = id == "passphrase"),
    );
    g.append(&row);
    let length = gtk::SpinButton::with_range(8.0, 128.0, 1.0);
    length.set_value(v.password_rules.length as f64);
    length.connect_value_changed(|s| prefs::update(|p| p.vault.password_rules.length = s.value() as usize));
    g.append(&w::row("Password length", "Characters in a generated password.", Some(length.upcast_ref())));
    for (title, which) in
        [("Uppercase letters", 0), ("Lowercase letters", 1), ("Digits", 2), ("Symbols", 3), ("Avoid look-alikes", 4)]
    {
        let r = &v.password_rules;
        let on = [r.uppercase, r.lowercase, r.digits, r.symbols, r.avoid_ambiguous][which];
        let desc = if which == 4 { "Leave out I, O, l, 0 and 1." } else { "" };
        switch(&g, title, desc, on, move |p, x| {
            let r = &mut p.vault.password_rules;
            match which {
                0 => r.uppercase = x,
                1 => r.lowercase = x,
                2 => r.digits = x,
                3 => r.symbols = x,
                _ => r.avoid_ambiguous = x,
            }
        });
    }
    let words = gtk::SpinButton::with_range(3.0, 20.0, 1.0);
    words.set_value(v.passphrase_rules.words as f64);
    words.connect_value_changed(|s| prefs::update(|p| p.vault.passphrase_rules.words = s.value() as usize));
    g.append(&w::row("Passphrase words", "Words in a generated passphrase.", Some(words.upcast_ref())));
    username_rows(ui, &g, &v.username_rules);

    let g = group(&body, "Templates");
    template_rows(ui, &g);

    let g = group(&body, "Integrations");
    switch(
        &g,
        "Glimpse",
        "Find logins with “pw” in Glimpse and copy from them. Passwords are never shown there.",
        v.glimpse,
        |p, x| p.vault.glimpse = x,
    );
    if std::path::Path::new(nyx_auth_proto::keyd::SOCKET).exists() {
        switch(
            &g,
            "Protected items in Glimpse",
            "Copy from items that ask for the master password again after confirming it's you, with your face, fingerprint, \
             security key or password as Sign-in & Security is set up. Off, they open only in Passwords.",
            v.glimpse_protected,
            |p, x| p.vault.glimpse_protected = x,
        );
    }
    switch(
        &g,
        "Nyx Assistant",
        "Let the Assistant find logins and copy them to the clipboard. It asks for a key press each time and never sees a password.",
        v.assistant,
        |p, x| p.vault.assistant = x,
    );

    if *ui.state.borrow() == nyx_passwords_proto::state::UNLOCKED {
        let g = group(&body, "Travel Mode");
        travel_rows(ui, &g);
        let g = group(&body, "App access");
        access_rows(ui, &g);
    }

    let g = group(&body, "SSH agent");
    switch(
        &g,
        "SSH agent",
        "Let ssh and git use the SSH keys you turn on for it (in each key's view). Each use asks you first, once or until the vault locks; the private key never leaves Passwords.",
        v.ssh_agent,
        |p, x| p.vault.ssh_agent = x,
    );
    let socket = nyx_passwords_proto::ssh_agent_socket_path().map(|p| p.display().to_string()).unwrap_or_default();
    let line = format!("SSH_AUTH_SOCK={socket}");
    let copy = w::bar_button("edit-copy-symbolic", "Copy");
    let (win, text) = (ui.window.clone(), line.clone());
    copy.connect_clicked(move |_| win.clipboard().set_text(&text));
    g.append(&w::row(
        &line,
        "Set this in your shell or ~/.config/environment.d/ to use the agent. Security-key (sk-) keys stay with ssh itself.",
        Some(copy.upcast_ref()),
    ));

    let g = group(&body, "Browsers");
    g.append(&w::row(
        "Browser extension",
        &glib::markup_escape_text(&format!(
            "Install it from {}: “Load unpacked” in Chromium and Brave; “Install Add-on From File” in Firefox and Zen. Then pair from its button.",
            nyx_core::paths::pretty(&nyx_core::paths::data_dir().join("browser"))
        )),
        None,
    ));
    switch(
        &g,
        "Fill logins as pages load",
        "Paired browsers fill a site's login when its page opens: only on https, only the login made for that exact site, only into empty fields, never one that asks for the master password. A login can opt out in the editor.",
        v.fill_on_load,
        |p, x| p.vault.fill_on_load = x,
    );
    switch(
        &g,
        "Passkeys in browsers",
        "Paired browsers may offer your vault's passkeys when a site asks and save new ones there. You confirm each in the extension's own window, and the extension's setting must be on too.",
        v.browser_passkeys,
        |p, x| p.vault.browser_passkeys = x,
    );
    super::pairing::fill_group(&g);

    let g = group(&body, "Passwords window");
    g.append(&w::start_row());
    let (row, dd) = w::choice_row(
        "Theme",
        "Choose a bundled or user theme.",
        theme::all().into_iter().map(|t| (t.id, t.name)).collect(),
        &p.theme,
        |id| {
            prefs::update(|p| {
                p.mode = prefs::ThemeMode::Theme;
                p.theme = id;
            });
            theme::apply();
        },
    );
    dd.set_sensitive(p.mode == prefs::ThemeMode::Theme || !theme::omarchy_available());
    if theme::omarchy_available() {
        let (r, _) = w::switch_row(
            "Follow Omarchy theme",
            "Match the desktop colors and update live.",
            p.mode == prefs::ThemeMode::Omarchy,
            move |on| {
                prefs::update(|p| p.mode = if on { prefs::ThemeMode::Omarchy } else { prefs::ThemeMode::Theme });
                dd.set_sensitive(!on);
                theme::apply();
            },
        );
        g.append(&r);
    }
    g.append(&row);
    let swatches = w::hbox(4);
    let repaint = {
        let s = swatches.clone();
        move || {
            ui::clear(&s);
            let p = theme::current_palette();
            for color in [&p.bg, &p.surface, &p.muted, &p.text, &p.accent, &p.danger] {
                let b = w::hbox(0);
                b.set_size_request(24, 24);
                b.add_css_class("swatch");
                w::paint(&b, color);
                s.append(&b);
            }
        }
    };
    repaint();
    let weak = swatches.downgrade();
    glib::timeout_add_seconds_local(1, move || {
        if weak.upgrade().is_none() {
            return glib::ControlFlow::Break;
        }
        repaint();
        glib::ControlFlow::Continue
    });
    g.append(&w::row("Current colors", "", Some(swatches.upcast_ref())));
    g.append(&nyx_ui::widgets::accent_row("passwords"));
    let (r, _) = w::switch_row("Reduce motion", "Turn off transitions and animations in this window.", p.reduce_motion, |on| {
        prefs::update(|p| p.reduce_motion = on);
        theme::apply();
    });
    g.append(&r);

    let g = group(&body, "Keyboard");
    for (keys, action) in ui::SHORTCUTS {
        g.append(&w::row(action, "", Some(w::key_caps(keys).upcast_ref())));
    }

    nyx_ui::settings_card::open_page(
        &ui.overlay,
        &ui.window,
        nyx_ui::settings_card::Spec {
            groups: &[
                ("Vault", "dialog-password-symbolic", "Locking, sync, server"),
                ("Import and export", "document-send-symbolic", "Bitwarden, 1Password, browsers, Wi-Fi"),
                ("Emergency access", "system-users-symbolic", "Trusted contacts"),
                ("Clipboard", "edit-paste-symbolic", "Clearing, notifications"),
                ("Generator", "media-playlist-shuffle-symbolic", "Passwords and passphrases"),
                ("Templates", "view-grid-symbolic", "Layouts for new items"),
                ("Integrations", "system-search-symbolic", "Glimpse, Nyx Assistant"),
                ("Travel Mode", "mark-location-symbolic", "Leave sensitive items behind"),
                ("App access", "system-users-symbolic", "Nyx apps, activity"),
                ("SSH agent", "utilities-terminal-symbolic", "Keys for ssh and git"),
                ("Browsers", "web-browser-symbolic", "Paired browsers, the extension"),
                ("Passwords window", "applications-graphics-symbolic", "Theme, accent, motion"),
                ("Keyboard", "input-keyboard-symbolic", "Shortcuts"),
            ],
            search_text: None,
        },
        root.upcast_ref(),
        &body,
    );
}
