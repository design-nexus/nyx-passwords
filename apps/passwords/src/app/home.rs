//! Home, where Passwords opens: how healthy the vault is, its problems by kind, the
//! logins used lately and the favourites with copy buttons, and the other tools.

use std::f64::consts::{FRAC_PI_2, TAU};

use gtk::prelude::*;
use nyx_ui::widgets as w;

use super::data::Entry;
use super::ui::{self, Ui};
use super::{aliases, detail, emergency, security, transfer};

/// The swatches monograms take, picked by the name so a site keeps its colour.
const MONOGRAM_SWATCHES: [&str; 8] = ["blue", "violet", "pink", "red", "coral", "amber", "green", "teal"];

/// The name's first letter on a square in a colour of its own.
pub fn monogram(name: &str, size: i32) -> gtk::Widget {
    let letter: String = name.chars().find(|c| c.is_alphanumeric()).map_or("•".into(), |c| c.to_uppercase().collect());
    let hash = name.to_lowercase().bytes().fold(2_166_136_261u32, |h, b| (h ^ u32::from(b)).wrapping_mul(16_777_619));
    let tile = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    tile.add_css_class("monogram");
    nyx_ui::sidebar::set_section(&tile, &format!("swatch-{}", MONOGRAM_SWATCHES[hash as usize % MONOGRAM_SWATCHES.len()]));
    tile.set_size_request(size, size);
    tile.set_valign(gtk::Align::Center);
    tile.set_halign(gtk::Align::Start);
    tile.set_hexpand(false);
    tile.set_vexpand(false);
    tile.set_homogeneous(true);
    let face = gtk::Label::new(Some(&letter));
    face.add_css_class("monogram-letter");
    face.set_halign(gtk::Align::Center);
    tile.append(&face);
    tile.upcast()
}

/// Builds Home again from the listing and the report.
pub fn build(ui: &Ui) {
    ui::clear(&ui.home);
    let narrow = ui.narrow.get();
    let entries = ui.listing.borrow().entries.clone();
    let summary = ui.security.borrow().summary(&entries);
    ui.home.append(&health(ui, &summary, narrow));
    ui.home.append(&tiles(ui, &summary, narrow));

    let live = |id: &String| entries.iter().find(|e| e.id == *id && !e.deleted).cloned();
    let shown = if narrow { 3 } else { 4 };
    let recent: Vec<Entry> = ui.recent.borrow().iter().filter_map(live).take(shown).collect();
    let mut favorites: Vec<Entry> = entries.iter().filter(|e| e.favorite && !e.deleted).cloned().collect();
    favorites.sort_by_key(|e| e.name.to_lowercase());
    favorites.truncate(shown);
    let columns = gtk::Grid::new();
    columns.set_column_homogeneous(true);
    columns.set_column_spacing(16);
    columns.set_row_spacing(20);
    columns.add_css_class("home-columns");
    columns.attach(
        &quick_list(
            ui,
            "Used lately",
            &recent,
            "Items you open or copy, here or in Glimpse and browsers, show up here.",
            "recent",
        ),
        0,
        0,
        1,
        1,
    );
    if !narrow {
        columns.attach(&quick_list(ui, "Favorites", &favorites, "Star an item to keep it here.", "favorites"), 1, 0, 1, 1);
    }
    ui.home.append(&columns);
    if !narrow {
        ui.home.append(&w::label("More in Passwords", "home-heading"));
        ui.home.append(&tools(ui, &entries));
    }
}

fn health(ui: &Ui, summary: &security::Summary, narrow: bool) -> gtk::Box {
    let card = w::hbox(if narrow { 16 } else { 22 });
    card.add_css_class("health-card");
    let score = summary.score();
    card.append(&ring(score, if narrow { 88 } else { 104 }));
    let text = w::vbox(4);
    text.set_valign(gtk::Align::Center);
    text.set_hexpand(true);
    let n = summary.risky_items;
    let title = match score {
        _ if summary.logins == 0 => "Nothing to check yet",
        80.. => "Your vault is in good shape",
        50.. => "Your vault could be safer",
        _ => "Your vault needs attention",
    };
    text.append(&w::label(title, "health-title"));
    let lead = match n {
        0 => "Nothing to fix.".to_string(),
        1 => "One login could be safer.".to_string(),
        n => format!("{n} logins could be safer."),
    };
    let about = ui::label(&format!("{lead} Everything is checked on this computer; nothing is sent anywhere."), "dim");
    about.set_max_width_chars(64);
    text.append(&about);
    let buttons = w::hbox(8);
    buttons.set_margin_top(10);
    let fix = gtk::Button::with_label("Fix the first one");
    fix.add_css_class("suggested-action");
    fix.set_sensitive(n > 0);
    let u = ui.clone();
    fix.connect_clicked(move |_| security::fix_first(&u));
    buttons.append(&fix);
    let breaches = w::labeled_button("security-high-symbolic", "Check for breaches…");
    breaches.set_tooltip_text(Some("Look up your passwords in Have I Been Pwned's breach data"));
    let u = ui.clone();
    breaches.connect_clicked(move |b| security::ask_and_check(&u, b));
    buttons.append(&breaches);
    text.append(&buttons);
    card.append(&text);
    card
}

/// The score in a ring that closes as it rises: green when it's good, amber, then red.
fn ring(score: u32, size: i32) -> gtk::Overlay {
    let area = gtk::DrawingArea::new();
    area.set_content_width(size);
    area.set_content_height(size);
    area.add_css_class("health-ring");
    area.add_css_class(match score {
        80.. => "good",
        50.. => "fair",
        _ => "poor",
    });
    let line = if size > 96 { 9.0 } else { 8.0 };
    area.set_draw_func(move |area, cr, width, height| {
        let color = area.color();
        let (r, g, b, a) = (f64::from(color.red()), f64::from(color.green()), f64::from(color.blue()), f64::from(color.alpha()));
        let (cx, cy) = (f64::from(width) / 2.0, f64::from(height) / 2.0);
        let radius = cx.min(cy) - line / 2.0 - 1.0;
        cr.set_line_width(line);
        cr.set_source_rgba(r, g, b, a * 0.16);
        cr.arc(cx, cy, radius, 0.0, TAU);
        let _ = cr.stroke();
        cr.set_source_rgba(r, g, b, a);
        cr.set_line_cap(gtk::cairo::LineCap::Round);
        cr.arc(cx, cy, radius, -FRAC_PI_2, -FRAC_PI_2 + TAU * f64::from(score.min(100)) / 100.0);
        let _ = cr.stroke();
    });
    let overlay = gtk::Overlay::new();
    overlay.set_child(Some(&area));
    overlay.set_valign(gtk::Align::Center);
    let number = w::label(&score.to_string(), "health-score");
    number.set_halign(gtk::Align::Center);
    number.set_valign(gtk::Align::Center);
    overlay.add_overlay(&number);
    overlay.update_property(&[gtk::accessible::Property::Label(&format!("Vault health {score} out of 100"))]);
    overlay
}

/// A problem tile: the Security page's group, icon, colour, count, title, description.
type Tile = (&'static str, &'static str, &'static str, Option<usize>, &'static str, &'static str);

/// A tool: icon, title, description, and what opens it.
type Tool = (&'static str, &'static str, String, fn(&Ui));

/// The four kinds of problem; each opens its group on the Security page. Two-step
/// login isn't known until it's checked, so its tile runs the check.
fn tiles(ui: &Ui, summary: &security::Summary, narrow: bool) -> gtk::Grid {
    let grid = gtk::Grid::new();
    grid.add_css_class("problem-tiles");
    grid.set_column_homogeneous(true);
    grid.set_column_spacing(10);
    grid.set_row_spacing(10);
    let tiles: [Tile; 4] = [
        ("weak", "dialog-warning-symbolic", "red", Some(summary.weak), "Weak passwords", "Easy to guess"),
        ("reused", "edit-copy-symbolic", "amber", Some(summary.reused), "Used more than once", "One leak opens several sites"),
        ("old", "document-open-recent-symbolic", "teal", Some(summary.old), "Over a year old", "Worth changing now and then"),
        (
            "no-code",
            "security-high-symbolic",
            "violet",
            summary.no_code,
            "Two-step login is off",
            if summary.no_code.is_some() { "On sites that offer it" } else { "Check which of your sites offer it" },
        ),
    ];
    let columns = if narrow { 2 } else { 4 };
    for (i, (group, icon, colour, count, title, desc)) in tiles.into_iter().enumerate() {
        let tile = gtk::Button::new();
        tile.add_css_class("problem-tile");
        nyx_ui::sidebar::set_section(&tile, &format!("swatch-{colour}"));
        let face = w::vbox(0);
        face.set_halign(gtk::Align::Fill);
        face.set_valign(gtk::Align::Start);
        let top = w::hbox(0);
        let disc = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        disc.add_css_class("tile-disc");
        disc.set_valign(gtk::Align::Start);
        disc.set_halign(gtk::Align::Start);
        let image = gtk::Image::from_icon_name(icon);
        image.set_halign(gtk::Align::Center);
        image.set_valign(gtk::Align::Center);
        image.set_size_request(26, 26);
        disc.append(&image);
        top.append(&disc);
        let number = w::label(&count.map_or(String::new(), |n| n.to_string()), "tile-count");
        number.set_hexpand(true);
        number.set_xalign(1.0);
        number.set_valign(gtk::Align::Start);
        top.append(&number);
        face.append(&top);
        let name = w::label(title, "tile-title");
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        face.append(&name);
        let about = w::label(desc, "tile-desc");
        about.set_wrap(true);
        face.append(&about);
        tile.set_child(Some(&face));
        let u = ui.clone();
        if count.is_some() {
            tile.set_tooltip_text(Some(&format!("{title}: show them on the Security page")));
            tile.connect_clicked(move |_| {
                ui::navigate(&u, "security");
                security::scroll_to(&u, group);
            });
        } else {
            tile.set_tooltip_text(Some("Check which of your sites offer two-step login"));
            tile.connect_clicked(move |b| security::ask_and_check_codes(&u, b));
        }
        grid.attach(&tile, (i % columns) as i32, (i / columns) as i32, 1, 1);
    }
    grid
}

/// A heading with "Show all" and up to four items, each with copy buttons.
fn quick_list(ui: &Ui, title: &str, entries: &[Entry], empty: &str, section: &'static str) -> gtk::Box {
    let column = w::vbox(8);
    let head = w::hbox(8);
    let heading = w::label(title, "home-heading");
    heading.set_hexpand(true);
    head.append(&heading);
    if !entries.is_empty() {
        let all = gtk::Button::with_label("Show all");
        all.add_css_class("flat");
        all.add_css_class("home-more");
        all.set_tooltip_text(Some(&format!("{title}: every one, in the list")));
        let u = ui.clone();
        all.connect_clicked(move |_| ui::navigate(&u, section));
        head.append(&all);
    }
    column.append(&head);
    let card = w::vbox(0);
    card.add_css_class("group-list");
    card.add_css_class("quick-list");
    if entries.is_empty() {
        let note = ui::label(empty, "dim");
        note.add_css_class("quick-empty");
        card.append(&note);
    }
    for e in entries {
        card.append(&quick_row(ui, e));
    }
    column.append(&card);
    column
}

fn quick_row(ui: &Ui, e: &Entry) -> gtk::Box {
    let row = w::hbox(4);
    row.add_css_class("quick-row");
    let open = gtk::Button::new();
    open.add_css_class("flat");
    open.add_css_class("quick-open");
    open.set_hexpand(true);
    open.set_tooltip_text(Some("Show this item"));
    let face = w::hbox(10);
    face.set_halign(gtk::Align::Fill);
    face.append(&monogram(&e.name, 28));
    let text = w::vbox(1);
    text.set_hexpand(true);
    text.set_valign(gtk::Align::Center);
    let name = w::label(&e.name, "quick-name");
    name.set_ellipsize(gtk::pango::EllipsizeMode::End);
    text.append(&name);
    let sub = w::label(&e.subtitle(), "quick-sub");
    sub.set_ellipsize(gtk::pango::EllipsizeMode::End);
    text.append(&sub);
    face.append(&text);
    open.set_child(Some(&face));
    let (u, id) = (ui.clone(), e.id.clone());
    open.connect_clicked(move |_| ui::show_item(&u, &id));
    row.append(&open);
    if e.kind == "login" {
        let user = w::icon_button("avatar-default-symbolic", "Copy username");
        user.set_sensitive(e.username.as_deref().is_some_and(|u| !u.is_empty()));
        let (u, id) = (ui.clone(), e.id.clone());
        user.connect_clicked(move |_| detail::copy(&u, &id, "username"));
        row.append(&user);
        let password = w::icon_button("edit-copy-symbolic", "Copy password");
        password.set_sensitive(e.has_password && e.view_password);
        let (u, id) = (ui.clone(), e.id.clone());
        password.connect_clicked(move |_| detail::copy(&u, &id, "password"));
        row.append(&password);
    }
    row
}

fn tools(ui: &Ui, entries: &[Entry]) -> gtk::Grid {
    let grid = gtk::Grid::new();
    grid.add_css_class("home-tools");
    grid.set_column_homogeneous(true);
    grid.set_column_spacing(10);
    let aliased = entries.iter().filter(|e| e.alias.is_some() && !e.deleted).count();
    let aliases_about = match aliased {
        0 => "Addresses made for sign-ups".to_string(),
        n => format!("{n} in use, made for sign-ups"),
    };
    let tools: [Tool; 4] = [
        ("mail-send-symbolic", "Email aliases", aliases_about, aliases::open),
        ("system-users-symbolic", "Emergency access", "People you trust".into(), emergency::open),
        ("nyx-import-symbolic", "Import", "From Bitwarden or another app".into(), transfer::import),
        ("nyx-export-symbolic", "Export", "A backup, with a password".into(), transfer::export),
    ];
    for (i, (icon, title, about, open)) in tools.into_iter().enumerate() {
        let tool = gtk::Button::new();
        tool.add_css_class("tool-card");
        tool.set_tooltip_text(Some(title));
        let face = w::hbox(10);
        face.set_halign(gtk::Align::Fill);
        let image = gtk::Image::from_icon_name(icon);
        image.set_valign(gtk::Align::Start);
        face.append(&image);
        let text = w::vbox(1);
        text.set_hexpand(true);
        let name = w::label(title, "tool-title");
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        text.append(&name);
        let sub = w::label(&about, "tool-desc");
        sub.set_wrap(true);
        text.append(&sub);
        face.append(&text);
        tool.set_child(Some(&face));
        let u = ui.clone();
        tool.connect_clicked(move |_| open(&u));
        grid.attach(&tool, i as i32, 0, 1, 1);
    }
    grid
}
