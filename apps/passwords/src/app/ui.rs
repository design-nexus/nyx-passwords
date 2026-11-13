//! The window: the shared header, then the sidebar and Home, the Security page or the
//! item list and details while the vault is open; the sign-in or unlock page otherwise
//! (Nyx Design 2.0, STYLE.md).

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use gtk::{gdk, glib, prelude::*};
use nyx_passwords_proto::state;
use nyx_ui::{chrome, widgets as w};

use super::data::{self, Listing};
use super::{account, client, detail, editor, home, prefs, security, settings, theme};

pub type Ui = Rc<State>;

pub struct State {
    pub window: gtk::ApplicationWindow,
    pub overlay: gtk::Overlay,
    nav: gtk::Box,
    header: chrome::AppHeader,
    collapse: gtk::Button,
    new_button: gtk::Button,
    sidebar: gtk::Box,
    /// "account" (sign in, unlock), "home", "security" or "vault" (the list and details).
    pages: gtk::Stack,
    pub account: gtk::Box,
    pub home: gtk::Box,
    /// Whether Home was last built for a narrow window.
    home_narrow: Cell<Option<bool>>,
    pub security_list: gtk::Box,
    pub security_scroll: gtk::ScrolledWindow,
    pub list: gtk::ListBox,
    list_scroll: gtk::ScrolledWindow,
    /// The line between the list and the details, while both show.
    pane_line: gtk::Separator,
    pub details: gtk::Box,
    detail_scroll: gtk::ScrolledWindow,
    pub search: gtk::SearchEntry,
    lock_button: gtk::Button,
    sync_button: gtk::Button,
    toast_box: gtk::Box,
    toast_serial: Cell<u64>,
    /// The daemon's state: logged_out, locked, unlocked; "" before the first answer.
    pub state: RefCell<String>,
    pub listing: RefCell<Listing>,
    /// The recently used items' ids, newest first (the daemon's `Recent`).
    pub recent: RefCell<Vec<String>>,
    /// An item to show once the listing arrives (`--item`).
    pending_item: RefCell<Option<String>>,
    pub section: RefCell<String>,
    pub selected: RefCell<Option<String>>,
    /// The items picked together (Ctrl- or Shift-click), when more than one is.
    pub multi: RefCell<Vec<String>>,
    pub narrow: Cell<bool>,
    pub showing_detail: Cell<bool>,
    rebuilding: Cell<bool>,
    pub editor: RefCell<Option<editor::Sheet>>,
    /// Bumped whenever details are rebuilt, so timers from older ones stop.
    pub detail_serial: Cell<u64>,
    /// The security report (`security.rs`).
    pub security: RefCell<security::Report>,
    /// The Trash section's "Empty the trash".
    trash_bar: gtk::Box,
    /// The daemon's `Revision` when the listing was last fetched.
    revision: Cell<u64>,
    /// "Restart to finish updating", when the daemon is an older build than the window.
    update_bar: gtk::Box,
}

thread_local! { static UI: RefCell<Option<Ui>> = const { RefCell::new(None) }; }

pub fn current() -> Option<Ui> {
    UI.with(|u| u.borrow().clone())
}

pub fn present(app: &gtk::Application, section: Option<&str>) -> Ui {
    if let Some(ui) = current() {
        if let Some(s) = section {
            navigate(&ui, s);
        }
        ui.window.present();
        return ui;
    }
    theme::install();
    install_icons();
    let window = gtk::ApplicationWindow::builder().application(app).default_width(1120).default_height(800).build();
    window.add_css_class("passwords-window");
    window.set_icon_name(Some("io.github.design_nexus.nyx.Passwords"));
    window.set_titlebar(Some(&w::hbox(0)));
    chrome::set_title(&window, "Passwords", "");

    // The app and the section, the sidebar toggle; search in the middle; sync, lock, New
    // item and Settings at the end.
    let header = chrome::app_header(&window, "nyx-key-symbolic", "Passwords");
    let collapse = w::bar_button("sidebar-show-symbolic", "Collapse the sidebar (Ctrl+B)");
    header.start.append(&collapse);
    let search = gtk::SearchEntry::new();
    search.set_placeholder_text(Some("Search the vault"));
    search.update_property(&[gtk::accessible::Property::Label("Search the vault")]);
    search.add_css_class("bar-search");
    // A small minimum keeps the header narrow enough for a half-screen tile.
    search.set_width_chars(8);
    search.set_max_width_chars(SEARCH_WIDE);
    let search_box = gtk::Overlay::new();
    search_box.set_child(Some(&search));
    let hint = w::label("Ctrl F", "key-hint");
    hint.set_halign(gtk::Align::End);
    hint.set_valign(gtk::Align::Center);
    hint.set_margin_end(10);
    hint.set_can_target(false);
    search_box.add_overlay(&hint);
    search.connect_changed(move |s| hint.set_visible(s.text().is_empty()));
    header.center.append(&search_box);
    header.end.set_spacing(4);
    let sync_button = w::bar_button("view-refresh-symbolic", "Sync now (F5)");
    sync_button.connect_clicked(|_| {
        if let Some(ui) = current() {
            sync(&ui);
        }
    });
    sync_button.set_visible(false);
    let trash_bar = w::hbox(0);
    let empty_trash = w::bar_button("user-trash-full-symbolic", "Empty the trash: delete everything in it for good");
    empty_trash.connect_clicked(|_| {
        if let Some(ui) = current() {
            detail::empty_trash(&ui);
        }
    });
    trash_bar.append(&empty_trash);
    header.end.append(&trash_bar);
    header.end.append(&sync_button);
    let lock_button = w::bar_button("system-lock-screen-symbolic", "Lock the vault (Ctrl+L)");
    lock_button.connect_clicked(|_| {
        if let Some(ui) = current() {
            lock(&ui);
        }
    });
    lock_button.set_visible(false);
    header.end.append(&lock_button);
    let new = gtk::Button::new();
    new.add_css_class("new-button");
    new.set_tooltip_text(Some("New item (Ctrl+N)"));
    let face = w::hbox(6);
    face.append(&gtk::Image::from_icon_name("list-add-symbolic"));
    face.append(&gtk::Label::new(Some("New item")));
    face.append(&w::label("Ctrl N", "key-hint"));
    new.set_child(Some(&face));
    new.set_valign(gtk::Align::Center);
    new.set_visible(false);
    header.end.append(&new);
    header.end.append(&chrome::settings_button(open_settings));

    let sidebar = w::vbox(0);
    sidebar.set_hexpand(false); // Required: expanding labels must not expand the sidebar.
    sidebar.add_css_class("settings-navigation");
    let nav = w::vbox(0);
    nav.set_hexpand(false);
    let nav_scroll = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(false)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .child(&nav)
        .build();
    sidebar.append(&nav_scroll);

    let content = w::vbox(0);
    content.add_css_class("settings-content");
    content.set_hexpand(true); // Only the page column receives spare horizontal space.
    let frame = nyx_ui::frame::AppFrame::new(&header.root);
    frame.set_sidebar(&sidebar);
    frame.set_page(&content);
    let overlay = frame.install(&window);
    let update_bar = w::vbox(0);
    update_bar.set_visible(false);
    content.append(&update_bar);
    let pages = gtk::Stack::new();
    pages.set_transition_type(gtk::StackTransitionType::Crossfade);
    pages.set_transition_duration(160);
    pages.set_vexpand(true);
    content.append(&pages);

    let account = w::vbox(0);
    account.set_vexpand(true);
    pages.add_named(&scroll(&account), Some("account"));

    let vault = w::vbox(0);
    let panes = w::hbox(0);
    panes.set_vexpand(true);
    vault.append(&panes);
    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::Multiple);
    // With single-click activation, a plain click adds its row to the selection instead
    // of replacing it, and never unselects one; Ctrl and Shift only work without it.
    list.set_activate_on_single_click(false);
    list.add_css_class("item-list");
    let list_scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .vexpand(true)
        .child(&list)
        .build();
    list_scroll.set_width_request(300);
    panes.append(&list_scroll);
    let pane_line = nyx_ui::frame::pane_line(gtk::Orientation::Vertical);
    panes.append(&pane_line);
    let details = w::vbox(12);
    details.add_css_class("item-details");
    let detail_scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .hexpand(true)
        .vexpand(true)
        .child(&nyx_ui::clamp::Clamp::new(&details, 920))
        .build();
    detail_scroll.add_css_class("item-detail-pane");
    panes.append(&detail_scroll);
    pages.add_named(&vault, Some("vault"));

    let home = w::vbox(0);
    home.add_css_class("home-page");
    pages.add_named(&scroll(&nyx_ui::clamp::Clamp::new(&home, 900)), Some("home"));

    let security_page = security::bar();
    let security_list = w::vbox(0);
    security_list.add_css_class("security-list");
    let security_scroll = scroll(&nyx_ui::clamp::Clamp::new(&security_list, 820));
    security_page.append(&security_scroll);
    pages.add_named(&security_page, Some("security"));

    let toast_box = w::hbox(10);
    toast_box.add_css_class("toast");
    toast_box.set_halign(gtk::Align::Center);
    toast_box.set_valign(gtk::Align::End);
    toast_box.set_margin_bottom(48);
    toast_box.set_visible(false);
    overlay.add_overlay(&toast_box);

    let start = section.map(str::to_string).unwrap_or_else(|| nyx_theme::start_page("home", &prefs::get().last_section));
    let ui = Rc::new(State {
        window,
        overlay,
        nav,
        header,
        collapse: collapse.clone(),
        new_button: new.clone(),
        sidebar,
        pages,
        account,
        home,
        home_narrow: Cell::new(None),
        security_list,
        security_scroll,
        list,
        list_scroll,
        pane_line,
        details,
        detail_scroll,
        search,
        lock_button,
        sync_button,
        toast_box,
        toast_serial: Cell::new(0),
        update_bar,
        state: RefCell::new(String::new()),
        listing: RefCell::new(Listing::default()),
        recent: RefCell::new(Vec::new()),
        pending_item: RefCell::new(None),
        section: RefCell::new(start),
        selected: RefCell::new(None),
        multi: RefCell::new(Vec::new()),
        narrow: Cell::new(false),
        showing_detail: Cell::new(false),
        rebuilding: Cell::new(false),
        editor: RefCell::new(None),
        detail_serial: Cell::new(0),
        security: RefCell::new(security::Report::default()),
        trash_bar,
        revision: Cell::new(0),
    });
    UI.with(|u| *u.borrow_mut() = Some(ui.clone()));

    let u = ui.clone();
    new.connect_clicked(move |_| editor::open(&u, None));
    let u = ui.clone();
    collapse.connect_clicked(move |_| {
        prefs::update(|p| p.sidebar_collapsed = !p.sidebar_collapsed);
        layout(&u);
    });
    let u = ui.clone();
    ui.search.connect_search_changed(move |s| {
        // Home and Security have no list: a search shows its matches in All items.
        if !s.text().is_empty() && matches!(u.section.borrow().as_str(), "home" | "security") {
            navigate(&u, "all");
        }
        refresh_list(&u);
    });
    // Enter opens the first match; Down moves into the list.
    let u = ui.clone();
    ui.search.connect_activate(move |_| {
        if let Some(row) = u.list.row_at_index(0).filter(|r| r.is_selectable()) {
            u.list.unselect_all();
            u.list.select_row(Some(&row));
            u.showing_detail.set(true);
            layout(&u);
        }
    });
    let keys = gtk::EventControllerKey::new();
    let u = ui.clone();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Down
            && let Some(row) = u.list.row_at_index(0)
        {
            row.grab_focus();
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    ui.search.add_controller(keys);
    let u = ui.clone();
    ui.list.connect_selected_rows_changed(move |list| {
        if u.rebuilding.get() {
            return;
        }
        let picked: Vec<String> = list.selected_rows().iter().map(|r| r.widget_name().to_string()).collect();
        if picked.len() > 1 {
            *u.selected.borrow_mut() = None;
            *u.multi.borrow_mut() = picked;
        } else {
            *u.selected.borrow_mut() = picked.into_iter().next();
            u.multi.borrow_mut().clear();
            if let Some(id) = u.selected.borrow().clone() {
                opened(&u, id);
            }
        }
        u.showing_detail.set(u.selected.borrow().is_some() || !u.multi.borrow().is_empty());
        detail::show(&u);
        layout(&u);
    });
    let u = ui.clone();
    let last_width = Cell::new(0);
    ui.window.add_tick_callback(move |win, _| {
        if last_width.replace(win.width()) != win.width() {
            layout(&u);
        }
        glib::ControlFlow::Continue
    });
    nyx_ui::keys::install(
        &ui.window,
        nyx_ui::keys::Common {
            settings: Some(open_settings),
            shortcuts: Some(show_shortcuts),
            close: true,
            ..Default::default()
        },
    );
    let keys = gtk::EventControllerKey::new();
    let u = ui.clone();
    keys.connect_key_pressed(move |_, key, _, mods| {
        // The editor's own keys (Ctrl+S, Esc) only while it's open.
        if u.editor.borrow().is_some() {
            return glib::Propagation::Proceed;
        }
        let ctrl = mods.contains(gdk::ModifierType::CONTROL_MASK);
        let shift = mods.contains(gdk::ModifierType::SHIFT_MASK);
        let open = *u.state.borrow() == state::UNLOCKED;
        match key {
            gdk::Key::f | gdk::Key::F if ctrl && open => find(&u),
            gdk::Key::n | gdk::Key::N if ctrl && open => editor::open(&u, None),
            gdk::Key::l | gdk::Key::L if ctrl && open => lock(&u),
            gdk::Key::F5 if open => sync(&u),
            gdk::Key::b | gdk::Key::B if ctrl => {
                prefs::update(|p| p.sidebar_collapsed = !p.sidebar_collapsed);
                layout(&u);
            }
            gdk::Key::c | gdk::Key::C if ctrl && shift && open => detail::copy_selected(&u, "password"),
            gdk::Key::u | gdk::Key::U if ctrl && shift && open => detail::copy_selected(&u, "username"),
            gdk::Key::o | gdk::Key::O if ctrl && shift && open => detail::copy_selected(&u, "totp"),
            gdk::Key::F1 => show_shortcuts(),
            gdk::Key::Escape => {
                if nyx_ui::settings_card::is_open() {
                    nyx_ui::settings_card::escape();
                } else if !u.search.text().is_empty() {
                    u.search.set_text("");
                    u.search.grab_focus();
                } else {
                    u.showing_detail.set(false);
                    layout(&u);
                }
            }
            _ => return glib::Propagation::Proceed,
        }
        glib::Propagation::Stop
    });
    ui.window.add_controller(keys);
    refresh_state(&ui);
    watch_state(&ui);
    ui.window.present();
    if prefs::take_broken() {
        toast(&ui, "Settings couldn't be read. The original is kept as settings.toml.bak.");
    }
    #[cfg(debug_assertions)]
    super::fixture::maybe(&ui);
    ui
}

/// Asks the daemon for its state and shows the matching page.
pub fn refresh_state(ui: &Ui) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        match client::status().await {
            Ok((st, _, _)) => set_state(&ui, &st),
            Err(e) => {
                set_state(&ui, "");
                account::unavailable(&ui, &e.to_string());
            }
        }
    });
}

/// Follows lock changes made elsewhere (the idle timer, `pw lock`, the screen locking).
fn watch_state(ui: &Ui) {
    let weak = Rc::downgrade(ui);
    glib::timeout_add_seconds_local(2, move || {
        let Some(ui) = weak.upgrade() else { return glib::ControlFlow::Break };
        if ui.window.is_visible() {
            glib::spawn_future_local(async move {
                if let Ok((st, _, _)) = client::status().await
                    && st != *ui.state.borrow()
                {
                    set_state(&ui, &st);
                }
                // A browser asking to pair shows here, while the vault is open.
                if *ui.state.borrow() == state::UNLOCKED {
                    super::pairing::check(&ui);
                    super::account::check_sign_in_requests(&ui);
                    // A sync brought changes from elsewhere: list again (not under the editor).
                    if let Ok(v) = client::call("Revision", None).await
                        && let Some((revision,)) = v.get::<(u64,)>()
                        && ui.revision.get() != revision
                        && ui.editor.borrow().is_none()
                    {
                        ui.revision.set(revision);
                        reload(&ui);
                    }
                    if !ui.update_bar.is_visible() {
                        let outdated = match client::call("Outdated", None).await {
                            Ok(v) => v.get::<(bool,)>().is_some_and(|(o,)| o),
                            Err(e) => e.unknown_method,
                        };
                        if outdated {
                            show_update_bar(&ui);
                        }
                    }
                }
            });
        }
        glib::ControlFlow::Continue
    });
}

/// Passwords was updated while the vault was open; restarting its daemon locks it.
fn show_update_bar(ui: &Ui) {
    clear(&ui.update_bar);
    let bar = w::banner("Passwords was updated. Restart it to finish; the vault locks.", false);
    let restart = gtk::Button::with_label("Restart");
    restart.set_valign(gtk::Align::Center);
    let u = ui.clone();
    restart.connect_clicked(move |_| {
        u.update_bar.set_visible(false);
        let u = u.clone();
        glib::spawn_future_local(async move {
            // A daemon from before `Restart` existed is restarted through its unit.
            if client::call("Restart", None).await.is_err_and(|e| e.unknown_method) {
                let _ = std::process::Command::new("systemctl")
                    .args(["--user", "restart", nyx_passwords_proto::SERVICE])
                    .stdin(std::process::Stdio::null())
                    .spawn();
            }
            glib::timeout_future(Duration::from_millis(1000)).await;
            refresh_state(&u);
        });
    });
    bar.append(&restart);
    ui.update_bar.append(&bar);
    ui.update_bar.set_visible(true);
}

pub fn set_state(ui: &Ui, st: &str) {
    let changed = *ui.state.borrow() != st;
    *ui.state.borrow_mut() = st.to_string();
    let open = st == state::UNLOCKED;
    // Nothing to navigate or search until the vault is open.
    ui.sidebar.set_visible(open);
    ui.collapse.set_visible(open);
    ui.search.set_visible(open);
    ui.lock_button.set_visible(open);
    ui.sync_button.set_visible(open);
    ui.new_button.set_visible(open);
    if open {
        show_view(ui);
        reload(ui);
        ui.search.grab_focus();
    } else {
        // Nothing of the vault stays in the window once it's locked.
        *ui.listing.borrow_mut() = Listing::default();
        ui.recent.borrow_mut().clear();
        super::icons::forget();
        *ui.security.borrow_mut() = security::Report::default();
        *ui.selected.borrow_mut() = None;
        ui.multi.borrow_mut().clear();
        clear(&ui.details);
        clear(&ui.list);
        clear(&ui.home);
        clear(&ui.security_list);
        let editor = ui.editor.borrow_mut().take();
        if let Some(e) = editor {
            e.close();
        }
        ui.search.set_text("");
        ui.pages.set_visible_child_name("account");
        if changed || st.is_empty() {
            account::show(ui, st);
        }
        // The subtitle says locked or signed out.
        ui.home_narrow.set(None);
        set_subtitle(ui, if st == state::LOCKED { "Locked" } else { "Sign in" });
    }
    nav(ui);
    layout(ui);
}

/// Several items picked together in All items, as if Ctrl-clicked.
pub fn show_several(ui: &Ui, ids: Vec<String>) {
    navigate(ui, "all");
    ui.search.set_text("");
    *ui.selected.borrow_mut() = None;
    *ui.multi.borrow_mut() = ids;
    ui.showing_detail.set(true);
    refresh_list(ui);
    detail::show(ui);
}

/// Shows one item from Home or the Security page: All items, with it selected.
pub fn show_item(ui: &Ui, id: &str) {
    navigate(ui, "all");
    *ui.selected.borrow_mut() = Some(id.to_string());
    ui.multi.borrow_mut().clear();
    ui.showing_detail.set(true);
    refresh_list(ui);
    opened(ui, id.to_string());
    detail::show(ui);
    layout(ui);
    let ui = ui.clone();
    glib::timeout_add_local_once(Duration::from_millis(80), move || {
        if let Some(row) = ui.list.selected_rows().first()
            && let Some(p) = row.compute_point(&ui.list, &gtk::graphene::Point::new(0.0, 0.0))
        {
            ui.list_scroll.vadjustment().set_value(f64::from(p.y()) - 48.0);
        }
    });
}

/// Shows one item (`--item ID`, from the Assistant): all items, with it selected. While
/// the vault is locked the selection waits for the unlock's listing.
pub fn open_item(ui: &Ui, id: &str) {
    if id.parse::<uuid::Uuid>().is_err() {
        return;
    }
    navigate(ui, "all");
    *ui.pending_item.borrow_mut() = Some(id.to_string());
    if *ui.state.borrow() == state::UNLOCKED {
        reload(ui);
    }
}

/// An item was opened in the window: it goes first among the recently used.
fn opened(ui: &Ui, id: String) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        if client::call("OpenedItem", Some((id.as_str(),).to_variant())).await.is_ok() {
            let mut recent = ui.recent.borrow_mut();
            recent.retain(|r| *r != id);
            recent.insert(0, id);
        }
    });
}

/// Fetches the listing again and redraws.
pub fn reload(ui: &Ui) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        match client::text("List", None).await {
            Ok(json) => {
                if let Ok(listing) = serde_json::from_str::<Listing>(&json) {
                    *ui.listing.borrow_mut() = listing;
                }
                let pending = ui.pending_item.borrow_mut().take();
                if let Some(id) = pending.filter(|id| ui.listing.borrow().entries.iter().any(|e| e.id == *id)) {
                    *ui.selected.borrow_mut() = Some(id);
                    ui.multi.borrow_mut().clear();
                    ui.showing_detail.set(true);
                }
                // A daemon from before Recent has no such method: the section stays empty.
                let recent = client::text("Recent", None).await.ok();
                *ui.recent.borrow_mut() = recent.and_then(|j| serde_json::from_str(&j).ok()).unwrap_or_default();
                refresh_list(&ui);
                nav(&ui);
                detail::show(&ui);
                refresh_views(&ui);
                security::refresh(&ui);
            }
            Err(e) if e.is(nyx_passwords_proto::Error::Locked) => set_state(&ui, state::LOCKED),
            Err(e) => toast(&ui, &e.to_string()),
        }
    });
}

pub fn sync(ui: &Ui) {
    let ui = ui.clone();
    ui.sync_button.set_sensitive(false);
    ui.sync_button.set_tooltip_text(Some("Syncing…"));
    glib::spawn_future_local(async move {
        let synced = client::call("Sync", None).await;
        ui.sync_button.set_sensitive(true);
        match synced {
            Ok(_) => reload(&ui),
            Err(e) => {
                toast(&ui, &format!("Sync failed: {e}"));
                refresh_list(&ui);
            }
        }
    });
}

pub fn lock(ui: &Ui) {
    let ui = ui.clone();
    glib::spawn_future_local(async move {
        let _ = client::call("Lock", None).await;
        set_state(&ui, state::LOCKED);
    });
}

pub fn navigate(ui: &Ui, section: &str) {
    if section == "settings" {
        open_settings();
        return;
    }
    if section == "aliases" {
        super::aliases::open(ui);
        return;
    }
    *ui.section.borrow_mut() = section.to_string();
    *ui.selected.borrow_mut() = None;
    ui.multi.borrow_mut().clear();
    ui.showing_detail.set(false);
    prefs::update(|p| p.last_section = section.to_string());
    refresh_list(ui);
    nav(ui);
    detail::show(ui);
    show_view(ui);
    ui.search.grab_focus();
}

/// Home, the Security page, or the list and details, as the section asks.
fn show_view(ui: &Ui) {
    if *ui.state.borrow() != state::UNLOCKED {
        return;
    }
    let view = match ui.section.borrow().as_str() {
        "home" => "home",
        "security" => "security",
        _ => "vault",
    };
    ui.pages.set_visible_child_name(view);
    refresh_views(ui);
}

/// Builds Home or the Security page again, whichever is showing, from the listing and
/// the report.
pub fn refresh_views(ui: &Ui) {
    if *ui.state.borrow() != state::UNLOCKED {
        return;
    }
    match ui.section.borrow().clone().as_str() {
        "home" => {
            ui.home_narrow.set(Some(ui.narrow.get()));
            home::build(ui);
        }
        "security" => security::page(ui),
        _ => {}
    }
}

/// The entries shown for the current section and search, in name order.
pub fn visible(ui: &Ui) -> Vec<data::Entry> {
    let section = ui.section.borrow().clone();
    let query = ui.search.text().to_string();
    let report = ui.security.borrow();
    if section == "recent" {
        let listing = ui.listing.borrow();
        return ui
            .recent
            .borrow()
            .iter()
            .filter_map(|id| listing.entries.iter().find(|e| e.id == *id && !e.deleted))
            .filter(|e| e.matches(&query))
            .cloned()
            .collect();
    }
    let shown = |e: &data::Entry| if section == "security" { report.flags(e) } else { e.in_section(&section) };
    ui.listing.borrow().entries.iter().filter(|e| shown(e) && e.matches(&query)).cloned().collect()
}

pub fn refresh_list(ui: &Ui) {
    ui.rebuilding.set(true);
    clear(&ui.list);
    let entries = visible(ui);
    let selected = ui.selected.borrow().clone().filter(|id| entries.iter().any(|e| e.id == *id));
    *ui.selected.borrow_mut() = selected.clone();
    ui.multi.borrow_mut().retain(|id| entries.iter().any(|e| e.id == *id));
    if ui.multi.borrow().len() < 2 {
        ui.multi.borrow_mut().clear();
    }
    let multi = ui.multi.borrow().clone();
    for e in &entries {
        let row = gtk::ListBoxRow::new();
        row.set_widget_name(&e.id);
        let line = w::hbox(12);
        line.set_margin_top(8);
        line.set_margin_bottom(8);
        line.set_margin_start(14);
        line.set_margin_end(14);
        let icon = gtk::Image::from_icon_name(data::kind_icon(&e.kind));
        icon.add_css_class("dim");
        super::icons::show(&icon, e.host.as_deref(), 16);
        line.append(&icon);
        let text = w::vbox(2);
        text.set_hexpand(true);
        let name = gtk::Label::new(Some(if e.readable { &e.name } else { "Unreadable item" }));
        name.add_css_class("item-row-name");
        name.set_xalign(0.0);
        name.set_ellipsize(gtk::pango::EllipsizeMode::End);
        text.append(&name);
        let sub = gtk::Label::new(Some(&e.subtitle()));
        sub.add_css_class("dim");
        sub.add_css_class("item-row-description");
        sub.set_xalign(0.0);
        sub.set_ellipsize(gtk::pango::EllipsizeMode::End);
        text.append(&sub);
        line.append(&text);
        if e.favorite {
            let star = gtk::Image::from_icon_name("starred-symbolic");
            star.add_css_class("accent");
            line.append(&star);
        }
        row.set_child(Some(&line));
        ui.list.append(&row);
        if selected.as_deref() == Some(e.id.as_str()) || multi.contains(&e.id) {
            ui.list.select_row(Some(&row));
        }
    }
    if entries.is_empty() {
        let empty = w::vbox(12);
        empty.add_css_class("item-empty");
        empty.set_margin_top(80);
        empty.set_margin_start(20);
        empty.set_margin_end(20);
        empty.set_halign(gtk::Align::Center);
        let icon = gtk::Image::from_icon_name("dialog-password-symbolic");
        icon.set_pixel_size(32);
        icon.add_css_class("dim");
        empty.append(&icon);
        let message = if !ui.search.text().is_empty() {
            "No matching items."
        } else if *ui.section.borrow() == "trash" {
            "The trash is empty."
        } else if *ui.section.borrow() == "recent" {
            "Items you open or copy, here or in Glimpse and browsers, show up here."
        } else {
            "No items here yet."
        };
        empty.append(&label(message, "dim"));
        let row = gtk::ListBoxRow::new();
        row.add_css_class("item-empty-row");
        row.set_selectable(false);
        row.set_activatable(false);
        row.set_child(Some(&empty));
        ui.list.append(&row);
    }
    ui.rebuilding.set(false);
    let synced = ui.listing.borrow().account.last_sync.map(|t| format!(" · synced {}", data::ago(t))).unwrap_or_default();
    ui.sync_button.set_tooltip_text(Some(&format!("Sync now (F5){synced}")));
    layout(ui);
}

/// What a sidebar entry shows beside its name.
enum Readout {
    None,
    Count(usize),
    /// An accent badge: things to fix.
    Badge(usize),
    /// A word, dim ("Shared").
    Note(&'static str),
}

/// A sidebar entry: section id, name, icon, readout.
type NavEntry = (String, String, String, Readout);

/// The icon rail's mark where a group starts, in the group's colour.
fn nav_divider(ui: &Ui, section: &str) {
    let bar = gtk::Separator::new(gtk::Orientation::Horizontal);
    bar.add_css_class("nav-divider");
    bar.add_css_class("compact-show");
    nyx_ui::sidebar::set_section(&bar, section);
    bar.set_visible(false);
    ui.nav.append(&bar);
}

/// Sections that have no sidebar entry of their own, and their titles.
const UNLISTED: &[(&str, &str)] = &[("recent", "Used lately")];

pub fn nav(ui: &Ui) {
    clear(&ui.nav);
    if *ui.state.borrow() != state::UNLOCKED {
        return;
    }
    let listing = ui.listing.borrow();
    let live = |f: &dyn Fn(&data::Entry) -> bool| listing.entries.iter().filter(|e| !e.deleted && f(e)).count();
    let flagged = listing.entries.iter().filter(|e| ui.security.borrow().flags(e)).count();
    // The first entries have no heading; the first heading takes the app's accent.
    let mut groups: Vec<(Option<&str>, &str, Vec<NavEntry>)> = vec![(
        None,
        "",
        vec![
            ("home".into(), "Home".into(), "go-home-symbolic".into(), Readout::None),
            ("all".into(), "All items".into(), "view-list-symbolic".into(), Readout::Count(live(&|_| true))),
            ("favorites".into(), "Favorites".into(), "starred-symbolic".into(), Readout::Count(live(&|e| e.favorite))),
            ("security".into(), "Security".into(), "security-high-symbolic".into(), Readout::Badge(flagged)),
        ],
    )];
    let mut types: Vec<NavEntry> = data::KINDS
        .iter()
        .map(|(id, name, icon)| (id.to_string(), name.to_string(), icon.to_string(), live(&|e| e.kind == *id)))
        .filter(|(id, _, _, n)| *n > 0 || id == "login")
        .map(|(id, name, icon, n)| (id, name, icon, Readout::Count(n)))
        .collect();
    types.extend(super::templates::all().into_iter().filter_map(|t| {
        let n = live(&|e| e.template.as_deref() == Some(t.id.as_str()));
        let icon = if t.id == "wifi" { "network-wireless-symbolic" } else { data::kind_icon(&t.kind) };
        (n > 0).then(|| (format!("template:{}", t.id), t.name, icon.to_string(), Readout::Count(n)))
    }));
    groups.push((Some("Types"), nyx_ui::sidebar::ACCENT_SECTION, types));
    let mut folders: Vec<NavEntry> = listing
        .folders
        .iter()
        .map(|f| {
            let id = f.id.clone();
            let n = live(&|e| e.folder.as_deref() == Some(&id));
            (format!("folder:{}", f.id), f.name.clone(), "folder-symbolic".into(), Readout::Count(n))
        })
        .collect();
    if !folders.is_empty() {
        let n = live(&|e| e.folder.is_none() && e.organization.is_none());
        folders.push(("nofolder".into(), "No folder".into(), "folder-symbolic".into(), Readout::Count(n)));
    }
    folders.extend(
        listing
            .collections
            .iter()
            .map(|c| (format!("collection:{}", c.id), c.name.clone(), "system-users-symbolic".into(), Readout::Note("Shared"))),
    );
    groups.push((Some("Folders"), "swatch-green", folders));
    let trashed = listing.entries.iter().filter(|e| e.deleted).count();
    let aliased = live(&|e| e.alias.is_some());
    groups.push((
        Some("More"),
        "swatch-graphite",
        vec![
            ("aliases".into(), "Email aliases".into(), "mail-send-symbolic".into(), Readout::Count(aliased)),
            ("trash".into(), "Trash".into(), "user-trash-symbolic".into(), Readout::Count(trashed)),
        ],
    ));
    drop(listing);
    let current = ui.section.borrow().clone();
    let mut title = UNLISTED.iter().find(|(id, _)| *id == current).map(|(_, t)| t.to_string());
    for (heading, section, items) in groups {
        if let Some(heading) = heading {
            nav_divider(ui, section);
            let row = if heading == "Folders" {
                let u = ui.clone();
                nyx_ui::sidebar::group_label_with_add(heading, false, "New folder", move || new_folder(&u))
            } else {
                nyx_ui::sidebar::group_label(heading, false)
            };
            nyx_ui::sidebar::set_section(&row, section);
            ui.nav.append(&row);
        }
        for (id, name, icon, readout) in items {
            let item = nyx_ui::sidebar::nav_item(&icon, &name, &name);
            match readout {
                Readout::None => {}
                Readout::Count(n) => item.set_count(Some(n as u64)),
                Readout::Badge(n) => item.set_badge(Some(n as u64)),
                Readout::Note(text) => {
                    if let Some(line) = item.button.child().and_downcast::<gtk::Box>() {
                        let note = w::label(text, "nav-sub");
                        note.add_css_class("compact-hide");
                        line.append(&note);
                    }
                }
            }
            if id == current {
                item.set_active(true);
                title = Some(name.clone());
            }
            if let Some(folder) = id.strip_prefix("folder:") {
                folder_menu(ui, &item.button, folder, &name);
                item.button.set_tooltip_text(Some(&format!("{name} · right-click to rename or delete")));
            }
            let u = ui.clone();
            item.button.connect_clicked(move |_| navigate(&u, &id));
            ui.nav.append(&item.button);
        }
    }
    match title {
        Some(t) => set_subtitle(ui, &t),
        // The section's folder or collection is gone: back to everything.
        None => {
            *ui.section.borrow_mut() = "all".into();
            set_subtitle(ui, "All items");
        }
    }
    compact_sidebar(ui);
}

fn new_folder(ui: &Ui) {
    let u = ui.clone();
    w::ask_text("New folder", "", "", "Create", move |name| {
        let u = u.clone();
        glib::spawn_future_local(async move {
            match client::text("CreateFolder", Some((name.as_str(),).to_variant())).await {
                Ok(id) => {
                    *u.section.borrow_mut() = format!("folder:{id}");
                    reload(&u);
                }
                Err(e) => toast(&u, &e.to_string()),
            }
        });
    });
}

/// Right-clicking a folder in the sidebar: rename or delete it.
fn folder_menu(ui: &Ui, button: &gtk::Button, id: &str, name: &str) {
    let click = gtk::GestureClick::new();
    click.set_button(gdk::BUTTON_SECONDARY);
    let (u, b, id, name) = (ui.clone(), button.clone(), id.to_string(), name.to_string());
    click.connect_pressed(move |_, _, _, _| {
        let menu = gtk::Popover::new();
        let items = w::vbox(2);
        let rename = gtk::Button::with_label("Rename…");
        let delete = gtk::Button::with_label("Delete folder…");
        for item in [&rename, &delete] {
            item.add_css_class("flat");
            items.append(item);
        }
        menu.set_child(Some(&items));
        menu.set_parent(&b);
        // Unparented once closed, so the sidebar can be rebuilt without leftovers.
        menu.connect_closed(|m| {
            let m = m.clone();
            glib::idle_add_local_once(move || m.unparent());
        });
        let (u2, id2, name2, m) = (u.clone(), id.clone(), name.clone(), menu.clone());
        rename.connect_clicked(move |_| {
            m.popdown();
            rename_folder(&u2, &id2, &name2);
        });
        let (u2, id2, name2, m) = (u.clone(), id.clone(), name.clone(), menu.clone());
        delete.connect_clicked(move |_| {
            m.popdown();
            delete_folder(&u2, &id2, &name2);
        });
        menu.popup();
    });
    button.add_controller(click);
}

fn rename_folder(ui: &Ui, id: &str, name: &str) {
    let (u, id) = (ui.clone(), id.to_string());
    w::ask_text("Rename folder", "", name, "Rename", move |name| {
        let (u, id) = (u.clone(), id.clone());
        glib::spawn_future_local(async move {
            match client::call("RenameFolder", Some((id.as_str(), name.as_str()).to_variant())).await {
                Ok(_) => reload(&u),
                Err(e) => toast(&u, &e.to_string()),
            }
        });
    });
}

fn delete_folder(ui: &Ui, id: &str, name: &str) {
    let (ui, id, name) = (ui.clone(), id.to_string(), name.to_string());
    glib::spawn_future_local(async move {
        let asked = format!("Delete the folder “{name}”?");
        if !confirm(&ui, &asked, "Its items stay in the vault, in no folder.", "Delete").await {
            return;
        }
        match client::call("DeleteFolder", Some((id.as_str(),).to_variant())).await {
            Ok(_) => {
                if *ui.section.borrow() == format!("folder:{id}") {
                    *ui.section.borrow_mut() = "all".into();
                }
                reload(&ui);
                toast(&ui, "Folder deleted.");
            }
            Err(e) => toast(&ui, &e.to_string()),
        }
    });
}

/// Asks before something that can't be undone; Cancel is the default.
pub async fn confirm(ui: &Ui, message: &str, detail: &str, action: &str) -> bool {
    let ask = gtk::AlertDialog::builder()
        .modal(true)
        .message(message)
        .detail(detail)
        .buttons(["Cancel", action])
        .cancel_button(0)
        .default_button(0)
        .build();
    ask.choose_future(Some(&ui.window)).await == Ok(1)
}

const SEARCH_WIDE: i32 = 28;
const SEARCH_NARROW: i32 = 14;

pub fn layout(ui: &Ui) {
    let width = if ui.window.width() > 0 { ui.window.width() } else { ui.window.default_width() };
    let narrow = width > 0 && width < 980;
    nyx_ui::settings_card::fit(&ui.window);
    ui.narrow.set(narrow);
    // The centred search mustn't reach the sidebar toggle or the actions beside it.
    ui.search.set_max_width_chars(if narrow { SEARCH_NARROW } else { SEARCH_WIDE });
    compact_sidebar(ui);
    if *ui.section.borrow() == "home" && ui.home_narrow.get().is_some_and(|n| n != narrow) {
        refresh_views(ui);
    }
    let empty = visible(ui).is_empty();
    let open = *ui.state.borrow() == state::UNLOCKED;
    let trashed = ui.listing.borrow().entries.iter().any(|e| e.deleted);
    ui.trash_bar.set_visible(open && *ui.section.borrow() == "trash" && trashed);
    ui.new_button.set_visible(open && *ui.section.borrow() != "trash");
    ui.list_scroll.set_hexpand(narrow || empty);
    ui.list_scroll.set_visible(empty || !narrow || !ui.showing_detail.get());
    ui.detail_scroll.set_visible(!empty && (!narrow || ui.showing_detail.get()));
    ui.pane_line.set_visible(ui.list_scroll.is_visible() && ui.detail_scroll.is_visible());
    if let Some(back) = ui.details.first_child() {
        back.set_visible(narrow);
    }
    ui.list_scroll.set_width_request(if narrow || empty { -1 } else { 300 });
}

/// Puts the sidebar in its icon-only form (narrow window, or collapsed) or its full one.
/// Runs after every rebuild of the sidebar too, or new buttons would show their labels
/// in the narrow column.
fn compact_sidebar(ui: &Ui) {
    let compact = ui.narrow.get() || prefs::get().sidebar_collapsed;
    if compact {
        ui.sidebar.add_css_class("compact");
    } else {
        ui.sidebar.remove_css_class("compact");
    }
    fn hide(root: &gtk::Widget, compact: bool) {
        if root.has_css_class("nav-item") {
            if compact {
                root.add_css_class("compact");
            } else {
                root.remove_css_class("compact");
            }
            if let Some(content) = root.downcast_ref::<gtk::Button>().and_then(|b| b.child()) {
                content.set_halign(if compact { gtk::Align::Center } else { gtk::Align::Fill });
            }
        }
        // An empty count stays hidden when the labels come back.
        let empty_readout =
            root.has_css_class("nav-readout") && root.downcast_ref::<gtk::Label>().is_some_and(|l| l.text().is_empty());
        if root.has_css_class("compact-hide") {
            root.set_visible(!compact && !empty_readout);
        }
        if root.has_css_class("compact-show") {
            root.set_visible(compact);
        }
        let mut child = root.first_child();
        while let Some(c) = child {
            hide(&c, compact);
            child = c.next_sibling();
        }
    }
    hide(ui.nav.upcast_ref(), compact);
}

/// The section (or the lock state) beside the app name, and in the window title.
fn set_subtitle(ui: &Ui, text: &str) {
    ui.header.set_subtitle(text);
    chrome::set_title(&ui.window, "Passwords", text);
}

fn find(ui: &Ui) {
    ui.search.grab_focus();
    ui.search.select_region(0, -1);
}

fn install_icons() {
    let dir = nyx_core::paths::cache_dir().join("icons");
    let _ = std::fs::create_dir_all(&dir);
    for (name, svg) in [
        ("nyx-card-symbolic.svg", include_str!("../../data/icons/nyx-card-symbolic.svg")),
        ("nyx-key-symbolic.svg", include_str!("../../data/icons/nyx-key-symbolic.svg")),
        ("nyx-duplicate-symbolic.svg", include_str!("../../data/icons/nyx-duplicate-symbolic.svg")),
        ("nyx-import-symbolic.svg", include_str!("../../data/icons/nyx-import-symbolic.svg")),
        ("nyx-export-symbolic.svg", include_str!("../../data/icons/nyx-export-symbolic.svg")),
    ] {
        let _ = std::fs::write(dir.join(name), svg);
    }
    if let Some(display) = gdk::Display::default() {
        gtk::IconTheme::for_display(&display).add_search_path(&dir);
    }
}

/// Empties a box or a list.
pub fn clear(b: &impl IsA<gtk::Widget>) {
    let b = b.upcast_ref::<gtk::Widget>();
    if let Some(list) = b.downcast_ref::<gtk::ListBox>() {
        list.remove_all();
    } else if let Some(bx) = b.downcast_ref::<gtk::Box>() {
        while let Some(c) = bx.first_child() {
            bx.remove(&c);
        }
    }
}

pub fn label(text: &str, class: &str) -> gtk::Label {
    let l = w::label(text, class);
    l.set_xalign(0.0);
    l.set_wrap(true);
    l
}

pub fn scroll(child: &impl IsA<gtk::Widget>) -> gtk::ScrolledWindow {
    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .vexpand(true)
        .child(child)
        .build()
}

/// Puts the toast back above overlays added after it (the editor), so it stays visible.
pub fn raise_toast(ui: &Ui) {
    ui.overlay.remove_overlay(&ui.toast_box);
    ui.overlay.add_overlay(&ui.toast_box);
}

pub fn toast(ui: &Ui, text: &str) {
    toast_action(ui, text, None);
}

pub type ToastAction<'a> = Option<(&'a str, Box<dyn Fn()>)>;

pub fn toast_action(ui: &Ui, text: &str, action: ToastAction<'_>) {
    clear(&ui.toast_box);
    let l = label(text, "");
    l.set_max_width_chars(65);
    ui.toast_box.append(&l);
    let has_action = action.is_some();
    if let Some((name, run)) = action {
        let b = gtk::Button::with_label(name);
        let u = ui.clone();
        b.connect_clicked(move |_| {
            run();
            u.toast_box.set_visible(false);
        });
        ui.toast_box.append(&b);
    }
    ui.toast_box.set_visible(true);
    let serial = ui.toast_serial.get() + 1;
    ui.toast_serial.set(serial);
    let weak = Rc::downgrade(ui);
    let shown = if has_action { Duration::from_secs(6) } else { Duration::from_millis(3500) };
    glib::timeout_add_local_once(shown, move || {
        if let Some(u) = weak.upgrade()
            && u.toast_serial.get() == serial
        {
            u.toast_box.set_visible(false);
        }
    });
}

pub const SHORTCUTS: &[(&[&str], &str)] = &[
    (&["Ctrl", "N"], "New item"),
    (&["Ctrl", "F"], "Search the vault"),
    (&["Ctrl", "Shift", "U"], "Copy the username"),
    (&["Ctrl", "Shift", "C"], "Copy the password"),
    (&["Ctrl", "Shift", "O"], "Copy the one-time code"),
    (&["Ctrl", "S"], "Save in the editor"),
    (&["Ctrl", "L"], "Lock the vault"),
    (&["F5"], "Sync now"),
    (&["Ctrl", "B"], "Collapse sidebar"),
    (&["Ctrl", ","], "Settings"),
    (&["Ctrl", "Shift", "P"], "Command palette"),
    (&["Esc"], "Clear the search, close a card, or return to the list"),
    (&["F1"], "Show these shortcuts (or ?)"),
    (&["Ctrl", "Q"], "Quit Passwords"),
    (&["Ctrl", "W"], "Close window"),
];

pub fn show_shortcuts() {
    let (dialog, card) = w::dialog("Keyboard shortcuts", 520);
    let list = w::vbox(0);
    list.add_css_class("group-list");
    for (keys, action) in SHORTCUTS {
        list.append(&w::row(action, "", Some(w::key_caps(keys).upcast_ref())));
    }
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vscrollbar_policy(gtk::PolicyType::External)
        .propagate_natural_height(true)
        .max_content_height(560)
        .child(&list)
        .build();
    card.append(&scroll);
    let close = gtk::Button::with_label("Close");
    close.set_tooltip_text(Some("Close shortcuts (Esc)"));
    close.set_halign(gtk::Align::End);
    let d = dialog.clone();
    close.connect_clicked(move |_| d.close());
    card.append(&close);
    dialog.present();
}

pub fn open_settings() {
    if let Some(ui) = current() {
        settings::open(&ui);
    }
}
