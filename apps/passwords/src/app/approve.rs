//! The approval card: what another program asks of the vault (an SSH key signing, a Nyx
//! app wanting access), one request at a time, with Deny first. The daemon opens it with
//! `nyx-passwords --approve` when something waits; it closes once nothing does.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::time::Duration;

use gtk::{gdk, glib, prelude::*};
use nyx_ui::widgets as w;
use serde::Deserialize;

use super::client;
use super::ui::label;

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct Waiting {
    id: u64,
    title: String,
    detail: String,
    program: String,
    #[serde(default)]
    once_label: String,
    session_label: Option<String>,
}

thread_local! { static OPEN: RefCell<Option<gtk::Window>> = const { RefCell::new(None) }; }

pub fn open(app: &gtk::Application) {
    if let Some(window) = OPEN.with(|o| o.borrow().clone()) {
        window.present();
        return;
    }
    super::theme::install();
    let window = gtk::Window::builder().application(app).title("Passwords: approve").default_width(460).resizable(false).build();
    window.add_css_class("passwords-window");
    // The window is the card: a card inside it would draw a second frame.
    let card = w::vbox(12);
    card.set_margin_top(18);
    card.set_margin_bottom(18);
    card.set_margin_start(18);
    card.set_margin_end(18);
    let title = w::label("", "section-title");
    title.set_wrap(true);
    title.set_xalign(0.0);
    let detail = label("", "");
    detail.set_wrap(true);
    detail.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    let program = label("", "dim");
    program.set_wrap(true);
    program.set_wrap_mode(gtk::pango::WrapMode::WordChar);
    let note = label("Passwords never gives the program a key or password: it signs, or copies to the clipboard.", "dim");
    note.set_wrap(true);
    let buttons = w::hbox(8);
    buttons.set_halign(gtk::Align::End);
    let deny = gtk::Button::with_label("Deny");
    let once = gtk::Button::with_label("Allow once");
    once.add_css_class("suggested-action");
    let session = gtk::Button::with_label("");
    buttons.append(&deny);
    buttons.append(&session);
    buttons.append(&once);
    for widget in
        [title.upcast_ref::<gtk::Widget>(), detail.upcast_ref(), program.upcast_ref(), note.upcast_ref(), buttons.upcast_ref()]
    {
        card.append(widget);
    }
    window.set_child(Some(&card));

    let current: Rc<RefCell<Option<Waiting>>> = Rc::default();
    let answered = Rc::new(Cell::new(0u64));
    let reply = {
        let (current, answered) = (current.clone(), answered.clone());
        move |choice: &'static str| {
            let Some(w) = current.borrow_mut().take() else { return };
            answered.set(w.id);
            glib::spawn_future_local(async move {
                let _ = client::call("Answer", Some((w.id, choice).to_variant())).await;
            });
        }
    };
    let r = reply.clone();
    deny.connect_clicked(move |_| r("deny"));
    let r = reply.clone();
    once.connect_clicked(move |_| r("once"));
    let r = reply.clone();
    session.connect_clicked(move |_| r("session"));
    let keys = gtk::EventControllerKey::new();
    let r = reply.clone();
    keys.connect_key_pressed(move |_, key, _, _| {
        if key == gdk::Key::Escape {
            r("deny");
            return glib::Propagation::Stop;
        }
        glib::Propagation::Proceed
    });
    window.add_controller(keys);
    // Closing the window refuses what it was showing.
    let r = reply.clone();
    window.connect_close_request(move |_| {
        r("deny");
        OPEN.with(|o| o.borrow_mut().take());
        glib::Propagation::Proceed
    });
    OPEN.with(|o| *o.borrow_mut() = Some(window.clone()));
    window.present();
    deny.grab_focus();

    // Polls for what's waiting; shows the oldest; closes when nothing is left (or
    // nothing came within a few seconds of opening).
    let started = std::time::Instant::now();
    let (win, shown) = (window.downgrade(), Rc::new(Cell::new(false)));
    glib::spawn_future_local(async move {
        loop {
            let Some(window) = win.upgrade() else { return };
            let list: Vec<Waiting> = match client::text("Approvals", None).await {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => Vec::new(),
            };
            match list.into_iter().find(|w| w.id != answered.get()) {
                Some(next) => {
                    if current.borrow().as_ref() != Some(&next) {
                        title.set_text(&next.title);
                        detail.set_text(&next.detail);
                        program.set_text(&format!("Program: {}", next.program));
                        once.set_label(if next.once_label.is_empty() { "Allow once" } else { &next.once_label });
                        session.set_visible(next.session_label.is_some());
                        session.set_label(next.session_label.as_deref().unwrap_or_default());
                        *current.borrow_mut() = Some(next);
                        shown.set(true);
                        window.present();
                        deny.grab_focus();
                    }
                }
                None if shown.get() || started.elapsed() > Duration::from_secs(5) => {
                    current.borrow_mut().take();
                    window.close();
                    return;
                }
                None => {}
            }
            glib::timeout_future(Duration::from_millis(400)).await;
        }
    });
}
