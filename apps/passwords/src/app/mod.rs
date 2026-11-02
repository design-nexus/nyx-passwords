//! The Passwords window. It holds no keys: everything goes through the daemon.

mod account;
mod aliases;
pub mod approve;
mod attachments;
mod client;
mod data;
mod detail;
mod editor;
mod emergency;
#[cfg(debug_assertions)]
pub mod fixture;
mod icons;
mod pairing;
pub mod prefs;
mod security;
mod settings;
mod templates;
mod theme;
mod transfer;
pub mod ui;
