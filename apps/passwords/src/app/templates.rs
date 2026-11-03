//! The templates the window offers: the built-in ones and the user's own, from
//! `~/.config/nyx-passwords/templates.toml` (labels and types only; values live in the
//! items).

use std::path::PathBuf;

pub use nyx_passwords_core::templates::{Slot, Template, TemplateField};
use nyx_passwords_core::templates::{TemplateFile, builtin};

fn file() -> PathBuf {
    nyx_core::paths::app_dir().join("templates.toml")
}

/// The user's own templates, as usable (see `TemplateFile::usable`).
pub fn custom() -> Vec<Template> {
    let Ok(text) = std::fs::read_to_string(file()) else { return Vec::new() };
    toml::from_str::<TemplateFile>(&text).map(|f| f.usable()).unwrap_or_default()
}

/// Built-in templates, then the user's.
pub fn all() -> Vec<Template> {
    let mut all = builtin();
    all.extend(custom());
    all
}

pub fn find(id: &str) -> Option<Template> {
    all().into_iter().find(|t| t.id == id)
}

/// Saves the user's templates, replacing the file.
pub fn save(templates: &[Template]) -> Result<(), String> {
    let text = toml::to_string_pretty(&TemplateFile { templates: templates.to_vec() }).map_err(|e| e.to_string())?;
    let path = file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    nyx_core::cmd::atomic_write(&path, text).map_err(|e| e.to_string())
}

/// The slots a custom template's field may use for `kind`, with their names.
pub fn slot_choices(kind: &str) -> Vec<(String, String)> {
    let mut rows: Vec<(String, String)> = [("text", "Text"), ("hidden", "Hidden"), ("boolean", "True or false")]
        .iter()
        .map(|(s, n)| (s.to_string(), n.to_string()))
        .collect();
    if kind == "login" {
        for (slot, name) in [
            ("username", "The username"),
            ("password", "The password"),
            ("uri", "A web address"),
            ("totp", "The one-time code key"),
        ] {
            rows.push((slot.into(), name.into()));
        }
    }
    rows.push(("notes".into(), "The notes".into()));
    for spec in nyx_passwords_proto::fields::of_kind(kind) {
        rows.push((spec.name.into(), format!("{} ({})", spec.label, super::data::kind_name(kind).to_lowercase())));
    }
    rows
}
