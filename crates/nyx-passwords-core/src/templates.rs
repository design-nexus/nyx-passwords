//! Item templates: ways of laying out and editing standard Bitwarden items. A template
//! is presentation only. Its values live in the item's own fields (a login's username,
//! password and addresses, an identity's fields) and in custom fields named after the
//! template's labels, so every Bitwarden client shows them. The item records which
//! template it uses in one text custom field, `nyx:template` (`proto::custom::TEMPLATE`);
//! without it the item shows as its plain kind.
//!
//! Built-in templates are here; the user's own come from the app's `templates.toml`
//! (labels and types only, never values).

use serde::{Deserialize, Serialize};

/// A template: an id (the value of the item's `nyx:template` field), a name, the kind
/// of item it makes (`login`, `note`, `card` or `identity`), and its fields in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Template {
    pub id: String,
    pub name: String,
    pub kind: String,
    #[serde(default, rename = "field")]
    pub fields: Vec<TemplateField>,
}

/// One field: its label, where it's kept (`slot`), and an example shown in the empty
/// field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateField {
    pub label: String,
    /// `username`, `password`, `totp`, `uri` or `notes` (the item's own; the first four
    /// for logins only), a field of the item's kind (`identity.passportNumber`), or a
    /// custom field: `text`, `hidden` or `boolean`.
    pub slot: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hint: String,
}

/// Where a template field's value is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot<'a> {
    Username,
    Password,
    Totp,
    Uri,
    Notes,
    /// A field of the item's kind, by name (`identity.passportNumber`).
    Own(&'a str),
    /// A custom field named after the label: 0 text, 1 hidden, 2 true or false.
    Custom(i64),
}

/// The kinds a template can make.
pub const KINDS: &[&str] = &["login", "note", "card", "identity"];

/// Custom templates' ids start with this, so they can't take a built-in one's.
pub const CUSTOM_PREFIX: &str = "my-";

/// The most fields a template may have.
const FIELDS_MAX: usize = 50;

impl TemplateField {
    pub fn slot(&self, kind: &str) -> Option<Slot<'_>> {
        let login = kind == "login";
        Some(match self.slot.as_str() {
            "username" if login => Slot::Username,
            "password" if login => Slot::Password,
            "totp" if login => Slot::Totp,
            "uri" if login => Slot::Uri,
            "notes" => Slot::Notes,
            "text" => Slot::Custom(0),
            "hidden" => Slot::Custom(1),
            "boolean" => Slot::Custom(2),
            own if nyx_passwords_proto::fields::of_kind(kind).iter().any(|s| s.name == own) => Slot::Own(own),
            _ => return None,
        })
    }
}

impl Template {
    /// The label this template gives a slot, if it has that slot.
    pub fn label_for(&self, slot: Slot) -> Option<&str> {
        self.fields.iter().find(|f| f.slot(&self.kind) == Some(slot)).map(|f| f.label.as_str())
    }

    /// The custom fields it lays out: `(label, type)`.
    pub fn custom_fields(&self) -> impl Iterator<Item = (&str, i64)> {
        self.fields.iter().filter_map(|f| match f.slot(&self.kind) {
            Some(Slot::Custom(kind)) => Some((f.label.as_str(), kind)),
            _ => None,
        })
    }

    /// Why a template can't be used, if it can't: an unknown kind or slot, an empty or
    /// repeated label, a slot used twice, or one of Passwords' own field names.
    pub fn problem(&self) -> Option<String> {
        if self.name.trim().is_empty() {
            return Some("a template needs a name".into());
        }
        if !KINDS.contains(&self.kind.as_str()) {
            return Some(format!("“{}” isn't a kind of item a template can make", self.kind));
        }
        if self.fields.len() > FIELDS_MAX {
            return Some(format!("a template can have at most {FIELDS_MAX} fields"));
        }
        let mut labels = std::collections::HashSet::new();
        let mut own = std::collections::HashSet::new();
        for f in &self.fields {
            let label = f.label.trim();
            if label.is_empty() {
                return Some("every field needs a name".into());
            }
            if label.starts_with("nyx:") {
                return Some(format!("“{label}” is a name Passwords keeps for itself"));
            }
            if !labels.insert(label.to_lowercase()) {
                return Some(format!("“{label}” is there twice"));
            }
            match f.slot(&self.kind) {
                None => return Some(format!("“{label}” has a type this kind of item doesn't have")),
                Some(Slot::Custom(_)) => {}
                Some(slot) if !own.insert(format!("{slot:?}")) => {
                    return Some(format!("“{label}” uses a field another one already uses"));
                }
                Some(_) => {}
            }
        }
        None
    }
}

/// The user's templates file: `[[template]]` tables.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemplateFile {
    #[serde(default, rename = "template")]
    pub templates: Vec<Template>,
}

impl TemplateFile {
    /// The usable custom templates: ids given the custom prefix, and any with a problem
    /// or an id seen before left out.
    pub fn usable(&self) -> Vec<Template> {
        let mut seen = std::collections::HashSet::new();
        self.templates
            .iter()
            .filter(|t| t.problem().is_none())
            .map(|t| {
                let mut t = t.clone();
                if !t.id.starts_with(CUSTOM_PREFIX) {
                    t.id = custom_id(&t.id);
                }
                t
            })
            .filter(|t| seen.insert(t.id.clone()))
            .collect()
    }
}

/// An id for a custom template from its name: `my-gym-membership`.
pub fn custom_id(name: &str) -> String {
    let mut slug = String::new();
    for c in name.trim().to_lowercase().chars() {
        if c.is_alphanumeric() {
            slug.push(c);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    format!("{CUSTOM_PREFIX}{}", if slug.is_empty() { "template" } else { slug })
}

fn field(label: &str, slot: &str, hint: &str) -> TemplateField {
    TemplateField { label: label.into(), slot: slot.into(), hint: hint.into() }
}

fn template(id: &str, name: &str, kind: &str, fields: Vec<TemplateField>) -> Template {
    Template { id: id.into(), name: name.into(), kind: kind.into(), fields }
}

/// The built-in templates. A plain login is the website login.
pub fn builtin() -> Vec<Template> {
    vec![
        template(
            "ssh",
            "SSH credential",
            "login",
            vec![
                field("Address", "uri", "ssh://server.example.com:22"),
                field("Username", "username", ""),
                field("Password or passphrase", "password", ""),
                field("Host key fingerprint", "text", "SHA256:…"),
            ],
        ),
        template(
            "api-key",
            "API key",
            "login",
            vec![
                field("Key ID", "username", ""),
                field("Secret", "password", ""),
                field("Service address", "uri", "https://api.example.com"),
                field("Scopes", "text", "read, write"),
                field("Expires", "text", "2027-01-31"),
            ],
        ),
        template(
            "wifi",
            "Wi-Fi network",
            "login",
            vec![
                field("Network name (SSID)", "username", ""),
                field("Password", "password", ""),
                field("Security", "text", "WPA3, WPA2…"),
                field("Hidden network", "boolean", ""),
            ],
        ),
        template(
            "server",
            "Server",
            "login",
            vec![
                field("Address", "uri", "https://server.example.com or ssh://…"),
                field("Username", "username", ""),
                field("Password", "password", ""),
                field("IP address", "text", "203.0.113.10"),
                field("Operating system", "text", ""),
                field("Provider", "text", ""),
            ],
        ),
        template(
            "database",
            "Database",
            "login",
            vec![
                field("Connection address", "uri", "postgres://db.example.com:5432"),
                field("Username", "username", ""),
                field("Password", "password", ""),
                field("Engine", "text", "PostgreSQL, MySQL…"),
                field("Database name", "text", ""),
            ],
        ),
        template(
            "email",
            "Email account",
            "login",
            vec![
                field("Email address", "username", ""),
                field("Password", "password", ""),
                field("Webmail address", "uri", "https://mail.example.com"),
                field("IMAP server", "text", "imap.example.com:993"),
                field("SMTP server", "text", "smtp.example.com:465"),
                field("Recovery email", "text", ""),
            ],
        ),
        template(
            "license",
            "Software license",
            "note",
            vec![
                field("License key", "hidden", ""),
                field("Licensed to", "text", ""),
                field("Email", "text", ""),
                field("Version", "text", ""),
                field("Order number", "text", ""),
                field("Expires", "text", ""),
            ],
        ),
        template(
            "bank",
            "Financial account",
            "note",
            vec![
                field("Bank", "text", ""),
                field("Account holder", "text", ""),
                field("Account number", "hidden", ""),
                field("Routing or sort code", "text", ""),
                field("IBAN", "hidden", ""),
                field("SWIFT/BIC", "text", ""),
                field("PIN", "hidden", ""),
                field("Phone", "text", ""),
            ],
        ),
        template(
            "id-document",
            "Identification document",
            "identity",
            vec![
                field("Document type", "text", "Passport, driver's license, ID card"),
                field("First name", "identity.firstName", ""),
                field("Last name", "identity.lastName", ""),
                field("Passport number", "identity.passportNumber", ""),
                field("License number", "identity.licenseNumber", ""),
                field("Document number", "hidden", ""),
                field("Issuing country", "text", ""),
                field("Issued", "text", ""),
                field("Expires", "text", ""),
            ],
        ),
        template(
            "recovery-codes",
            "Recovery codes",
            "note",
            vec![field("Service", "text", ""), field("Generated on", "text", ""), field("Codes", "notes", "One code per line")],
        ),
        template("record", "Custom record", "note", vec![]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_templates_are_sound() {
        let all = builtin();
        let mut ids = std::collections::HashSet::new();
        for t in &all {
            assert_eq!(t.problem(), None, "{}", t.id);
            assert!(ids.insert(t.id.clone()) && !t.id.starts_with(CUSTOM_PREFIX), "{}", t.id);
        }
        let wifi = all.iter().find(|t| t.id == "wifi").unwrap();
        assert_eq!(wifi.label_for(Slot::Username), Some("Network name (SSID)"));
        assert_eq!(wifi.label_for(Slot::Totp), None);
        assert_eq!(wifi.custom_fields().collect::<Vec<_>>(), [("Security", 0), ("Hidden network", 2)]);
        let id = all.iter().find(|t| t.id == "id-document").unwrap();
        assert_eq!(id.label_for(Slot::Own("identity.passportNumber")), Some("Passport number"));
    }

    #[test]
    fn slots_follow_the_kind() {
        let f = field("User", "username", "");
        assert_eq!(f.slot("login"), Some(Slot::Username));
        assert_eq!(f.slot("note"), None);
        assert_eq!(field("N", "card.number", "").slot("card"), Some(Slot::Own("card.number")));
        assert_eq!(field("N", "card.number", "").slot("identity"), None);
        assert_eq!(field("Codes", "notes", "").slot("note"), Some(Slot::Notes));
        assert_eq!(field("X", "bogus", "").slot("note"), None);
    }

    #[test]
    fn custom_templates_are_checked() {
        let good = template("Gym", "Gym membership", "note", vec![field("Member number", "hidden", "")]);
        let file = TemplateFile {
            templates: vec![
                good.clone(),
                template("x", "Twice", "login", vec![field("A", "username", ""), field("B", "username", "")]),
                template("y", "Same label", "note", vec![field("A", "text", ""), field("a", "hidden", "")]),
                template("z", "Ours", "note", vec![field("nyx:template", "text", "")]),
                template("w", "Kind", "ssh", vec![]),
                template("v", " ", "note", vec![]),
                template("my-gym", "Gym again", "note", vec![]),
            ],
        };
        let usable = file.usable();
        assert_eq!(usable.len(), 1, "{usable:?}");
        assert_eq!(usable[0].id, "my-gym");
        assert_eq!(custom_id("  Gym — membership! "), "my-gym-membership");
        assert_eq!(custom_id("!!"), "my-template");
    }
}
