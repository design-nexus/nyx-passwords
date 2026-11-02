//! Unlocking with the face (or another sign-in method) through Nyx Biometrics' key service.
//!
//! The user key is sealed to the TPM by a root service that hands it back only after polkit
//! has confirmed the person in front of the screen; nothing that unlocks is kept in the
//! session. A successful face match is never the key itself.

use nyx_auth_proto::keyd::{self, Request};
use nyx_passwords_core::secret::Secret;
use sha2::{Digest, Sha256};

/// One account's sealed key.
pub struct Entry {
    name: String,
}

impl Entry {
    pub fn new(server: &str, email: &str) -> Self {
        let digest = Sha256::digest(format!("{server}\0{email}").as_bytes());
        let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
        Self { name: format!("vault-{hex}") }
    }

    /// Whether the key service is installed at all.
    pub fn available() -> bool {
        std::path::Path::new(keyd::SOCKET).exists()
    }

    pub fn exists(&self) -> Result<bool, String> {
        let r = call(&Request::Exists { name: self.name.clone() })?;
        Ok(r.exists.unwrap_or(false))
    }

    /// Seals the key. Asks the person to confirm it's them first.
    pub fn store(&self, key: &Secret) -> Result<(), String> {
        call(&Request::Store { name: self.name.clone(), secret: key.expose().to_string() }).map(|_| ())
    }

    /// Asks the person to confirm it's them, then returns the key; `None` when there's none.
    pub fn load(&self) -> Result<Option<Secret>, String> {
        match call(&Request::Load { name: self.name.clone(), purpose: "Unlock Nyx Passwords".into() }) {
            Ok(r) => Ok(r.secret.map(Secret::new)),
            Err(e) if e == NOT_FOUND => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn clear(&self) -> Result<(), String> {
        call(&Request::Clear { name: self.name.clone() }).map(|_| ())
    }
}

const NOT_FOUND: &str = "not-found";

fn call(request: &Request) -> Result<keyd::Reply, String> {
    if !Entry::available() {
        return Err("Nyx Biometrics isn't set up on this computer".into());
    }
    let reply = keyd::call(request).map_err(|e| format!("the key service didn't answer: {e}"))?;
    if reply.ok {
        return Ok(reply);
    }
    Err(match reply.error.as_deref() {
        Some("not-found") => NOT_FOUND.into(),
        Some("denied") => "not confirmed".into(),
        _ => reply.message.unwrap_or_else(|| "the key service refused".into()),
    })
}

#[cfg(test)]
mod tests {
    use super::Entry;

    #[test]
    fn names_are_stable_per_account_and_valid() {
        let a = Entry::new("https://vault.example", "ken@example.com");
        assert_eq!(a.name, Entry::new("https://vault.example", "ken@example.com").name);
        assert_ne!(a.name, Entry::new("https://vault.example", "other@example.com").name);
        assert!(nyx_auth_proto::keyd::valid_name(&a.name), "{}", a.name);
    }
}
