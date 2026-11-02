//! Travel Mode: items marked travel-sensitive (a `nyx:travel` true-or-false custom
//! field, synced like any other) are kept off this device while it's on. Turning it on
//! removes them from the local copy and memory; every sync, sign-in and saved edit
//! drops them before anything is stored. Turning it off (master password, then a sync)
//! brings them back from the server.
//!
//! What it doesn't do: the server, the web vault and other devices still have the
//! items, and anyone with the master password and the server's address can sync them
//! again. Removed rows are overwritten and the file rewritten, but an SSD may keep old
//! blocks. See docs/SECURITY.md.

use crate::crypto::Keys;
use crate::model::{Cipher, Sync};
use crate::session::{Result, Session};
use crate::store::Store;

const MARKER: &str = nyx_passwords_proto::custom::TRAVEL;

/// Whether an item is marked travel-sensitive. One whose fields can't be read counts as
/// marked, so a key problem never leaves a sensitive item behind.
pub fn marked(keys: &Keys, c: &Cipher) -> bool {
    let Some(fields) = c.fields.as_ref().filter(|f| !f.is_empty()) else { return false };
    let Ok(mut key) = keys.item(c.organization_id, c.key.as_deref()) else { return true };
    fields.iter().any(|f| {
        key.decrypt_opt(f.name.as_deref()).ok().flatten().is_some_and(|n| n.expose() == MARKER)
            && key.decrypt_opt(f.value.as_deref()).ok().flatten().is_some_and(|v| v.expose().trim() == "true")
    })
}

/// Drops marked items from a sync response, when Travel Mode is on.
pub fn filter(store: &Store, keys: &Keys, sync: &mut Sync) -> Result<()> {
    if store.travel()? {
        sync.ciphers.retain(|c| !marked(keys, c));
    }
    Ok(())
}

impl Session {
    /// The marked items this copy holds.
    pub fn travel_marked(&self) -> usize {
        self.snapshot.ciphers.iter().filter(|c| marked(&self.keys, c)).count()
    }

    /// Turns Travel Mode on: marked items leave the store, the snapshot and the view at
    /// once, and the file is rewritten. Returns how many left.
    pub fn enter_travel(&mut self, store: &mut Store) -> Result<usize> {
        store.set_travel(true)?;
        let gone: Vec<_> = self.snapshot.ciphers.iter().filter(|c| marked(&self.keys, c)).map(|c| c.id).collect();
        for id in &gone {
            store.remove_cipher(*id)?;
            self.view.remove(*id);
        }
        self.snapshot.ciphers.retain(|c| !gone.contains(&c.id));
        store.compact()?;
        Ok(gone.len())
    }
}
