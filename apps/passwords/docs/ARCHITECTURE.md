# Nyx Passwords — architecture

Nyx Passwords is a desktop client for a self-hosted Vaultwarden server. It speaks the
Bitwarden client API, so the same account keeps working in the official Bitwarden apps,
the web vault and the `bw` CLI. There is no server component.

## Components

```
 nyx-passwords (GTK) ─┐
 nyx-glimpse          ─┤   peer-to-peer D-Bus over
 nyx-passwords-settings┼── $XDG_RUNTIME_DIR/nyx-passwords/bus ──┐
 nyx-passwords-bridge ─┘   (dir 0700, SO_PEERCRED, exe allowlist) │
   ▲ Native Messaging                                             ▼
 browser extension                                         nyx-passwordsd
                                                    ┌──────────┼───────────────┬───────────────┐
                                                    ▼          ▼               ▼               ▼
                                              Vaultwarden  vault.sqlite   Secret Service   Wayland
                                              (HTTPS)      (ciphertext)   (refresh token)  data-control
                                                                                           (clipboard)
```

| Process | Package / licence | Holds keys | Role |
| --- | --- | --- | --- |
| `nyx-passwordsd` | `apps/passwords`, GPL-3.0-only | yes, the only one | Session, sync, local store, lock state, search, clipboard owner, policy |
| `nyx-passwords` | `apps/passwords`, GPL-3.0-only | no | The window: login, unlock, browse, edit, settings |
| `nyx-passwords-settings` | `apps/passwords`, GPL-3.0-only | no | Settings extension helper (pages JSON) |
| `nyx-passwords-bridge` | `apps/passwords`, GPL-3.0-only | no | Native Messaging host: a relay between one browser connection and the daemon |
| Glimpse `pw` provider | `apps/glimpse`, MIT | no | Native provider in Glimpse; links only `nyx-passwords-proto` |

The daemon is the only process that derives keys, decrypts ciphers or touches the
clipboard with a secret. The others send requests and get back metadata or a result
("copied"). The one exception is the GTK app, which may receive a single field's
plaintext after a user action (reveal, edit).

## Workspace layout

```
crates/
  nyx-passwords-proto/      MIT. Interface name, object path, socket path, scopes,
                             wire types, error names. No crypto, no I/O beyond paths.
  nyx-passwords-core/       GPL-3.0-only. Everything that knows Bitwarden.
    src/secret.rs            Redacting newtypes (Debug/Display/Serialize never print).
    src/crypto.rs            The only module that names bitwarden-crypto types.
    src/api/                 identity (prelogin, token, refresh), api (sync, ciphers).
    src/model.rs             Encrypted wire models: Profile, Cipher, Folder, Collection,
                             Organization; unknown fields kept for round trips.
    src/store.rs             SQLite: the encrypted sync snapshot and account state.
    src/vault.rs             Decrypted in-memory view; search; dropped on lock.
    src/sync.rs              Full sync, revision checks, conflict reporting.
    src/totp.rs              otpauth:// and Steam parsing, code generation (totp-rs).
    src/generate.rs          Password and passphrase generation (thread CSPRNG, EFF word list).
    src/matching.rs          URI match rules (base domain via PSL, host, starts with,
                             exact, regex, never).
apps/passwords/
  src/main.rs                GTK app (nyx-passwords).
  src/bin/nyx-passwordsd.rs Daemon.
  src/bin/nyx-passwords-settings.rs
  src/bin/nyx-passwords-bridge.rs   (Phase 3)
  src/daemon/                server (p2p zbus), peers, policy, lock, clipboard, notify.
  src/ui/                    window, pages, item detail, unlock, settings_dialog.
  data/                      desktop file, systemd unit template.
  browser/                   (Phase 3) one WebExtension source, Firefox and Chromium manifests.
  docs/                      this folder.
```

`nyx-core` gets a default-on `gtk` feature. The daemon and the bridge use `app`,
`paths` and `cmd::atomic_write` with `default-features = false`. Existing apps don't
change.

## Data and storage

| What | Where | Form |
| --- | --- | --- |
| Account state: server URL, email, KDF parameters, the protected user key, private key, org keys | `~/.local/share/nyx-passwords/vault.sqlite` | As the server sends them: EncStrings, never decrypted on disk |
| Sync snapshot: ciphers, folders, collections, policies | same database | Raw server JSON per object, encrypted fields untouched |
| Refresh token | Secret Service (`application nyx-passwords server <url> account <email>`) | Through `secret-tool` stdin, as Git does |
| Access token | daemon memory | |
| Device identifier | `vault.sqlite` | A random UUID, created once per install |
| Preferences | `~/.config/nyx-passwords/settings.toml` | Written by the app (`prefs_store!`); the daemon reads it and reloads when its mtime changes |
| Custom templates | `~/.config/nyx-passwords/templates.toml` | Names, kinds and field labels only; written by the app |
| Recently used items | `vault.sqlite` (setting `recent`) | Up to 20 item ids, encrypted with the user key |
| Email alias service tokens | Secret Service (`nyx-passwords-forwarder-<service>`) | Through `secret-tool` stdin |
| Email aliases as last listed | daemon memory | Addresses and states, for the item view; dropped on lock |
| Decrypted fields, search index, keys | daemon memory only | Zeroized on lock |
| Site icons (opt-in, Phase 2) | `~/.cache/nyx-passwords/icons/` | PNGs from the server's icon service |

The database and its directory are created 0600/0700 under umask 077. SQLite runs with
`secure_delete=ON` and `journal_mode=WAL`. Because the snapshot is stored as the server
sent it, an offline unlock works the same way as an online one: KDF over the master
password, decrypt the user key, then decrypt items on demand.

## Flows

**Log in:**
1. `POST {server}/identity/accounts/prelogin {email}` returns the KDF and its parameters.
2. `crypto::master_key(password, email, kdf)` derives the master key, then
   `crypto::master_password_hash`.
3. `POST /identity/connect/token`: `grant_type=password`, `scope=api offline_access`,
   `client_id=desktop`, `deviceType=8` (Linux desktop), `deviceIdentifier`, `deviceName`.
4. A 400 with `TwoFactorProviders2` returns a 2FA challenge to the app. The request is
   then retried with `twoFactorToken` and `twoFactorProvider`.
5. The refresh token goes to Secret Service. The response's `Key` and `PrivateKey` go
   to the store.
6. Full sync, then unlocked.

The server and email are fixed per account. Only `https://` is accepted, except
`http://` on loopback addresses.

**Unlock:** master password → master key → decrypt the user key → decrypt the private
key and org keys → build the in-memory view. The view holds decrypted names, usernames,
URIs and folder names for search and listing. Passwords, TOTP seeds, notes, card
numbers and the like are decrypted per request and zeroized after use.

**Sync:** `GET /api/sync?excludeDomains=true` with the access token, which is refreshed
when it expires. The snapshot is replaced in one transaction. A failed sync keeps the
last good snapshot. Sync runs on unlock, on an interval (setting) and on demand.

**Edit:** the app sends the changed fields. The daemon encrypts them with the item's
key: the cipher's own key if it has one, otherwise the org key or user key. It then
sends `PUT /api/ciphers/{id}` with `lastKnownRevisionDate`. If the server rejects a
stale revision, the daemon refetches the item and reports a conflict to the app, which
shows both versions. Nothing is overwritten silently. Deleting moves the item to the
trash (`PUT /api/ciphers/{id}/delete`). Edits need a connection; offline edits wait for
a later phase.

**When the server disagrees:** a call about one item that fails (an edit, a move,
trash or restore, an attachment) asks the server for that item. If it comes back, its
latest copy replaces this one and the error stands (a conflict, for an edit made
elsewhere meanwhile). If the server refuses it, because it was deleted for good or the
account lost access, it leaves the local copy at once, store included, and the error
is `NotFound`. The window then reloads and says so. Vaultwarden answers 400, not 404,
for both.

**Rules for edits:**
- **New items:** created under the user key, without an item key of their own.
  Official clients don't create per-item keys against Vaultwarden either. Items that
  already have their own key keep it.
- **Changing a password:** the old one moves into the item's password history (newest
  first, at most five) and `passwordRevisionDate` is set.
- **Web addresses:** every one is saved with its encrypted checksum. An address that was
  already on the item keeps its match rule unless the draft sets one.

**Web addresses and Android apps:** a draft's `uris` are plain strings (the address
keeps the rule it had) or `{uri, match}` (the rule given; null is the default). An
Android app is the address `androidapp://<package>`, as the Bitwarden apps write it;
the daemon refuses one whose package name isn't valid. The window lists them apart from
web addresses and saves web addresses first. Matching, Glimpse and the extension never
treat them as web addresses.

**Passwords' own custom fields** (`proto::custom`): ordinary text or true-or-false
custom fields that the official clients show and keep. `nyx:sign-in-with` and
`nyx:no-fill-on-load` are for the extension; `nyx:template` names the item's template;
`nyx:alias` is `<service>:<id>`, the email alias its username is. The vault view reads
the last two for the listing; the window never shows them as fields.

**Templates** (`core/templates.rs`, `app/templates.rs`): a template is a kind of item
and an ordered list of fields, each kept in one of the item's own fields (a login's
username, password, code key, an address, the notes, or a card's or identity's field)
or in a custom field named after its label. Built-in templates are in the core; the
user's own are in `~/.config/nyx-passwords/templates.toml` (labels and types only). A
template only lays out the editor and the item view: the item is a standard one, and
without the marker it shows as its plain kind.

**Recently used:** the daemon keeps the last 20 item ids used (copied by any peer,
filled by a browser, opened in the window), encrypted with the user key in the store's
settings, so the list survives a restart. It's read on unlock, dropped on lock and
removed with everything else on sign-out.

**Email aliases** (`core/alias/`, `daemon/aliases.rs`): one `Account` per service, with
the user's token from the keyring. `Service::capabilities` says what each allows (make,
list, turn off or on, delete, self-hosted); the window shows only what the service
offers and names no service itself. The daemon keeps each service's last list in memory
for the item view (its status for five minutes), dropped on lock. Nothing is asked of a
service unless the user makes, lists, checks, turns off or deletes an alias.

**Nyx Online Accounts** (`daemon/online_accounts.rs`): the daemon reads `ListAccounts`
on the session bus (metadata only) to suggest Fastmail when an account is set up there.
Online Accounts keeps Fastmail as an app password for mail, calendars and contacts, so
masked email still needs a Fastmail API token of its own.

**Unlock with the keyring** (opt-in): the daemon saves the user key in Secret Service
(`application=nyx-passwords-unlock`, so a lookup for the session token can't find
it) and can then open the local copy with it. The key is checked against the account's
private key; one that no longer fits is removed. Signing out removes it. Fingerprint
unlock waits for hardware to test it on: it would gate this same key behind fprintd.

**Attachments:** each file has its own key, wrapped by the item's key, as the official
clients do. Adding one encrypts it (at most 100 MB, held in memory meanwhile), announces
it (`POST /api/ciphers/{id}/attachment/v2`) and uploads it to the server
(`application/octet-stream`; without a type Vaultwarden stores the file re-encoded).
Downloads follow the server's link only if it's on the same server. The window never
holds a decrypted file: it opens the file the user picked and passes the handle to
the daemon, which decrypts into it or encrypts from it. Saved files are created 0600,
and a failed save is removed.

**Organizations:** the server's permissions are enforced in the core, not only shown in
the app:
- **Read-only items** (`edit: false`, from a read-only collection) can't be changed;
  `permissions.delete`/`restore` decide the trash.
- **Hidden passwords** (`viewPassword: false`): the password, one-time code key, hidden
  custom fields and the secret fields of cards, identities and SSH keys can't be
  revealed or copied. Filling a page still uses the password, as the official extension
  does, and the current one-time code stays available. An edit keeps the hidden values
  as stored.
- **Placing items:** a new item goes into collections the account can write to
  (`POST /api/ciphers/create`), and an organization item changes collections the same
  way (`PUT /api/ciphers/{id}/collections_v2`). Items never leave their organization.
- **Moving a personal item in** (`PUT /api/ciphers/{id}/share`, one way): an item with
  its own key has that key rewrapped by the organization key. One without gets its own
  key, and every encrypted value is re-encrypted with it, including attachment keys
  (sent as `attachments2`). Attachments from before attachment keys can't be moved here.
- **What's sent back unchanged:** custom fields, passkeys, attachments and unknown fields.

**Copy (Glimpse or the app):**
1. The client sends `Copy(id, field)`.
2. The daemon checks the peer's scope and the lock state.
3. It decrypts the one field, offers it on the Wayland clipboard with the
   password-manager hint, and returns the clear-after time.
4. When that time is up, it clears the clipboard if the clipboard still holds the value.
5. A notification confirms the copy without showing the value.

**Lock:** after an inactivity timeout, logind `Lock`, `PrepareForSleep`, `pw lock`, the
app's lock button, or the daemon stopping. Locking drops the view and all keys, and
clears any clipboard value this daemon still owns.

## IPC

- **Vault traffic** goes over a peer-to-peer zbus connection on
  `$XDG_RUNTIME_DIR/nyx-passwords/bus`. There is no message bus in between, so
  `dbus-monitor` can't observe it.
  - Interface `io.github.design_nexus.nyx.Passwords1` at `/io/github/design_nexus/nyx/Passwords`.
  - Methods and scopes are in [GLIMPSE_API.md](GLIMPSE_API.md).
- **Peer identification:** SO_PEERCRED gives the peer's uid and pid. The uid must match
  the daemon's, and `/proc/<pid>/exe` must be a known binary. That fixes the peer's scope.
- **Session bus:** the daemon owns `io.github.design_nexus.nyx.Passwords` only for
  single-instance and activation. It emits `LockStateChanged(s)` with no vault data.
- **Native Messaging:** described in [NATIVE_MESSAGING.md](NATIVE_MESSAGING.md).

## Integrations

- **Glimpse (Phase 2):** a native provider in `apps/glimpse/src/passwords.rs`.
  - A `pw`/`password` prefix takes the query away from every other provider, including
    plugins and semantic search.
  - Talks to the daemon over the socket with gio (`DBusConnection::new_for_address`).
  - The full spec is in [GLIMPSE_API.md](GLIMPSE_API.md).
- **Settings:** an extension helper installed like Glimpse's (`install.sh` writes
  `extension.toml`). Category `Accounts`. Pages: server, sync, lock timeout, clipboard
  timeout, browser pairing, Glimpse, notifications.
- **Assistant:** the `passwords` ability (`apps/assistant/abilities/passwords`) runs
  `nyx-passwords-assistant`, an MCP server on stdio that is a daemon peer of its own
  (`assistant` scope: status, search, copy, generate, security summary).
  `passwords.find` returns metadata; `passwords.copy` and `passwords.generate` return
  only that they copied; `passwords.security_summary` returns counts;
  `passwords.open` starts the window with `--item <id>` (checked to be an id). All are
  `assistant-policy`'s `Secrets` capability: always asked, by key press, one call at a
  time. The daemon refuses the peer
  unless `assistant = true` (off by default). The ability is unconfined so it can reach
  the socket, which only the suite's own executables pass.
- **Clipboard:** the daemon owns sensitive copies. Limits are in
  [SECURITY.md](SECURITY.md#clipboard).
- **Approvals** (`daemon/approvals.rs`, `app/approve.rs`): requests from other programs
  wait in one queue in the daemon, which starts `nyx-passwords --approve`; that opens
  only the approval card (no main window), which polls `Approvals` and calls `Answer`.
- **SSH agent** (`core/ssh_agent.rs` for the protocol, `core/ssh.rs` for signing,
  `daemon/ssh_agent.rs` for the socket): `ssh-agent.sock` beside the bus socket, bound
  at start; it lists and signs only while "SSH agent" is on and the vault is open.
- **Travel Mode** (`core/travel.rs`): a flag in the store's `meta` table; the core's
  sync, sign-in and edit paths drop `nyx:travel` items while it's on.
- **Other Nyx apps** (`daemon/grants.rs`): `nyx-*` programs beside the daemon connect
  as `Scope::Requester` and get only what a grant allows. Grants and the activity log
  are store settings encrypted with the user key.
- **Nyx Settings** (`nyx-passwords-settings`): also Browsers, SSH agent, Email aliases
  (the username generator's settings, never tokens) and Templates (names); buttons open
  the window where the rest is done.

## Processes and lifetime

`nyx-passwordsd` runs as a systemd user service (`PartOf=graphical-session.target`,
`UMask=0077`, `Restart=on-failure`), with a `flock` on its runtime directory against a
second instance. The app, Glimpse and the bridge start it with
`systemctl --user start nyx-passwords.service` when the socket is missing. The service
has no `ExecStart` arguments carrying data.

An update replaces the binary but leaves a running daemon alone, since restarting locks
the vault. The daemon notices the new file (its inode changed). Once the vault is locked,
it exits with status 75 and the unit starts it again (`RestartForceExitStatus=75`).
While the vault is open, the window asks `Outdated` and offers "Restart", which calls
`Restart` (app scope only). A daemon too old to know `Outdated` counts as outdated, and
the window restarts it through its unit.
