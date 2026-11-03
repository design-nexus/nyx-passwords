# Nyx Passwords — security

This file is the threat model and the rules every change has to keep. If a change
can't meet a rule, the change waits; the rule doesn't bend.

## Assets

| Asset | Where it may exist |
| --- | --- |
| Master password | The app's password entry, then the daemon for the length of one KDF call |
| Master key, user key, private key, org keys, cipher keys | Daemon memory while unlocked |
| Decrypted secret fields (passwords, TOTP seeds, notes, card numbers, SSH keys) | Daemon memory for one request; the app for one reveal or edit; the clipboard after a copy |
| Decrypted attachments | Daemon memory for one download or upload; then only the file the user chose (0600). Never the app, never a temporary file |
| Decrypted metadata (names, usernames, URIs, folder names) | Daemon memory while unlocked; shown in the app and in Glimpse results |
| Access token | Daemon memory |
| Refresh token | Secret Service |
| User key | Secret Service, only while "Unlock with the keyring" is on (off by default). Then anyone who can use the logged-in session, including programs running as the user, can open the vault; the setting says so |
| User key, sealed | Nyx Biometrics' key service (`nyx-auth-keyd`, root), sealed to this computer's TPM, only while unlocking with the face is on (off by default). Released to the daemon only after the person confirms it's them; never stored in the session (below) |
| A grantor's vault (emergency access) | Daemon memory while it's open for viewing, dropped on lock; their user key arrives encrypted for this account's public key |
| Encrypted snapshot | `vault.sqlite` (0600), the same ciphertext the server keeps |

Metadata counts as sensitive. It isn't a secret like a password, but it is never
written to disk decrypted, logged, or sent to anything but the app, Glimpse and a
paired browser asking about its own origin.

## Adversaries and what is done about each

| Adversary | In scope | Measures |
| --- | --- | --- |
| Someone who gets the disk (theft, backup, a shared machine) | Yes | Only ciphertext and a refresh token in a keyring are stored. A refresh token alone can't decrypt anything. Unlocking needs the master password, or the face on this computer: the sealed key opens only with its own TPM. |
| Network attacker | Yes | rustls with system roots. `http://` only on loopback. No certificate-pinning bypass and no "ignore errors" switch. |
| Malicious or compromised web page | Yes | The origin comes from browser tab APIs, not from the page. Base-domain matching uses the PSL. A fill is a user's click or shortcut, or the narrow page-load fill below. No fill into cross-origin frames unless their site matches. One item per request. The page can't read or press the extension's menu, bar or passkey window. |
| A malicious extension or a process pretending to be the extension | Yes | Pairing is confirmed by the user in the desktop app. Every message is authenticated with the pairing key, carries a counter (no replays) and is scoped to its origin. |
| An unrelated app on the session bus | Yes | Vault traffic never goes on the session bus. The socket checks the uid and the executable, and each peer gets a fixed scope. |
| A malicious process running as the same user | **Partly** | See below. |
| A malicious Vaultwarden server | Partly | Server data is parsed strictly with size limits and fuzzing (Phase 5). A server can still withhold or replay data. Detecting a key swap is the official clients' scheme and isn't extended here. |
| root, kernel, firmware, or a key logger in the compositor | No | Out of scope. |

### Same-user processes

On a Linux desktop any process running as the user can read the user's files, run
the user's binaries and talk to the compositor. No password manager fully defends
against that. What Nyx Passwords does:

- The daemon calls `prctl(PR_SET_DUMPABLE, 0)` and sets `RLIMIT_CORE` to 0: no core
  dumps, and with Yama `ptrace_scope ≥ 1` no ptrace by other user processes.
- **Memory:** it doesn't lock its memory against swap. The default `RLIMIT_MEMLOCK`
  (8 MiB) would make `mlockall` fail allocations. What it relies on instead:
  - bitwarden-crypto zeroizes key material;
  - bitwarden-crypto's global allocator, installed in every binary that links it,
    zeroes all freed memory, including D-Bus messages and JSON that carried a secret;
  - decrypted values in the core are zeroizing `Secret`s.

  Encrypted swap (or none) protects the rest.
- **Peer checks:** the socket refuses any executable that isn't one of the suite's,
  installed next to the daemon. The peer is pinned by pidfd (`SO_PEERPIDFD`), so a
  process that exits and has its pid reused can't pass the executable check.
- **What peer checks can't stop:** a same-user process can still run one of those
  executables, or connect and then `exec` one. So each executable's scope also limits
  what it can ask for:
  - Glimpse can search metadata and ask for copies, but can't read a secret back or
    reveal anything.
  - The Assistant's helper can do about the same: search, copy and generate (onto the
    clipboard, never back), plus the security report as counts only, and open a login
    in the window; no suggestions or site addresses. Only while its setting is on, and
    the assistant asks for a key press before each call.
  - Only the app can reveal a field.
- Rate limits on copy and reveal, plus a notification for each copy, make silent bulk
  extraction visible.
- An attacker with the user's access can read the clipboard after a copy. That is the
  clipboard's nature (below).

### Nyx Biometrics: the face, and confirming it's you

Where Nyx Biometrics is installed, the person can unlock with the face and confirm
some actions without the master password. Passwords never sees a face, a fingerprint
or a key's answer; it asks Nyx Biometrics, which shows the system's prompt (polkit,
answered by whatever the computer is set up with) and says yes or no.

- **Unlocking with the face** (`face_unlock.rs`): turning it on needs the master
  password confirmed just before, and the prompt. The daemon then hands the user key
  to the key service, which seals it to the TPM. Each unlock asks the key service,
  which shows the prompt before it hands the key back; the daemon opens the vault with
  it and keeps nothing. Only the window, and Glimpse while its integration is on, may
  start it. A key that no longer fits (rotated keys) is cleared; signing out clears
  it too.
- **It isn't the master password.** A face unlock opens the vault but doesn't count as
  confirming the master password: exporting, turning Travel Mode off, turning on
  keyring or face unlock, and items that ask for the master password again still ask
  for it in the window.
- **Confirming with the sign-in broker** (`sign_in.rs`, `nyx-authd`): Glimpse copying
  from an item that asks for the master password again (opt-in), and a passkey for a
  site that requires user verification, ask the broker under the `vault` policy. The
  broker is used only if the session-bus name belongs to the installed `nyx-authd`;
  otherwise the daemon asks polkit directly, a system service.
- **Limits:**
  - The prompt shows polkit's fixed message ("Confirm it's you to allow this"), not
    what's asked; the window says what it's for.
  - With hands-free face at administrator prompts, a program running as the user that
    can start the daemon gets the vault opened if the user is in view when it asks.
    The prompt is on screen each time.
  - The key service hands the key to a program by its name, `nyx-passwordsd`, and
    doesn't yet check where it's installed (the broker does). Until it does, any
    program running as the user could ask for the sealed key under that name and get
    it when the prompt passes. Tracked in Nyx Biometrics.

### Where the daemon connects

- **Your Vaultwarden server:** everything vault-related.
- **Have I Been Pwned** (`api.pwnedpasswords.com`): only when you press "Check for
  breaches…" in the Security section and confirm. It gets the first five hex
  characters of each password's SHA-1 hash, one request per distinct prefix, with
  padding on; the answer is matched here. Never automatic.

- **Your server's notification hub** (`/notifications/hub`): while the vault is open
  and live sync is on, a WebSocket with the access token. It hears only "something
  changed" (ids and dates); the daemon then syncs as usual.
- **Your server's icon service** (`/icons/<host>/icon.png`): only with website icons
  turned on. The server learns each login's host and fetches the icon from that site.
  Icons stay in daemon memory until the vault locks; none are written to disk.

- **An email alias service** (SimpleLogin, addy.io, Firefox Relay, DuckDuckGo,
  Fastmail, Forward Email, Cloudflare Email Routing): only when you generate a username
  with it, or list, check, turn off or delete its aliases. It gets your API token and,
  for a new alias, the site's name. The token stays in the desktop keyring and never
  leaves the daemon; the window gets addresses and states. Alias ids are checked before
  they go into a request's path. A paired browser may ask for at most five usernames a
  minute, since each may make a real alias.
- **Nyx Online Accounts** (session bus): `ListAccounts`, which holds no secrets, when
  the window lists the alias services, to suggest Fastmail.
- **2fa.directory** (`api.2fa.directory/v3/totp.json`): only when you press "Check
  two-step login" in the Security section and confirm. The whole public list is
  downloaded (about 300 KB, at most 8 MB read) and matched here; nothing about the
  vault is sent. It's kept in daemon memory until the vault locks.
- **NetworkManager** (system bus): only when you press "Import…" for Wi-Fi networks
  in Settings → Import and export. Listing reads the saved connections' settings,
  which hold no passwords; the window gets names, SSIDs and security types. On
  import the daemon asks NetworkManager for each chosen network's password
  (`GetSecrets`, allowed by polkit for an admin user at the computer) and saves it
  straight into a new item; it never reaches the window. Open and enterprise networks,
  and networks whose password another program keeps, are skipped. At most 500
  connections are read, with each value's length capped.

The security report itself (weak, reused, old; `http://` addresses, duplicates,
incomplete records) is worked out in daemon memory. Its strength cache keeps only item
ids, revisions and a weak/not-weak flag, and is dropped on lock. A breach is reported as
verified; everything else is labelled advice.

### Other programs using the vault

All three follow one pattern: the program asks, the daemon opens the window's approval
card (`nyx-passwords --approve`), and only the app's scope can see or answer what's
waiting. Deny is focused first; Escape and closing the card deny. Unanswered requests
are refused after a minute, at most four wait at once, and locking refuses them all.
Each use goes into the activity log.

- **SSH agent** (off by default; `$XDG_RUNTIME_DIR/nyx-passwords/ssh-agent.sock`, 0600 in
  the 0700 directory, peers of another uid ignored):
  - offers only SSH key items turned on for it (that list encrypted with the user key),
    only while the vault is open, never keys that ask for the master password or that
    an organization hides;
  - each signature needs approval, once or until the vault locks, for that key and
    that program (by its real path); a use allowed without asking still shows a
    notification;
  - private keys stay in the daemon; adding, removing and locking keys and every other
    agent request are refused; RSA signs with SHA-2 only; requests are size-limited and
    the parser is fuzzed;
  - the card shows the program's command line as the kernel reports it: a process can
    write its own command line, so the path (`Program:`) is the trustworthy part.
- **Other Nyx apps** (`Scope::Requester`: a `nyx-*` program beside the daemon):
  - nothing until the user grants it `search` (names, usernames, sites) and/or `copy`
    (to the clipboard, never back), for at most a week, optionally asking before each
    copy;
  - grants are kept encrypted with the user key, so editing a file can't make one;
    revoked in Settings → App access; 10 copies a minute per app; items that ask for
    the master password are refused;
  - the app's own words ("reason") are shown as its words, cut to 200 characters.
- **Activity log:** who (program or app), what (copy, sign, request, revoke), the item's
  id and the outcome, never a value or an item's name; the last 500 events, encrypted
  with the user key, removed on sign-out.

### Travel Mode

Items marked travel-sensitive (`nyx:travel`) leave this device when Travel Mode is
turned on: their rows are deleted from `vault.sqlite` (with `secure_delete`) and the
file is rewritten (`VACUUM`); every later sync, sign-in and saved edit drops them before
anything is stored or shown. Turning it off needs the master password confirmed just
before and the server; the sync brings them back, and if it fails the mode stays on.

What it doesn't do, and the app says so before turning it on: the server, the web
vault and other devices keep the items; anyone with the master password and the
server's address can sync them again; and an SSD may keep old blocks of the file.

### Browser extensions

- **Pairing:** an extension pairs only after the user compares a code in the
  extension with the one the Passwords window shows, and confirms there.
- **Where the key lives:**
  - The extension keeps the pairing key in the browser's extension storage. Another
    process running as the user can read it there, which is the same limit as above.
  - The daemon keeps it encrypted under the user key, so a locked vault answers no
    one.
- **What a request can get:**
  - only items whose web address matches the tab's URL under its rule (or a login
    the user picked from the whole vault in the popup and confirmed for this page
    after a warning);
  - only for a frame on the same base domain;
  - nothing for a plain-`http` page unless the address says `http://`, and cards
    only on https;
  - nothing from an item that asks for the master password again;
  - from the popup's search: names, usernames and hosts, no secrets. A popup copy
    goes through the daemon's clipboard, so the value never enters the browser.
- **Filling as the page loads:** on by default, off in the app's settings (the daemon
  enforces it) or the extension's. Only on https, into the top frame or a same-site
  frame, for a login whose address names this very host, with one such login (or the
  one last used), never a re-prompting login or one marked not to, and only into
  empty visible fields. A page can still make the fields its own (that's how it
  learns a filled password anyway); the narrow host rule stops a page on another
  subdomain from collecting it.
- **The extension's own pages:** the menu under a field and the save bar are
  extension pages in frames inside a closed shadow root; the passkey prompt is its own
  window. The page can't read them or click them. Each acts only for the tab and
  frame it was opened for, under a random token.
- **Passkeys** (off by default, on in both the app and the extension): the extension
  builds the signed client data from the frame's origin as the browser reports it,
  never the page's word; the relying-party id must be the page's host or a registrable
  domain above it; every use and every new passkey is confirmed in the extension's
  window. Private keys stay in the daemon.
- **Save prompts:** the never-save list is kept encrypted with the user key. The save
  bar asks only after the daemon says the login is new or changed; a password typed
  into a page reaches the daemon only when the user clicks Save.
- **Rate:** at most 30 fills, copies and changes a minute per pairing.
- **Where the URL comes from:** the browser's tab API, never page content. The fill
  re-checks the page's origin before typing anything, so a tab that navigated after
  the request gets nothing.
- **The bridge:** it relays sealed frames and can't read them. The daemon serves it
  only when a browser started it.

## Rules for code

1. **No custom cryptography.** Every KDF, cipher, MAC, hash and key-wrap call goes
   through `nyx-passwords-core/src/crypto.rs`, and that module only calls
   bitwarden-crypto (and, for native messaging, RustCrypto's `x25519-dalek`, `hkdf` and
   `aes-gcm`; for the security report, `sha2` and `sha1`). No other module names a
   primitive. The one exception is `ssh.rs`, which uses RustCrypto's `ssh-key` for SSH
   key items: generating Ed25519 keys, reading OpenSSH files, and signing for the SSH
   agent; nothing the vault's own encryption depends on.
2. **No plaintext on disk.** No decrypted field in SQLite, settings, caches, temp files
   or the plugin storage of any app. A test plants a canary password, runs a sync,
   copy, edit and lock, then scans every file under the app's directories for it.
3. **No secrets in logs, errors, panics or telemetry.** Secret values use the types in
   `secret.rs`, whose `Debug`/`Display` print `[redacted]` and which don't implement
   `Serialize`. Errors carry kinds, not values. There is no telemetry. Logging is off
   by default and never includes metadata.
4. **No secrets in argv, environment or D-Bus signals.** `secret-tool` gets the token on
   stdin. The clipboard is served in-process. Notifications never contain the value.
5. **No general retrieval API.** No method returns a password, TOTP seed, note or card
   number to anything but the app. Glimpse's, the Assistant's and other apps' copy
   calls return only "copied"; the SSH agent returns signatures, never keys.
6. **No indexing of secrets.** Search covers names, usernames, URIs, folder and
   collection names, in memory. Glimpse holds results for the panel's lifetime and
   writes nothing.
7. **Lock drops everything.** Every type holding decrypted data lives under the vault
   view. Locking drops it, and a test checks the view is empty afterwards.
8. **Strict input.** Every length-prefixed or JSON input has a size limit. Unknown
   cipher fields are kept for round trips but never interpreted.

## Clipboard

Copies are served by the daemon through the Wayland data-control protocol
(`wl-clipboard-rs`). Hyprland supports this.

- **Hint:** each copy offers the text types plus `x-kde-passwordManagerHint` = `secret`.
  - wl-clipboard ≥ 2.3 sets `CLIPBOARD_STATE=sensitive` for watchers, and KDE's Klipper
    reads the hint directly. Which history managers skip such entries (cliphist and
    Omarchy's own among them) is checked in Phase 2 and listed here.
  - Managers that ignore it **will store the password in their history.** The Settings
    page names the manager it finds and says whether it is known to honor the hint.
- **Clearing:** after the timeout (setting, default 30 s) the daemon reads the current
  selection.
  - If it still holds the copied value (compared in constant time), the daemon clears it.
  - If something else was copied since, it is left alone.
  - A manager that took over the selection or saved a copy is beyond reach. Clearing
    is best effort.
- **Checked on Omarchy (2026-10-19):** a copy offers `TEXT`, `text/plain;charset=utf-8`,
  `text/plain`, `UTF8_STRING`, `STRING` and `x-kde-passwordManagerHint`, and is cleared
  after the set time. No clipboard history manager was running.
- **Paste once (setting):** serve one paste and then clear.
- **Primary selection** is never used.
- Any client with data-control access can read the clipboard while it holds the value.
- If the compositor has no data-control protocol, copying fails with a clear error. It
  never falls back to a visible window or `wl-copy` with argv.

## Supply chain

- `bitwarden-crypto` is pinned (`=4.0.0`). Upgrades are
  deliberate, read and tested against the local Vaultwarden.
- `cargo deny` (licences, advisories, duplicate and banned crates) runs in CI on every
  pull request and release (`tools/ci.py`), with clippy at `-D warnings`. Allowed
  licences: MIT, Apache-2.0, BSD, ISC, Zlib, Unicode, MPL-2.0, GPL-3.0-only.
- The browser extension has no runtime npm dependencies. Build tooling is pinned by
  lockfile.

## Reviews

Each review checks the code against this file rule by rule and records what it found
and changed in [REVIEW.md](REVIEW.md).

## Reporting

Report vulnerabilities privately through GitHub security advisories on
`design-nexus/nyx`, not in public issues.
