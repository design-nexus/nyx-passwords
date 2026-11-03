# Nyx Passwords — audit (2026-11-01)

What the app does today against the full brief for Nyx Passwords (Vaultwarden backend,
Bitwarden-compatible, native Nyx desktop experience), what is missing, and in what order
the rest gets built. Design: [ARCHITECTURE.md](ARCHITECTURE.md). Rules:
[SECURITY.md](SECURITY.md). Progress: [TASKS.md](TASKS.md).

## Decisions behind this audit

- **One backend.** Vaultwarden, over the Bitwarden client API. No server component, no
  item database of our own, no other storage format.
- **Android:** the official Bitwarden Android app against the same Vaultwarden. No Nyx
  Android app unless that ever becomes necessary. Nyx Passwords edits the associations
  Bitwarden Android uses ([ANDROID.md](ANDROID.md)).
- **Browsers:** the Nyx extension (`browser/`) is the one to use and keeps being built.
  The official Bitwarden extension still works against the same server; nothing here
  gets in its way.
- **Biometrics and security-key unlock** come last, built on the shared Nyx Biometrics
  service once it exists, rather than a backend of our own.
- **SSH agent:** the daemon will serve its own agent socket, so private keys never leave
  it.

## Implementation matrix

Verdicts: **done** (built and tested), **partial**, **missing**, **deferred** (left out
on purpose, with the reason).

### Core

| Feature | Verdict | Where / notes |
| --- | --- | --- |
| Vaultwarden sign-in (PBKDF2, Argon2id, KDF limits and downgrade refusal) | done | `core/session.rs`, `core/crypto.rs`; live `tests/session.rs` |
| Two-step login: authenticator, email, YubiKey OTP, recovery code; device approval; API key | done | `core/api.rs`, `app/account.rs`; `tests/signin.rs` |
| Two-step login: FIDO2, Duo, SSO | missing | Needs hardware, a Duo account, an IdP to test against |
| Encrypted local cache, offline unlock and read | done | `core/store.rs` (ciphertext only, 0600, `secure_delete`) |
| Sync: on unlock, interval, manual, live (notification hub) | done | `daemon/vault.rs`, `core/live.rs` |
| Logins, notes, cards, identities, SSH keys | done | `core/edit.rs`, `app/editor.rs`, `app/detail.rs` |
| Folders, organizations, collections, permissions | done | Enforced in the core; live owner-and-member test |
| Password and passphrase generator | done | `core/generate.rs` |
| Passkeys (made and used by the extension, Bitwarden's storage format) | done | `core/passkey.rs`, [PASSKEYS.md](PASSKEYS.md) |
| TOTP | done | `core/totp.rs` (RFC 6238 vectors, Steam) |
| Search (metadata only, in memory) | done | `core/vault.rs` |
| Favorites | done | |
| Recently used | done (this pass) | Last 20 items copied, filled or opened, encrypted with the user key beside the vault; Recent section; dropped on lock. Was memory-only, not shown, not cleared on lock |
| Clipboard: daemon-owned, sensitive hint, timed clear, paste once | done | `daemon/clipboard.rs` |
| Auto-lock: timer, screen lock, sleep, stop | done | Screen-lock and sleep paths not yet tried on the desktop |
| Master-password re-prompt for chosen items and sensitive actions | done | `Reprompt`, `VerifyPassword` (5-minute grace) |
| Import and export | done | Bitwarden JSON/CSV (plain, password-protected, account), 1Password, Chrome, Firefox, KeePassXC |
| Attachments | done | Daemon writes through a handle the window passes |
| Emergency access | done | Takeover not offered |
| Multiple accounts | deferred | `store.rs` holds one account (`CHECK (id = 1)`); the daemon holds one session. Needs a schema migration and per-account sessions everywhere |
| Offline edits | deferred | Edits are refused offline (`Unreachable`) and change nothing locally. Queuing them would need conflict handling against edits made elsewhere; refusing is the safe behaviour |

### Brief items beyond the core

| Feature | Verdict | Where / notes |
| --- | --- | --- |
| SSH key items kept by a full sync | fixed (Phase 5) | Vaultwarden leaves type-5 items out of `/api/sync` for clients without `Bitwarden-Client-Version` ≥ 2024.12.0; the header is now sent |
| Login addresses with match rules | done (this pass) | One row per address with its rule; a rule set elsewhere survives edits here. Was one text box that reset rules when an address changed |
| Android app associations (`androidapp://`) | done (this pass) | Package-name rows, validated; their own section in the item view; round trip with `bw`. Checking with Bitwarden Android on a device is open |
| Rich templates and custom templates | done (this pass) | Eleven built-in, custom ones in Settings; standard items with named custom fields and a `nyx:template` marker |
| Email aliases: create | done | SimpleLogin, addy.io, Firefox Relay, DuckDuckGo, Fastmail, Forward Email, and now Cloudflare Email Routing; tokens in the keyring |
| Email aliases: list, disable, delete, link to logins, provider status | done (this pass) | One interface with capabilities (`core/alias/providers.rs`); Email aliases page; `nyx:alias` link and status in the item view. Tested against stand-ins, not yet real accounts |
| Nyx Online Accounts | partial (this pass) | A Fastmail account there makes Fastmail the suggested service. Shared authorization needs an OAuth Fastmail provider with the Masked Email scope in `nyx-accounts` |
| Fingerprint, face, FIDO2 unlock | missing | Keyring unlock (opt-in) exists. Waits for Nyx Biometrics |
| SSH keys (generate, import, passphrase) | done | `core/ssh.rs` |
| SSH agent | done (Phase 5) | The daemon's own socket; per-key opt-in; approval once or until locked; Ed25519, ECDSA, RSA (SHA-2); tested with real `ssh-add` and `ssh-keygen -Y sign` |
| Security report: weak, reused, old, breach check (k-anonymity) | done | `core/audit.rs`, `app/security.rs` |
| Security report: missing 2FA, duplicates, `http://` addresses, incomplete records, remediation | done (Phase 5) | 2fa.directory downloaded whole on request; breaches marked verified, the rest advice; fixes from the item view (new password, https, code key, show duplicates, edit) |
| Travel Mode | done (Phase 5) | `nyx:travel` items purged locally and kept out of syncs; off needs the master password and the server; limits stated before turning on |
| Glimpse `pw` | done | `nyx-glimpse/apps/glimpse/src/pw.rs`; `pw aliases` added (this pass); pins an older proto (`f30ea28`), still compatible |
| Assistant (`find`, `copy`, `generate`, `security_summary`, `open`) | done | The last three added this pass. Never returns secrets; `Secrets` capability asks per call |
| Grant-based API for trusted apps (approval, expiry, revocation, audit log) | done (Phase 5) | `nyx-*` apps ask; search and copy only, at most a week, optionally per copy; grants and an activity log encrypted with the user key; Settings → App access |
| Browser extension: fill, save, update, TOTP, generate, passkeys, lock and unlock | done | Hands-on runs in Zen, Chromium and Brave still open |
| Nyx Settings | done | `nyx-passwords-settings` (vault, locking, clipboard, sync, Glimpse, Assistant; browsers, email aliases and templates added this pass) |
| Nyx Design 2.0 | done | `style.css` uses tokens only, no blur or glass. The extension's `theme.css` keeps hex fallbacks until the app's theme arrives (by design) |

### Assurance

| Item | Verdict |
| --- | --- |
| Threat model and rules | done ([SECURITY.md](SECURITY.md)) |
| Review against the code | done ([REVIEW.md](REVIEW.md), 2026-10-20) |
| Fuzzing (sync, EncString, pairing, TOTP, matching, SSH) | done |
| Offline and conflict matrix | done (`tests/matrix.rs`) |
| Live compatibility with `bw` | done (`tests/edit.rs`, `tests/transfer.rs`, `tests/passkeys.rs`) |
| `cargo deny`, clippy in CI | done (this pass) |
| Web vault check by hand, extension in every browser | open (needs hands) |

## Security findings

| Finding | Severity | Action |
| --- | --- | --- |
| The browser's `GenerateUsername` has no rate limit, and with an alias service each call makes a real alias at the provider | low | Fixed: at most 5 a minute per pairing |
| Self-hosted service addresses (`service_url`) were applied to every alias service, so a token for one service could be sent to another's address | low | Fixed: only services that can be self-hosted (SimpleLogin, addy.io) use it |
| Fastmail masked email was created with "Made by Nyx Passwords" as its description, against Fastmail's guidance (the description is the user's; the site goes in `forDomain`) | none | Fixed |
| Test copies' dialogs took the real program name as their window class, so layout checks could open them on the real desktop | process | Fixed: `NYX_PASSWORDS_APP_ID` also sets the program name |
| SSH key items disappeared from Passwords after any full sync or fresh sign-in (Vaultwarden's version gate) | medium | Fixed: `Bitwarden-Client-Version` sent with the sync; live test syncs after creating one |
| A layout check ran the scratch daemon on a private session bus, which started gnome-keyring and showed its "new keyring" prompt on the desktop; `--include-ignored` also ran the keyring tests against the real Secret Service | process | Rules in `CLAUDE.md`: no bus and no `secret-tool` for scratch daemons; core tests with `--ignored --skip keyring` |
| Integration switches (`glimpse`, `assistant`) live in `settings.toml`, which any process of the user can edit | known | Accepted in SECURITY.md (same-user processes). The grant design (Phase 5) keeps grants encrypted under the user key instead |
| `Lock` is answered for every scope, even with the integration off | none | Locking can only deny service; left as is |
| "Copy address" in the item view uses the window's clipboard, without the hint or clearing | none | Addresses aren't secrets |
| Recently used isn't dropped on lock | low | Fixed |
| SECURITY.md says `cargo deny` and `cargo audit` run before every release; nothing runs them | low | Fixed: `cargo deny` and clippy run in CI |
| The fuzz crate's lockfile had tokio 1.54.0 (yanked, RUSTSEC-2026-0384) and advised ctutils and crypto-bigint | low | Fixed |
| Doc drift: GLIMPSE_API.md described a debug-only allowlist that doesn't exist; NATIVE_MESSAGING.md said Settings can revoke pairings | doc | Fixed |

No secrets are logged: there is no logging dependency, `Secret` redacts in `Debug` and
`Display`, and the daemon prints only start-up errors.

## Roadmap

Each phase builds, passes its tests and is installed before the next. Each stops for
approval where a security-sensitive design is chosen.

1. **Foundation:** `cargo deny` and clippy in CI; doc drift.
2. **Editing:**
   - per-address rows with match rules, and Android app associations;
   - built-in and custom templates over standard items and custom fields;
   - Recent, kept encrypted under the user key.
3. **Email aliases:** one provider interface with capabilities (create, list, enable or
   disable, delete); Fastmail first, then SimpleLogin and addy.io, the rest after;
   aliases linked to logins; Nyx Online Accounts makes Fastmail the preferred service.
4. **Desktop integration:** Assistant tools for generating, a security summary (counts
   only) and opening an item; more Settings pages; Glimpse rows for aliases and Recent;
   the proto pin in Glimpse bumped.
5. **Advanced security:**
   - the security report's missing checks and one-step fixes;
   - the SSH agent (own socket, approval per use, session allowances);
   - grants for trusted apps (approval, expiry, revocation, an audit log without
     values);
   - Travel Mode (below).
6. **Validation:** a security review, Bitwarden Android on a device, the web vault, every
   browser, regression.
7. **Last:** biometrics and security keys on Nyx Biometrics. The master password stays
   the fallback; no key wrapping goes in without a reviewed design.

### Travel Mode, as far as Vaultwarden allows

Vaultwarden has no travel mode: the server sends every item to every signed-in client.
The strongest design without another backend:

- Items are marked with a `nyx:travel` custom field (synced, visible to other clients).
- While Travel Mode is on, marked items are removed from `vault.sqlite` and filtered out
  of every later sync before they're stored or decrypted.
- Turning it off needs the master password and a fresh sync.

What it can't do, and won't claim: the server and every other client still have the
items; anyone with the master password and the server address can sync them again; and
removed rows aren't guaranteed to be erased from an SSD, `secure_delete` notwithstanding.

## External dependencies and blockers

- **Nyx Biometrics** (Ken): needed for fingerprint, face and security-key unlock.
- **Fastmail OAuth in Nyx Online Accounts:** until then, alias management uses a
  Fastmail API token of its own, with the Masked Email scope.
- **Hardware and accounts** for FIDO2 two-step login, Duo and SSO.
- **An Android device** for the Bitwarden Android association checks.
