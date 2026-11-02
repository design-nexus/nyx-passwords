# Passwords

A password manager for a self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
server, built with Rust, GTK 4 and the suite's shared theme and widgets. It uses the
Bitwarden client API, so the same account keeps working in the Bitwarden apps, the web
vault and the `bw` command line.

```sh
curl -fsSL https://raw.githubusercontent.com/design-nexus/nyx-passwords/main/install.sh | bash -s -- passwords
```

Launch `nyx-passwords`, enter your server's address, email and master password, and
the vault syncs. Two-step login works with an authenticator app, an emailed code, a
YubiKey (OTP) or the account's recovery code. You can also sign in with another
device's approval (on a computer that has signed in to the account before, as
Vaultwarden requires) or with the account's API key, and approve other devices'
requests to sign in from Passwords.

## What it does

- Lists logins, secure notes, cards, identities and SSH keys by type, template, folder
  and collection, with favorites, recently used items (copied here, in Glimpse or a
  browser, or opened), search and a trash with Undo. Items in the trash can be deleted
  for good, one at a time or by emptying the trash.
- Templates lay out new items: SSH credential, API key, Wi-Fi network, server,
  database, email account, software license, financial account, identification
  document, recovery codes and custom record, plus your own (Settings → Templates).
  They're ordinary Bitwarden items with named custom fields, so every Bitwarden app
  shows the same information.
- A login's web addresses each have their match rule (base domain, host, starts with,
  exact, regular expression, never), and its Android apps are listed by package name
  (`com.instagram.android`), stored as Bitwarden Android expects. See
  [docs/ANDROID.md](docs/ANDROID.md).
- Email aliases (sidebar → Email aliases): list a service's aliases with the logins
  that use them, copy one, turn one off (after asking) or on, and delete one, for
  Fastmail, SimpleLogin, addy.io, Firefox Relay, Forward Email and Cloudflare Email
  Routing. An alias made in the editor is remembered by its login, which shows it and
  whether it's on. A Fastmail account in Nyx Online Accounts makes Fastmail the
  suggested service; masked email still needs its own Fastmail API token.
- Folders are made in the sidebar ("New folder"), and renamed or deleted by
  right-clicking them. Ctrl- or Shift-click picks several items at once, to move them
  to a folder, to the trash, or out of it.
- Shows a login's username, password (hidden until shown, hidden again after 30 s),
  web addresses, and its one-time code with a ring counting down to the next one. Also
  every field of cards, identities, SSH keys and custom fields, with secret ones hidden
  until shown, and a login's old passwords with the date each was last used.
- Creates, edits and copies logins, secure notes, cards, identities and SSH keys,
  custom fields included (text, hidden, or true or false), with a password and
  passphrase generator, and a username generator: a random word, your email with a
  tag, an address at your catch-all domain, or a new alias from SimpleLogin, addy.io,
  Firefox Relay, DuckDuckGo, Fastmail, Forward Email or Cloudflare Email Routing (with
  your API token, kept in the keyring). What the generators made stays listed until the vault locks. SSH keys are generated (Ed25519) or imported from an OpenSSH
  private key file, with its passphrase if it has one. An edit made in another app in
  the meantime is caught instead of overwritten.
- Honors "ask for master password" on items, and an organization's permissions:
  read-only items and hidden passwords stay that way.
- Creates items in an organization's collections, changes their collections, and
  moves personal items into an organization.
- Nyx Assistant can find logins and copy them ("copy my password for GitHub") once
  you turn that on in Passwords' settings. It asks for a key press each time and never
  sees a password.
- A Security section lists logins with weak, reused or year-old passwords, `http://`
  addresses, likely duplicates and records missing something, worked out on your
  computer. On request it checks passwords against Have I Been Pwned's breach data
  without sending them (only the first five characters of each hash), and finds sites
  that offer two-step login you don't use (2fa.directory's public list, downloaded
  whole). Each item says what to do, with a button that does it.
- SSH agent (Settings → SSH agent, off by default): ssh and git can use the SSH keys you
  turn on for it. Each use asks you first, once or until the vault locks; the private
  key never leaves Passwords. Point `SSH_AUTH_SOCK` at the socket the setting shows.
- Travel Mode (Settings → Travel Mode): items marked travel-sensitive leave this
  device until you turn it off with your master password. They stay on your server and
  other devices; the setting says what it can't protect against.
- Other Nyx apps can ask to find logins or copy one to the clipboard; you approve each
  app (and, if you like, each copy), for a set time. Settings → App access lists them,
  revokes them, and shows what other programs did with the vault.
- Emergency access (Settings → Emergency access): invite people you trust, confirm them
  after comparing fingerprint phrases, approve or reject their requests; and ask for
  access to vaults others trust you with, then view them read-only. Taking over an
  account is left to the web vault.
- Attachments: saves them to a file you choose, attaches files (up to 100 MB), and
  deletes them. Nothing decrypted goes to a temporary file.
- Imports from Bitwarden (JSON, password-protected JSON, CSV), 1Password (.1pux), Chrome,
  Firefox and KeePassXC (CSV), and exports in Bitwarden's formats (JSON, JSON with a
  password, JSON for this account, CSV), from Settings → Import and export. Exporting
  asks for the master password.
- Works offline from the local copy; edits need the server. While the vault is open it
  hears from the server as soon as something changes on another device (live sync) and
  syncs then; a timed sync is the fallback.
- Matches logins to sites with your server's equivalent domains (apple.com and
  icloud.com count as one site, and any groups you set in the web vault).
- Website icons, if you turn them on: your server fetches them, and they're kept in
  memory only while the vault is open.
- Can unlock with your desktop keyring instead of the master password, if you turn that
  on. The setting explains what that gives up.
- Lists a login's passkeys and deletes them.

## In the browser

The installer builds the extension into `~/.local/share/nyx-passwords/browser`, for
Firefox and Zen (`nyx-passwords-firefox.xpi`) and for Chromium, Chrome and Brave
(load `chromium/` unpacked), and sets up the native host that links it to the running
app. Until the Firefox build is signed, release Firefox loads it only for the session
(`about:debugging` → This Firefox → Load Temporary Add-on). Pair it once by comparing a code with the one Passwords
shows. The vault stays in Passwords; the extension asks for one thing at a time.

- A small menu under login, sign-up, one-time-code, card and address fields fills them,
  or makes a new password or username.
- Fills the login as the page loads, when exactly one login names that site (or you
  used one of them last). Turn it off in Passwords → Settings → Browsers, in the
  extension's settings, or for one login in its editor.
- Offers to save a login after you sign in, or to update its password; "Never for
  this site" remembers.
- The popup shows the site's logins with their one-time codes and countdown rings,
  searches the whole vault (filling a login from another site warns first, then offers
  to add the site to it), copies through Passwords' clipboard, generates passwords and
  usernames, and flags weak, reused and old passwords.
- Remembers when a site's login is "Sign in with Google" (or Apple, Microsoft, GitHub
  and others) and clicks it for you.
- Passkeys, if you turn them on in both Passwords and the extension: sites can make
  and use passkeys kept in your vault, with a prompt each time; "Use the browser's own"
  hands back to Firefox.
- Ctrl+Shift+L fills (again for the next login), Ctrl+Shift+9 generates a password,
  Alt+Shift+Y opens the popup.

## How it keeps the vault

- **The daemon:** a small service, `nyx-passwordsd` (systemd unit
  `nyx-passwords.service`), holds the unlocked keys. The window asks it for one
  field at a time over a private socket that only the suite's own programs may use.
- **The local copy:** the server's encrypted data as received, in
  `~/.local/share/nyx-passwords/vault.sqlite` (readable only by you). Nothing
  decrypted is written to disk.
- **The session token:** kept in the desktop keyring (Secret Service).
- **Copying:** the clipboard is marked as holding a password and cleared after 30 s
  (configurable) if it still holds the copy. Clipboard managers that ignore the mark
  can still store it.
- **Locking:** after 15 minutes without use (configurable), when the screen locks,
  before sleep, and with Ctrl+L.

Settings live in `~/.config/nyx-passwords/settings.toml`. Details:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SECURITY.md](docs/SECURITY.md).

| Shortcut | Action |
| --- | --- |
| Ctrl+N | New item |
| Ctrl+F | Search the vault |
| Ctrl+Shift+U / C / O | Copy the username / password / one-time code |
| Ctrl+S | Save in the editor |
| Ctrl+L | Lock the vault |
| F5 | Sync now |
| Ctrl+B | Collapse sidebar |
| Ctrl+, | Settings |
| Esc | Close search or card, or return to the list |
| F1 / ? | Shortcuts |
| Ctrl+Q / Ctrl+W | Close window |

## License

GPL-3.0-only, because it uses Bitwarden's GPL-licensed cryptography library. The rest
of Nyx is MIT.
