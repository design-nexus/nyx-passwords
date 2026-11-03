# Passwords — notes for working on this app

- GPL-3.0-only (links `bitwarden-crypto`); `crates/nyx-passwords-proto` is MIT so
  Glimpse and Settings can talk to the daemon without linking GPL code. Design and
  rules: `docs/ARCHITECTURE.md`, `docs/SECURITY.md`; daemon interface:
  `docs/GLIMPSE_API.md`; passkeys (not built): `docs/PASSKEYS.md`; progress: `docs/TASKS.md`.
- Package `nyx-passwords`: the window (`src/main.rs`, `src/app/`) and the daemon
  (`src/bin/nyx-passwordsd.rs`, `src/daemon/`). The daemon must not link GTK: check
  `ldd target/debug/nyx-passwordsd` after dependency changes.
- Vault logic is in `crates/nyx-passwords-core`; only its `crypto.rs` names
  bitwarden-crypto types.
- The daemon only answers the suite's binaries in its own directory (`peer.rs`), so
  run the window and daemon from the same `target/<profile>`; the window starts the
  sibling daemon when no systemd unit is installed.
- Tests: `cargo test -p nyx-passwords -p nyx-passwords-core`. Live tests need the
  throwaway server: `apps/passwords/scripts/test-server.sh start`, then
  `NYX_PW_TEST_SERVER=https://127.0.0.1:8087 NYX_PW_TEST_CA=$PWD/target/vaultwarden-test/ca.pem cargo test … -- --ignored --skip client`.
  Never point them at a real server.
- Fuzzing: `crates/nyx-passwords-core/fuzz/run.sh [seconds] [target…]` (needs a
  rustup nightly and `cargo install cargo-fuzz`). Targets: sync, enc_string, pairing,
  totp, matching, ssh; seeds in `fuzz/seeds/`, crashes in `fuzz/artifacts/`.
- Nyx Design 2.0 (`nyx_theme::use_design_2`, see nyx-design `STYLE.md`): one
  unified header (`chrome::app_header`) with the section as its subtitle and the
  sidebar toggle; search in the middle; the item count, the Security section's breach
  check, sync, lock, new item and Settings at the end. No status bar. The Accent row
  in Settings replaces Glow.
- Layout checks: run a test copy under `NYX_PASSWORDS_APP_ID=io.github.design_nexus.nyx.PasswordsTest`
  on a virtual monitor of its own, against a scratch daemon (copy `nyx-passwords` and
  `nyx-passwordsd` into one directory, scratch `XDG_RUNTIME_DIR`/`XDG_CONFIG_HOME`/
  `XDG_DATA_HOME`, `WAYLAND_DISPLAY` as an absolute path), never the real vault. Debug
  builds sign in to the throwaway server and set up the view from `PASSWORDS_TEST_*`
  (`src/app/fixture.rs`). Use a short `XDG_RUNTIME_DIR` for scratch runs: socket
  paths are limited to 108 bytes. Dialogs are windows of their own; the test copy gives
  them its class too (`main.rs` sets the program name), so the window rule must match
  that class. Still kill any window with the test copy's pid on another monitor.
- Daemon tests copy several debug binaries per test: run them with
  `TMPDIR=$PWD/target/tmp` when `/tmp` is a small tmpfs.
- Never let a test or scratch daemon reach a keyring. Ken doesn't want keyrings created
  or prompts shown. Run scratch daemons with `DBUS_SESSION_BUS_ADDRESS` unset and a
  `PATH` without `secret-tool` (no `dbus-run-session`: it activates gnome-keyring, whose
  prompter opens on the real screen). Never use `--include-ignored` on the core: its
  keyring tests use the real Secret Service. Use `--ignored --skip keyring`. The daemon
  test `keyring_unlock` makes a throwaway keyring in a scratch home: skip it too
  (`--skip keyring`).
- Docs for this pass: [docs/AUDIT.md](docs/AUDIT.md) (what's done, the roadmap),
  [docs/ANDROID.md](docs/ANDROID.md).
