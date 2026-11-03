# Nyx Passwords — Android

There is no Nyx Android app. On Android, use the official **Bitwarden** app, signed in
to the same Vaultwarden server and account. Everything Nyx Passwords saves is a standard
Bitwarden item, so the phone sees the same vault.

## Setting it up

1. Install Bitwarden from Google Play or F-Droid.
2. On its sign-in screen, choose **Self-hosted** and enter your Vaultwarden address (the
   one shown in Passwords → Settings → Vault).
3. Sign in with the same email and master password.
4. In Bitwarden → Settings → Autofill, turn on **Autofill services** (and inline
   suggestions, if your keyboard offers them).

## Android app associations

A login can name the Android apps it belongs to. In the item editor, under
**Android apps**, add each app's package name (`com.instagram.android`). It is saved as
`androidapp://com.instagram.android`, which is exactly how the Bitwarden apps write it,
in the login's ordinary list of addresses, encrypted and synced like the rest.

- One login can have several apps (the app and its "Lite" version, say), next to its
  web addresses.
- The item view lists them under **Android apps**.
- An app added on the phone (Bitwarden asks to save the app to the item when you fill
  it from a search) shows up here after the next sync, and editing the item here keeps
  it. Live tested with `bw` as the other client (`tests/edit.rs`,
  `android_apps_and_match_rules`).
- Package names are checked as Android requires: at least two dot-separated parts, each
  starting with a letter, with letters, digits and underscores only.

### Finding a package name

- The app's Google Play address: `play.google.com/store/apps/details?id=`**`com.example.app`**.
- Its F-Droid page lists it as the package name.
- On the phone: some versions of Android show it under Settings → Apps → the app.
- With a cable: `adb shell pm list packages | grep -i example`.

Looking names up for you was considered and left out: Google Play has no public
search API, F-Droid's index covers only free apps, and either would send the app
names you search for to a third party.

## How Bitwarden Android matches

- In an app, Bitwarden offers the logins with that app's `androidapp://` address,
  compared as the exact package name.
- In a browser, or a page shown inside an app (a WebView that reports its site), it
  matches the web addresses under their match rules instead.
- Logins with neither show up only through search. Picking one there offers to add
  the app to it.

## Limits outside Nyx Passwords

- **Apps that opt out of autofill** (fields marked `importantForAutofill="no"`, custom
  drawn fields, some banking apps) get no suggestions. Bitwarden's accessibility-based
  fill can sometimes help; otherwise copy from the Bitwarden app.
- **Inline suggestions** in the keyboard need Android 11 or later and a keyboard that
  supports them (Gboard does); otherwise Bitwarden shows its own drop-down.
- **Sign-in pages inside an app** may report a web domain rather than the app; the
  login then needs a web address too.
- **Passkeys** on Android 14 and later go through Credential Manager and match the
  passkey's site, not the app's package name.
- **Several devices:** associations made here reach the phone on its next sync, which
  Bitwarden does on unlock, on pull-to-refresh, or from Vaultwarden's push when the
  server has it set up.
